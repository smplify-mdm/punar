# Milestone 4 — Declarative desired state: architecture plan

Spec authority: section 76 Milestone 4 ("schemas, preference/policy merge,
reconciliation, explain, and firewall-drift demo"), grounded in sections 38
(declarative state model), 39 (sources and precedence), 40 (explainability),
42 (reconciliation), 43 (drift), 52 (compliance), 73 (security/privacy UX
voice). Binding prior contracts, not relitigated here:
`docs/api/ipc.md` (M3 wire contract — M4 changes are **additive under
`v: 1`**, marked "M4" in that file) and `docs/development/milestone-3.md`
(daemon architecture, capability backends, m3-check, budgets).

M4 remains **unmanaged-first personal mode** (design language section 8):
the merge engine and its tests know all seven section 39 sources (Acme
fixtures exercise the org rungs), but the VM image renders only OS defaults
and user preferences. Nothing org-shaped appears in any VM output.

---

## 1. Scope

In: layered desired-state store with the section 39 merge, `policy.effective`
/ `policy.explain` IPC + CLI, remediating reconciliation with section 43
classification and loop protection, `punard-reconcile.timer` drift trigger,
personal-scope compliance in `status`, `m4-check` with a timer-driven
firewall-drift demo, one-shot migration of the M3 `desired.json`.

Out (unchanged non-goals): enrollment and any org source in the VM (M5),
policy.d hot-reload (M5, with enrollment), approvals/JIT elevation (M9),
event streaming, audit rotation (tracked for M5), agent methods (M7+).

## 2. Decision summary

| # | Decision |
|---|----------|
| 1 | **Layered store**: OS defaults compiled into `punard` (+ first-boot observation seeds persisted in `/var/lib/punar/os-defaults.json`); user preferences in `/var/lib/punar/preferences.json`, written only by `capabilities.set`; org layers reserved as a root-only file-drop dir `/var/lib/punar/policy.d/` (loader + tests in M4, files arrive M5). Effective document computed in memory through `punar-policy`; a non-authoritative copy materialized at `/var/lib/punar/effective.json` for debugging. |
| 2 | **Migration**: one-shot at first M4 start. `desired.json` values that differ from a compiled OS default become UserPreference entries; observation-role values (hostname/timezone seeds) become the persisted OS-default seeds. `desired.json` renamed to `desired.json.pre-m4`, never read again. Audited (`state.migrate`). Fresh installs skip it (nothing to migrate) — migration is covered by host `cargo test`, not by the VM (honest limit, section 10.3). |
| 3 | **IPC (v stays 1, additive)**: new read methods `policy.effective` and `policy.explain{path}`; `status` grows a `compliance` block (section 52 states, personal scope); `capabilities.set` records a UserPreference then reconciles that capability (byte-compatible result in personal mode); `reconcile` now remediates per policy — the semantic change M3 pre-announced by making it root-only. Contract text: `docs/api/ipc.md` sections 5.1, 5.4, 5.6, 5.7, 5.8. |
| 4 | **Reconciliation**: full section 42 chain (observe → normalize → load → diff → policy → plan → apply → verify → audit → compliance), synchronous within one `reconcile` call; section 43 classification is data in the effective document (`auto_remediate` for all three capabilities in personal mode); one audit event per remediation attempt (`reconcile.remediate`); loop protection at **N=3** consecutive failed attempts → `non_compliant` + one `attempts_exhausted` audit event, remediation suppressed until the effective value changes or a manual set succeeds. |
| 5 | **Drift trigger**: systemd `punard-reconcile.timer` (OnBootSec=120, OnUnitActiveSec=120, AccuracySec=15) starting oneshot `punard-reconcile.service` = `/usr/bin/punarctl --json reconcile` as root through the normal socket/authz/audit path. Vendor-wants symlink in `usr/lib/systemd/system/multi-user.target.wants/` (repo precedent: `punar-desktop-diag.timer`; the M1 mkosi /etc-preset lesson). Internal daemon thread timer rejected (section 6). |
| 6 | **`punarctl`**: new `policy` group — `policy effective` (D-014 table) and `policy explain <path>` (section 40 layout verbatim in field-note grammar); `status` gains the section 52 compliance block. Personal-mode strings: source "Personal preference" / "OS default", policy id `personal-defaults`, "User override: Permitted". This amends the M3 D-014 note "no compliance rows in personal mode" — personal compliance (device vs. your own preferences + OS defaults) now exists and renders; org rows still do not. |
| 7 | **m4-check**: asserts effective/explain via `--json` + `jq`, the set→preference-layer→re-enable cycle, and the timer-driven firewall-drift demo (`nft destroy` → table restored within ≤3 timer periods + `reconcile.remediate` audit event + `drift_remediated_total` increment); loop protection not triggered. m3-check needs a small documented amendment (section 10.4) because reconcile now remediates. |
| 8 | **Schema deltas: none.** The `status` compliance block and `policy.*` results are IPC result shapes (ipc.md is their contract). `policy.d` files are already covered by `schemas/policy/policy-source.json` + `schemas/desired-state`. New audit `action`/`result` strings conform to the existing patterns. The M3 follow-up (conditional agent fields in the audit schema) is deferred again, to M5 (section 9). |

## 3. Layered desired-state store

### 3.1 Layers (lowest precedence first)

| Layer | section 39 source | `source_kind` (schema) | rank | Storage | policy_id / source_name |
|---|---|---|---|---|---|
| OS default | OS secure default | `os_secure_default` | 6 | Compiled into `punard` where fixed (`security.firewall` → `enabled`, spec 44.4); observation-seeded at **first M4 start** for open-valued capabilities (`system.hostname`, `time.timezone`), persisted `/var/lib/punar/os-defaults.json` (0600 root, atomic) so the default is stable across boots and drift stays meaningful | `personal-defaults` / "OS default" |
| User preference | local user preference | `local_user_preference` | 5 | `/var/lib/punar/preferences.json` (0600 root, atomic) — created lazily on the first `capabilities.set`; shape below | `personal-defaults` / "Personal preference" |
| Org rungs (1–4) | hard constraint, org mandatory, org role, temp exception | per `schemas/policy/policy-source.json` | 1–4 | **Reserved**: `/var/lib/punar/policy.d/` (0700 root; tmpfiles entry added now). Each file `<policy_id>.json` is a policy-source envelope whose `policy` payload is a `DeviceDesiredState` fragment (section 38). Loaded at startup, ascending filename order; duplicate `policy_id` → refuse to start (same posture as a corrupt store). **M4 ships the loader + tests against `fixtures/organizations/acme`; the image ships an empty directory** (design section 8: nothing org renders) | from each envelope |

`preferences.json` shape (private daemon store, like `device-id` — documented
here, not a public schema):

```json
{
  "version": 1,
  "preferences": {
    "security.firewall": {
      "value": "enabled",
      "set_at": "2026-08-25T09:14:02Z",
      "set_by": "root"
    }
  }
}
```

### 3.2 Merge

`punar-policy` grows a document layer on top of the existing, already-tested
`resolve` (section 39 ladder, spec: "Encode and test"):

- `Provenance { kind, rank, policy_id, source_name }` — `kind` is the
  7-value `policy_source_kind` enum of `schemas/policy/policy-source.json`,
  serde-compatible with its snake_case strings.
- Mapping `kind → PolicySource` is pinned by test against the schema's
  documented rank table (1=hard constraint … 6=OS default);
  `device_specific_override` has no fixed rung (schema: rank is stored
  data) — the loader accepts its explicit rank and maps it positionally.
  A loader check rejects an envelope whose stored `precedence_rank`
  contradicts the fixed mapping for the six laddered kinds.
- Flattener: `DeviceDesiredState` `spec.*` → capability paths. M4 maps
  exactly `spec.security.firewall.enabled: true|false` →
  `security.firewall: "enabled"|"disabled"`. Unmapped spec paths
  (diskEncryption, applications, ai, network, update) are logged once at
  load and ignored — no registered capability exists for them yet (honest
  limit; they land with their capabilities in M5+).
- `merge(layers) → EffectiveDocument`: `BTreeMap<path, { effective_value,
  provenance, user_override_permitted, classification }>` via `resolve`
  per path. `user_override_permitted = (winning rank >= 5)` — a user may
  override the OS default and their own preference; anything above the
  User Preference rung pins the value (personal mode: always `true`).
- Engine tests reproduce the spec 40 org output from the Acme fixtures:
  `eng-baseline-v12` (rank 2) over a user preference → effective from
  `organization_baseline`, override not permitted. Tests only; never in VM.

Recompute triggers: startup, every `capabilities.set`. (policy.d changes
require restart in M4; hot-reload arrives with M5 enrollment.)

After each recompute the effective document is written to
`/var/lib/punar/effective.json` (0600, atomic) — a **non-authoritative debug
artifact**; the in-memory document is the truth and is rebuilt from the
layers at startup.

### 3.3 Migration of the M3 `desired.json` (one-shot, first M4 start)

Trigger: `preferences.json` absent AND `desired.json` present.

1. `security.firewall`: compiled OS default is `enabled`. Recorded value
   `!= enabled` → write a UserPreference entry (`set_by: "migrated"`;
   the only way it could differ from the default is a root
   `capabilities.set`, i.e. a user action). Equal → drop (the OS-default
   layer regenerates it).
2. `system.hostname`, `time.timezone`: M3 seeded these from observation
   (OS-default role) and a later root set overwrote them — the file cannot
   distinguish seed from set. Rule: **unknowable provenance defaults DOWN
   the ladder** — the recorded values become the persisted OS-default seeds
   in `os-defaults.json`, not user preferences. Tradeoff (documented,
   honest): a genuinely user-set hostname explains as "OS default" after
   migration; the effective value is identical (nothing sits between rungs
   5 and 6 in personal mode), only the provenance label is conservative.
   The alternative — labeling a boot seed "Personal preference" — would
   fabricate a user action.
3. Rename `desired.json` → `desired.json.pre-m4` (kept, never read again).
4. One audit event: `action: "state.migrate"`, `resource: "state_store"`,
   `source: "service"`, `user_id: "punard"`, `decision: "allow"`,
   `result: "success"`, `policy_ids: ["personal-defaults"]`.

Fresh installs (no `desired.json` — every CI image boot) skip 1–4;
`os-defaults.json` is seeded from first observation, `preferences.json`
appears on first set. Consequence: **the migration path cannot be exercised
in-VM** and is covered by host `cargo test` with synthetic M3 stores
(spec 74.1/74.2), stated plainly in section 10.3.

`DesiredStore` is deleted from `punard`; the layer store + effective
document replace it everywhere (registry `desired_state` fields now render
the effective value).

## 4. IPC additions (contract: docs/api/ipc.md, v stays 1)

Envelope, framing, transport, authz mechanics: unchanged. Per ipc.md 3.3,
adding methods and optional result fields is not a version bump; clients
already must tolerate unknown result fields.

- **`policy.effective`** (read, any connected peer, not audited): the
  merged document. Result: `{"computed_at": ..., "entries": [ {"path",
  "effective_value", "source": {"kind", "rank", "policy_id", "name"},
  "user_override_permitted", "compliance_state"}, ... ]}`.
- **`policy.explain`** (read, any peer, not audited): params
  `{"path": "security.firewall"}` → one entry, same shape minus `path`:
  `{"effective_value", "source": {kind, rank, policy_id, name},
  "user_override_permitted", "compliance_state"}`. Unknown path →
  `not_found`. This is exactly the spec 40 information set.
- **`status`**: grows optional `compliance` result field —
  `{"overall": <section 52 state>, "capabilities": [{"capability",
  "state"}, ...], "drift_remediated_total": <n>,
  "last_remediation_at": <ts|null>}`. `drift_remediated_total` is an
  in-memory monotonic counter since daemon start — the observable evidence
  the drift demo asserts on. States are computed at reconcile time (boot
  reconcile guarantees a value before the socket opens).
- **`capabilities.set` M4 semantics** (compatibility stated precisely):
  request shape, authz (root-only), validation, and audit action are
  unchanged. Pipeline: validate → authorize → **record UserPreference entry**
  → recompute effective → apply the **effective** value for that capability →
  verify → audit → respond. In personal mode nothing outranks a user
  preference, so effective == requested and the `{descriptor, changed}`
  result is byte-identical to M3 — existing callers observe no difference.
  When a higher layer overrides (engine/tests only until M5), the preference
  is still recorded, the effective value is applied, and the result
  additionally carries `"overridden": true` and `"effective_state"`
  (optional fields; never emitted in personal mode). `audit.policy_ids`
  now cites the winning source's policy id.
- **`reconcile` M4 semantics**: remediates per policy (section 5 below).
  Result keeps every M3 field with its M3 meaning (`drift`/`drift_count`
  describe the pre-remediation observation) and adds per-capability
  `classification` + `remediation`
  (`"applied"|"none"|"apply_failed"|"verify_failed"|"alert_only"|"suppressed"`)
  and top-level `remediated_count` + `compliance` (same shape as in
  `status`). Root-only, unchanged — M3 made it root-only precisely so this
  semantic change would not loosen the authz surface.

## 5. Reconciliation engine (spec section 42, full chain)

One synchronous pass per `reconcile` call (boot, timer, manual — same code):

1. **Observe** — each backend's existing live read (nft/procfs/readlink).
2. **Normalize** — canonical state values (M3 normalizers unchanged).
3. **Load** — layer merge → effective document (section 3.2).
4. **Diff** — observed vs. effective per capability.
5. **Policy (classify — spec section 43 step 3)** — classification is data
   in the effective document, defaulting per source: personal mode sets
   `auto_remediate` for all three capabilities (firewall per the task and
   spec 43's own example; hostname/timezone restore the user's recorded
   choice or the stable seed, risk `low`). `alert_only` and
   `approval_required` are representable and org-testable (Acme fixtures);
   `approval_required` degrades to `alert_only` behavior until M9 delivers
   approvals (documented in the result as classification
   `approval_required`, remediation `alert_only`).
6. **Plan** — ordered list of `auto_remediate` drifts whose loop-protection
   budget is not exhausted (`suppressed` otherwise).
7. **Apply** — the backend's existing apply, fixed argv, no shell.
8. **Verify** — re-observe; must equal effective.
9. **Audit** — one event **per remediation attempt**: `action:
   "reconcile.remediate"`, `resource: <capability>`, `decision: "allow"`,
   `result: "success" | "apply_failed" | "verify_failed" |
   "attempts_exhausted"`, `policy_ids: [<winning policy id>]` — plus the
   M3 summary event (`action: "reconcile"`, `result: "drift_detected" |
   "clean"`) unchanged.
10. **Compliance** — recompute per-capability and overall states, bump
    `drift_remediated_total` per successful remediation.

**Loop protection (N=3):** per-capability in-memory counter of consecutive
failed remediation attempts (apply or verify failure). At 3: capability →
`non_compliant`, one `attempts_exhausted` audit event on the transition,
and Plan suppresses it (result shows `remediation: "suppressed"`) until the
effective value changes, a manual `capabilities.set` on it succeeds, or the
daemon restarts. A successful verify resets the counter. Honest limit:
*flapping* (an external actor re-disabling after each successful
remediation) never trips the counter — each cycle succeeds; the evidence is
the repeated `reconcile.remediate` success events in the audit trail, which
is the correct record of contested ownership, not a failure of this daemon.

**Compliance states (section 52, personal scope):** per capability —
`compliant` (observed == effective), `remediating` (drift with remediation
still inside the attempt budget: this pass applied-but-verify-failed, or
attempt < 3 pending next cycle), `non_compliant` (budget exhausted, or
`alert_only` drift left standing), `unknown` (observe failed). `unsupported`
maps to a descriptor with `supported: false` (none in M4); `exception`
renders only when a `temporary_approved_exception` source wins a path
(engine/tests only until M5). Overall = worst of
`non_compliant > unknown > remediating > exception > compliant`
(`unsupported` excluded from overall, matching section 52's per-row
treatment).

## 6. Drift trigger — systemd timer (decision)

**Chosen:** `punard-reconcile.timer` → oneshot `punard-reconcile.service`
running `/usr/bin/punarctl --json reconcile` as root (no `User=`), through
the normal socket. Units versioned in the desktop extra tree; enablement is
a **vendor-wants symlink** `usr/lib/systemd/system/multi-user.target.wants/punard-reconcile.timer`
(repo precedent `punar-desktop-diag.timer`; never postinst `systemctl`,
never `/etc` — the M1 mkosi preset lesson).

```ini
[Timer]
OnBootSec=120
OnUnitActiveSec=120
AccuracySec=15
```

**Cadence justification vs. spec 6.3** ("continuous high-frequency polling
is prohibited; prefer event-driven observation"): 120 s is a low-frequency
scheduled check, not a poll loop — each firing is one short-lived process
doing three file/readlink reads and one `nft` spawn (milliseconds of CPU),
then the system is fully idle again; `punard` itself stays event-driven with
zero resident wakeups. `AccuracySec=15` bounds firing jitter so the drift
demo's "≤3 periods" window is testable (default 60 s smear would make the
bound sloppy). No requirement needs sub-2-minute drift response in M4; the
spec sets no tighter bound.

**Rejected — internal daemon thread timer:** adds an always-on wakeup source
inside `punard` (against 6.3's spirit and the RSS/CPU posture), is invisible
to `systemctl list-timers`, cannot be stopped/masked/frozen by an admin
without killing the daemon, and would introduce an internal trigger path
that bypasses the audited request surface. The timer instead **reuses the
existing authz + audit path** (uid-0 peer), and m4-check can start/stop it
deterministically. **Follow-up (tracked, not M4):** true event-driven
observation (nftables monitor socket, inotify on `/etc/hostname` /
`/etc/localtime`) is the right end-state per 6.3; deferred because it is a
per-capability event mesh with always-on fds that the M4 demo does not need.

Honest attribution limit: timer-driven reconcile audit events carry
`user_id: "root"`, `source: "human"` — the daemon sees only peer
credentials and cannot distinguish the timer's `punarctl` from an admin's.
Documented in ipc.md; a client-asserted "I am the timer" flag would be
spoofable and is not added.

## 7. `punarctl` surface (D-014)

- `punarctl policy effective` — masthead `PUNAR · POLICY`, one row per
  path: `security.firewall  enabled  Personal preference · personal-defaults`.
  `--json` prints the IPC result verbatim.
- `punarctl policy explain <path>` — the **spec section 40 output layout
  verbatim** in field-note grammar (tracked-uppercase labels, D-014):

  ```text
  PUNAR · POLICY EXPLAIN
  ──────────────────────────────────────────
  security.firewall

  Effective value: enabled

  Source:
  Personal preference

  Policy:
  personal-defaults

  User override:
  Permitted

  Compliance:
  compliant
  ```

  Personal-mode strings, fixed: `Source:` is `Personal preference` or
  `OS default`; `Policy:` is `personal-defaults`; `User override:` is
  `Permitted` (spec 40's org example shows `Not permitted` — that renders
  only when a rank <5 source wins, i.e. never before M5). Unknown path →
  exit 1 with the server's section-73 `not_found` message.
- `punarctl status` — gains the section 52 block, rendered per the spec
  example (`Overall  compliant` + per-capability rows: Firewall, Hostname,
  Timezone), status words on the existing ANSI semantic slots. **Amendment
  to the M3 D-014 note** "no org/compliance rows in personal mode": personal
  compliance now exists (your device vs. your own preferences + OS defaults)
  and renders; org rows still never render before enrollment. Design
  section 8 holds: enrollment will add rows, not redraw.
- Exit codes unchanged (0/1/2/3/4/5).

## 8. Budgets (spec 6.2/6.3, PERFORMANCE_BUDGETS.md)

No new runtime dependencies planned (`punar-policy` is an existing workspace
crate; serde only). The timer adds no resident process; each firing spawns
`punarctl` transiently (~2/min², trivial). The existing
`PUNAR_SERVICES_RSS_MB` gate (punard cgroup PSS, warn >100 / fail >150) is
unchanged and will catch any regression from the merge engine. Timer firings
during the 5-minute idle-RAM window (~2 occurrences, OnBootSec=120) are
accepted sampling noise: transient process, no persistent allocation;
the RSS metric reads the `punard.service` cgroup only.

## 9. Schema deltas — none (decision, task 7)

- The `status` compliance block, `policy.effective`/`policy.explain`
  results, and reconcile result extensions are **IPC result shapes**;
  `docs/api/ipc.md` is their contract. No document schema binds them; no
  schema change.
- `policy.d` envelopes and payloads are already covered by
  `schemas/policy/policy-source.json` + `schemas/desired-state` — that is
  why those schemas shipped early. `./tools/validate-schemas.sh` continues
  to cover the Acme fixtures.
- `preferences.json`, `os-defaults.json`, `effective.json` are private
  daemon stores (peer of `device-id`), documented here, deliberately not
  public schemas.
- New audit strings — `action: "reconcile.remediate"`, `"state.migrate"`;
  `result: "attempts_exhausted"`, `"apply_failed"` — conform to the shipped
  schema as-is (`action` pattern allows dotted lowercase; `result` is an
  open string by design).
- The M3 follow-up (make audit agent fields conditional on
  `source == "ai_agent"`) is **deferred again, to M5**: M4 adds no event
  kind that needs it, and changing `required` churns every consumer and
  fixture for zero M4 benefit. Sentinels (`agt_none`, `project_id:
  "system"`) remain the documented contract.

## 10. In-VM exercise plan — `m4-check`

### 10.1 Mechanics

Mirror of m2/m3: `punar-m4-check.service` (root, `Type=oneshot`,
`TimeoutStartSec=10min`, **not enabled**) runs `/usr/lib/punar/m4-check.sh`,
always exits 0, writes `/run/punar/m4-report.txt` (`ok`/`FAIL` lines +
`PUNAR_M4_OK`/`PUNAR_M4_FAIL` verdict). `idle-ram.sh` starts it after
`punar-m3-check.service`, before export; `tools/boot-test.sh` gains the
copy+hard-fail phase; `ci.yml` ships the report in the same tar.

Timer determinism: m3-check and m4-check phase A run with the timer stopped
(`systemctl stop punard-reconcile.timer` at m3-check top); m4-check phase B
restarts it for the drift demo and leaves it running afterwards.

State inherited from m3-check (order matters, asserted accordingly):
hostname and firewall have been `capabilities.set` → both carry
**user-preference** provenance; `time.timezone` was never set → **OS
default** provenance. m4-check deliberately uses this to exercise both
source kinds.

### 10.2 Assertions (all machine checks via `--json` + `jq`)

1. Timer vendored + alive: `systemctl is-enabled punard-reconcile.timer` →
   `enabled` (vendor symlink survived mkosi); after phase B start,
   `is-active` → `active`.
2. Stores: `/var/lib/punar/os-defaults.json` and
   `/var/lib/punar/preferences.json` exist, `0600 root:root`;
   `/var/lib/punar/desired.json` absent (fresh install — no M3 store was
   ever written by an M4 daemon).
3. `runuser -u punar -- punarctl --json policy effective`: exit 0 (read
   path open to group punar); 3 entries; every entry has
   `effective_value`, `source.kind`, `source.rank`, `source.policy_id`,
   `user_override_permitted==true`, `compliance_state`.
4. OS-default provenance: `punarctl --json policy explain time.timezone` →
   `source.kind=="os_secure_default"`, `source.rank==6`,
   `source.policy_id=="personal-defaults"`, `compliance_state=="compliant"`.
   Human output greps: `Effective value: UTC`, `OS default`,
   `personal-defaults`, `Permitted`, `compliant` (section 40 layout).
5. User-preference provenance: `punarctl --json policy explain
   security.firewall` → `source.kind=="local_user_preference"`,
   `source.rank==5`, `source.name=="Personal preference"`,
   `effective_value=="enabled"` (m3-check's set recorded it).
6. Set writes the preference layer: root `punarctl capabilities set
   security.firewall disabled` → exit 0; `nft -j list table inet
   punar-base` exits nonzero (really applied); explain →
   `effective_value=="disabled"`, `compliance_state=="compliant"`
   (**disabled by your own preference is compliant** — desired==observed;
   the teaching point of personal-scope compliance); `jq` on
   `preferences.json` shows the `security.firewall` entry with
   `set_by=="root"`.
7. **Re-enable**: `punarctl capabilities set security.firewall enabled` →
   table back (`nft` exit 0); explain effective `enabled`, compliant.
8. `punarctl --json status`: `compliance.overall=="compliant"`, 3
   capability entries all `"compliant"`, `drift_remediated_total` is a
   number — captured as baseline `B` (boot reconcile and m3-check's
   remediation already incremented it; the exact value is
   order-dependent, so assert type + monotonicity, not a constant).
9. **Drift demo (timer-driven)**: start the timer; `nft destroy table inet
   punar-base`; poll `nft -j list table inet punar-base` every 5 s with a
   **375 s budget** (3 × 120 s periods + 15 s accuracy slack). On success:
   `punarctl --json audit tail -n 50` contains an event with
   `action=="reconcile.remediate"`, `resource=="security.firewall"`,
   `decision=="allow"`, `result=="success"`,
   `policy_ids==["personal-defaults"]`; `status` shows
   `compliance.overall=="compliant"` and `drift_remediated_total >= B+1`
   (the designed observable transition evidence — `remediating` is not
   observable in the happy path because remediation succeeds within one
   synchronous pass).
10. Loop protection **not** triggered in the happy path: no audit event
    with `result=="attempts_exhausted"` in the full log; no capability
    `non_compliant` in `status`.
11. Unknown path voice: `punarctl policy explain not.a.capability` →
    exit 1; stderr names the path and reads as section-73 prose (grep, not
    full-text).
12. Section 60 posture unchanged: `punarctl debug rpc policy.set` →
    `unknown_method` (no write-side policy method exists; the only policy
    mutations are `capabilities.set` and — M5 — the enrollment drop).

### 10.3 What the VM cannot show (honest)

- The **migration** (3.3) never runs on a fresh image; host `cargo test`
  covers it with synthetic M3 stores (firewall-differs, firewall-equals,
  seed-provenance, corrupt-file-refuses-start cases).
- **Org merge** paths run only in host tests against the Acme fixtures
  (spec 40 org output, override-not-permitted, exception rung,
  alert_only classification). Nothing org renders in the VM by design.
- **Loop-protection exhaustion** needs three forced apply failures; forcing
  them in-image would mean breaking `nft` mid-check. Covered by host tests
  with a failing mock backend; the VM asserts only its non-firing (10.2 #10).

### 10.4 Required m3-check amendment (documented, small)

m3-check step 7 asserted M3's report-only reconcile (`drift…==true`, no
remediation). Under M4 semantics that same reconcile **remediates**. The
amendment: stop the timer at script top; after `nft destroy` +
`punarctl --json reconcile`, assert `drift_count==1` **and**
`remediation=="applied"` **and** the table is back; drop the now-noop
explicit re-enable set (or keep it asserting `changed==false`); second
reconcile still asserts `drift_count==0`. All other m3-check assertions are
unaffected (status/list/get/set/audit/denial/authz shapes are additive-only
per ipc.md 3.3, and `jq` asserts specific keys, never whole-object
equality).

## 11. Image integration

New/changed content, all in the desktop extra tree (versioned; binaries
staged by the existing `container-build.sh` flow, `PUNAR_BUILD_MODE=summary`
still skips compilation):

- `usr/lib/systemd/system/punard-reconcile.service` + `.timer` +
  vendor-wants symlink in `multi-user.target.wants/`.
- `usr/lib/tmpfiles.d/punard.conf`: add
  `d /var/lib/punar/policy.d 0700 root root -`.
- `usr/lib/punar/m4-check.sh`, `punar-m4-check.service`; `idle-ram.sh`
  starts m4-check after m3-check; `tools/boot-test.sh` + `ci.yml` gain the
  m4 report phase/artifact.
- m3-check.sh amendment per 10.4.
- No new packages (nftables, tzdata already present; no new crates).

## 12. Verification status (spec 1.22)

Verified today (2026-08-25, repo reading): `punar-policy` ladder + tests
(`crates/punar-policy/src/lib.rs`), `policy-source.json` rank table and
source-kind enum, Acme fixtures shape, M3 `DesiredStore` semantics
(`crates/punard/src/state.rs` — seed vs. set indistinguishable, basis for
3.3), vendor-timer precedent (`punar-desktop-diag.timer` wants-symlink in
`multi-user.target.wants/`), audit schema `action` pattern and open
`result` (basis for section 9), ipc.md 3.3 additive-under-v1 rule and the
M3 root-only-reconcile forward declaration.

Asserted, not yet verified (lands with implementation, checked by CI):
every m4-check assertion; timer jitter under QEMU/TCG within the 375 s
budget; `AccuracySec=15` behavior on the snapshot's systemd; RSS impact of
the merge engine (gated, not estimated); `nft` observe/apply timing inside
a 120 s cadence (trivially expected, still measured by the demo itself).

## 13. Implementation status (2026-08-25, spec 1.22)

Landed:

- **Engine + daemon** (`crates/punard` — layered stores, policy.d loader/
  flattener, merge, section 42 reconcile chain with N=3 loop protection,
  `policy.effective`/`policy.explain`, `status.compliance`, one-shot
  migration) and **CLI** (`crates/punarctl` — `policy effective`/`policy
  explain <path>` in the spec 40 layout, section 52 status block, M4
  reconcile rendering). Verified in docker `rust:1` (1.98.0):
  `cargo fmt --all --check`, `cargo clippy --workspace --all-targets
  -D warnings`, `cargo test --workspace` all green — noting honestly this
  is aarch64 rust 1.98.0, not the ALA-pinned snapshot toolchain; CI's
  in-container build is the canonical check.
- **Image wiring** (section 11, all delivered): `punard-reconcile.timer`/
  `.service` + vendor-wants symlink; `tmpfiles.d/punard.conf` policy.d
  line; `m4-check.sh` + `punar-m4-check.service` (12 min bound);
  `idle-ram.sh` chains m4-check after m3-check (service timeout raised to
  100 min); m3-check amended per §10.4 (timer stopped at top, step 7 now
  asserts `drift_count==1` + `remediation=="applied"` + table restored by
  the reconcile itself, the re-enable set kept as a `changed==false` noop
  that records the user preference m4-check's provenance assertions need);
  `boot-test.sh` phase 6 hard gate on `m4-report.txt` (KVM export timeout
  900→1500 s, TCG 2400→3000 s); `ci.yml` shellcheck + artifact + timeout
  (65→75 min) extensions.

Verified locally today: shellcheck v0.11.0 (pinned container) clean over
all touched scripts; actionlint clean; `PUNAR_BUILD_MODE=summary
tools/build-image.sh all` passes for both images (config staging only — no
full image build was run locally, per repo practice); the cargo runs above.

Not verified until CI runs (honest): every §10.2 in-VM assertion including
the drift demo's 375 s bound and the systemd immediate-elapse behavior on a
restarted monotonic timer (the demo's poll budget covers both the
immediate-fire and the full-period interleavings); RSS impact of the merge
engine (gated by check-budgets.sh, not estimated); and the §10.4 m3-check
amendment itself — the green M3 run below exercised `m3-check.sh` as
committed at f1ff60c (M3 report-only reconcile semantics); the amended
script has no recorded run.

The M3 CI run that was in flight when M4 landed has since resolved
(recorded 2026-08-25 by the status audit):
[run 32828986305](https://github.com/smplify-mdm/punar/actions/runs/32828986305)
is fully green — all five jobs, `PUNAR_M3_OK` (27 assertions passed),
first real `PUNAR_SERVICES_RSS_MB` = **2 MB** (summed PSS of the
`punard.service` cgroup, against the 100 MB warn / 150 MB fail budget),
idle RAM mean 1160 MB / max 1167 MB (pass with the standing over-target
warning). M4 therefore builds on a runtime-proven M3 base. The M4 work
itself is uncommitted and has **no** CI run — the first M4-inclusive run
is the arbiter for everything above.
