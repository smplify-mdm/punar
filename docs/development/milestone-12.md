# Milestone 12 — Network privacy prototype

Spec authority: section 76 Milestone 12 ("Deliver local network
observability, project-route policy, relay abstraction, and simulated or
prototype private relay"), grounded in section 33 (native private relay
as an **OS** capability, not a browser feature — browser, AI agents, git,
project containers and native applications are all eligible traffic), 34
(the dual-hop privacy model, and its explicit prohibition: "Do not simply
route all traffic through a single Smplify-owned VPN and call it
private"), 35 (enterprise private networking driven by user / device /
compliance / project / process / agent / destination / policy), 36
(project-aware networking — the ATLAS table, and "AI network boundaries
should be enforced **below the agent** where possible"), 37 (network
observability: who is communicating, destination, reason/category, relay
route, project, AI session — and "Do not perform invasive content
inspection by default"), 45 (security through native OS primitives —
namespaces, cgroups, nftables), 64 (the privacy panel), 21.1 (
`network_destinations` is the ledger category M8 deferred here), 73 (the
restriction-explanation voice), 11.7 (`punar-netd` is a listed core local
service), 6.2 (services RSS), 6.3 (no polling), 6.4 (no write storms),
1.14 (avoid broad tracing when scoped primitives suffice), 1.22 (honesty).

Binding prior contracts, not relitigated:
`schemas/network/network-zone.json` and
`schemas/network/project-network-policy.json` (**SHIPPED — M12 does not
change one byte of either**, §4.1); `schemas/ai-agent/ledger-summary.json`
(**SHIPPED — M8 Decision 0 still holds; M12 does not change one byte**,
§8); `schemas/project/project-environment.json` `permissions.network`;
`docs/api/ipc.md` §1–§16 (including the implemented M12 additions
specified in §11 of this document); `docs/development/milestone-3.md` §4.1 (the
vendored `table inet punar-base` ruleset and the fixed-argv `nft`
backend), `milestone-4.md` (layered policy, reconcile, drift),
`milestone-6.md` §5.3 (`--network none`, declared-not-enforced),
`milestone-7.md` (`punar-agent-<id>.scope`, kernel-attested cgroup
attribution, adapters/data-files-as-data, the mock agent, the check
mechanics), `milestone-8.md` (the four-source evidence model, the
privacy-as-types rule, the `not_yet_observed[]` discipline),
`milestone-9.md` / `milestone-10.md` (approvals/secrets and shadow-AI /
remote query), `docs/design/mockups/privacy-panel.html` (**Plate D-006 —
the acceptance reference for this milestone**),
`docs/design/DESIGN_LANGUAGE.md` §7 (stroke semantics: dashed = outside
the current production claim) and §8 (unmanaged-first).

M6 declared a network block and enforced none of it. M7 gave every
managed agent a kernel-attested cgroup. M8 built a ledger whose
`network_destinations` row has read **NOT YET OBSERVED · MILESTONE 12**
on every surface since it shipped. M12 is the milestone that owes all
three of them an answer, and it pays exactly what it can prove.

---

## 0. The architectural law of this milestone

Five rules. Every decision below is downstream of them.

**Law 1 — Enforcement happens below the agent or it does not count
(spec 36).** A policy an agent enforces on itself is a suggestion. M12's
enforcement point is the kernel: nftables rules, installed by root,
matched on the kernel's own record of which cgroup owns a socket. The
agent has no capability to read, edit or remove them, and punard already
refuses `capabilities.set` from a non-root peer (M8 §12, proven in-VM).

**Law 2 — Observation is derived from mediation points Punar already
owns (spec 1.14, the M8 law).** No eBPF. No packet capture. No
`LD_PRELOAD`. No TLS/SNI inspection. No DNS query logging. No conntrack
flow log. Four sources, and only four (§7.1). A category with no owned
producer renders as a labeled absence, never as an empty success.

**Law 3 — Punar logs what it refused, never what it permitted.** The
only per-connection detail M12 records at packet level is on *deny*
rules, rate-limited by the kernel. Allowed traffic produces counters and
a live socket view, never a flow log. This is spec 6.4 and spec 21.2
("do not record every…") applied to the network.

**Law 4 — A destination host is personal data and belongs only where the
user can delete it.** Destinations appear in the live view (ephemeral)
and in the M8 ledger (purgeable by the user, `punarctl privacy purge`).
They **never** appear in `/var/log/punar/audit.jsonl`, which is
deliberately not purgeable (M8 guarantee 4). Audit records the *zone* and
the *decision*; the ledger records the destination. §8.3.

**Law 5 — The relay does not exist, and every surface says so.** M12
ships a relay *abstraction* and a *simulated* dual-hop model. It carries
no traffic, changes no packet path, and is drawn dashed (DESIGN_LANGUAGE
§7) and labeled `SIMULATED` in text on every surface that names it. §9.

---

## 1. Scope

**In:** `crates/punar-netd` becomes a real bin crate — a fourth resident
daemon (§3); zone data and project route policy compiled into an
effective decision (§4); **real per-agent-session egress enforcement** via
a netd-owned nftables table matched on the session's cgroup (§5);
container network derived from policy (§6); the connection view from
`/proc` socket tables joined to cgroups, plus nftables counters and
rate-limited deny logs (§7); `network_destinations` and
`production_access` becoming observed in the M8 ledger (§8); the relay
abstraction with a simulated dual-hop model (§9); the D-006 privacy panel
(`PUNAR+P`) and `punarctl privacy connections` / `relay status` /
`network policy|zones|explain` (§10); the implemented IPC/audit/data
contracts (§11); `m12-check` + boot-test phase + `punar-m12.png` (§13);
the stale-assertion sweep the honesty law requires (§14); the services
RSS gate growing to a fourth daemon (§12).

**Out (documented, never silently dropped):** any real relay, ingress or
egress hop, or VPN of any kind (Phase 2 — spec 77 lists "real dual-hop
private relay" there by name); DNS protection or a Punar resolver
(Phase 2, §7.5 — the D-006 mockup's green "DNS protection · Active" chip
is a design state M12 has not earned and **must not render**, §10.2);
enterprise routes as anything but a label (needs a real network and a
real org, Phase 2); org-supplied network policy through desired state
(M13+, §4.4); container *connectivity* (the image has no rootless-net
helper, §6); device-wide egress filtering for unmanaged processes (§5.6
— M12 is deliberately not a device egress firewall); escape-proof
isolation via a per-session network namespace (§5.5 — evaluated,
rejected for M12, named as the Phase-2 upgrade); approval-gated zones
executing a real M9 approval (§4.5 — M9 is landing concurrently; M12
enforces `approval_required` as deny-until-approved and proposes the
join); SNI, DNS or payload inspection **in any milestone, ever** (§7.5).

---

## 2. Decision summary

| # | Decision |
|---|---|
| 1 | **`punar-netd` is a separate daemon**, exactly as spec 11.7 lists it, on the `punar-agentd` precedent (M7 decision 1). Socket `/run/punar-netd/netd.sock`, `0660 root:punar`, inside a root-owned `0750 root:punar` directory. Consequence: a **fourth** resident service in the spec 6.2 budget; target ≤ 6 MB RSS; `idle-ram.sh`'s `PUNAR_SERVICE_UNITS` must gain `punar-netd.service` or the gate silently stops measuring the daemon it was written for. §3, §12. |
| 2 | **Table ownership is partitioned by table name, and that is the whole conflict-resolution story.** punard owns `table inet punar-base` (device firewall posture, M3 §4.1). punar-netd owns `table inet punar-net` (per-principal egress policy). Neither daemon ever reads, writes or destroys the other's table. Two tables at the same hook compose safely in nftables: a drop in either is final. §5.1. |
| 3 | **The enforcement primitive is `socket cgroupv2` matching in an nftables output chain.** For each managed agent session, netd emits a jump keyed on the session's **actual** scope cgroup path (read from `/proc/<pid>/cgroup` — the same kernel-attested chain M7/M8 verify, never a hardcoded layout) into a per-session chain of zone rules ending in the project's residual decision. This is real kernel enforcement, needs no new package, no forwarding, no address allocation, and no change to the M6/M7 launch path. §5.2. |
| 4 | **Deny is `reject`, not `drop`, and logging is split from enforcement.** `reject with icmpx type admin-prohibited` fails a `connect()` immediately instead of hanging it (spec 73: a restriction must be legible, and a 130-second timeout is not legible). The rate limiter goes on a **separate log-only rule** ahead of the reject rule — putting `limit rate` on the reject rule itself would make the enforcement fail **open** under flood. §5.3. |
| 5 | **The residual is per-project, and the device default is unchanged.** Inside a session chain: explicit zone sets first, then loopback/link-local, then the project's `internet` decision as the residual. Outside a session chain: **nothing** — M12 does not filter the browser, the user's shell, or any process Punar did not launch. Punar becomes a per-principal egress policy, not a device egress firewall. §5.6. |
| 6 | **Effective decision = strictest of (project route policy, manifest grant)**, with `deny > approval_required > allow`, and unlisted-zone = `deny` inside a session chain. This is a **deliberate divergence** from M4's highest-layer-wins precedence: the two documents are co-equal statements by the same author about the same project, and co-equal disagreement resolves restrictively. §4.3. |
| 7 | **Zone membership is CIDRs only, and netd never resolves a hostname.** `network-zone.json` is not extended (M8 Decision 0 discipline); membership lives in a non-contract data file `/usr/share/punar/network/zone-members.json` (the `process-classes.json` / `suspected.json` precedent). Consequence, stated on every surface: **a zone defined only by hostname cannot be enforced in M12**, and Punar displays a destination *name* only when its own zone data supplied one. §4.1, §7.4. |
| 8 | **punar-netd has no network access at all.** `RestrictAddressFamilies=AF_UNIX AF_NETLINK` + `IPAddressDeny=any`. The daemon that enforces and watches the network structurally cannot open a socket to it. This is what makes decision 7 non-negotiable (name resolution would require DNS) and it is asserted in-VM. §3.3. |
| 9 | **Session attachment: untrusted doorbell, trusted source.** netd watches `/run/punar/agents.json` with inotify purely as a *change signal*, then reads authoritative session state from `punar-agentd` over its socket (`agents.list`, existing method, no new agentd surface). A forged doorbell costs one extra authoritative read and can inject nothing. No timer, no polling. §5.4. |
| 10 | **Full-table regeneration on every change, one `nft -f` transaction** (`destroy table` + full definition in one file — the M3 idempotence pattern). One code path, atomic, no partial-ruleset window. Counters reset on regeneration, so **netd carries the running totals in its own aggregate** and treats kernel counters as deltas. §5.3. |
| 11 | **Enforcement is capability-probed at startup and fails LOUD, not open.** netd loads a probe table using `socket cgroupv2`; if the kernel or build does not support it, netd sets `enforcement: unavailable`, renders `POLICY DECLARED · ENFORCEMENT UNAVAILABLE` on every surface, audits it once, and **claims nothing**. §5.7. |
| 12 | **The container path enforces DENY by construction and cannot grant ALLOW.** `punar-env` derives podman's `--network` from effective policy: an all-deny project gets `--network none` (unchanged bytes, now *derived* rather than blanket), and any-allow project **also** gets `--network none` because the image ships no `passt`/`slirp4netns` — labeled `ALLOW DECLARED · connectivity Phase 2`. Honest and true; no faked connectivity. §6. |
| 13 | **Observability uses bounded kernel metadata only** (§7.1): nftables counters; rate-limited nftables **deny** logs; `/proc/net/tcp{,6}` socket rows; Linux `NETLINK_SOCK_DIAG` cgroup ids joined to the known cgroup-v2 scope; and best-effort pid/name enrichment when ordinary procfs permissions allow it. No `CAP_SYS_PTRACE`, `ss` output parsing (the M3 anti-`hostnamectl` rule), eBPF, pcap, or conntrack flow table. §7. |
| 14 | **Observation passes are on-demand, and M12 adds no timer at all.** Passes run on: panel open/refresh, CLI invocation, session attach/detach, and policy apply. `scanned_at` is rendered so the user knows the view's age. `connections.json` is rewritten **only when the connection set changes** (M10 decision 4 verbatim). Idle write rate 0 B/s, idle CPU 0%. §7.3, §12. |
| 15 | **SNI inspection and DNS query logging are REJECTED, permanently and by name.** Reading a TLS ClientHello is content inspection of the connection payload (spec 37 forbids it by default; Punar forbids it outright). A DNS query log is a browsing history (spec 21.2's never-record spirit). The honest path to real hostnames is a first-party resolver with aggregate-only retention — Phase 2, named, not smuggled in. §7.5. |
| 16 | **The relay is an abstraction plus a SIMULATED model, never a data path.** All three modes (`direct` / `private_relay` / `enterprise_route` — the shipped `network-zone.json` enum) produce the **same packet path** in M12. Putting a userspace proxy on every connection would contradict spec 45 (native primitives, not resident agents), add a failure mode to all traffic, and make the `SIMULATED` label *more* misleading, not less. §9.1. |
| 17 | **The simulated dual-hop is a structural knowledge-partition record, asserted in the check.** `relay.status` returns two hops: ingress carries client identity and no `destination` key; egress carries destination and no `client` key. The property §34 demands and the simulation **does not have** is stated in one sentence on every surface: *both halves are the same process on the same machine under one operator, so nothing is partitioned across trust boundaries; only the record's shape is.* §9.2. |
| 18 | **`network_destinations` fills through a new root-only `ledger.network` method on the agentd socket** — not through the audit stream, because that would write destination hosts into a record the user cannot delete (Law 4). M8's "no ledger code changes" promise is **honestly corrected** here: one method, one evidence value, one `classify()` arm. No new concepts, no schema change, no new privacy surface. §8. |
| 19 | **Level 3 records destinations *reached*; denials are Level 4.** A refused connection did not reach anything, so it is a `production_access` / `denied_access` event reference, not a resource. Destination identifiers are host names when zone data supplied one, else the IPv4 literal, else the **zone name** (the shipped schema forbids `:`, so IPv6 literals are unrepresentable — stated, not worked around). §8.2. |
| 20 | **Unmanaged-first: punard's zero-connection row is an observation, not a claim.** In personal mode punard makes no connections and the panel proves it by enumerating punard's cgroup sockets and finding none — it does **not** claim punard is incapable of network access, because when enrolled it is the control-plane client. `punar-netd`'s own zero row *is* structural (decision 8), and the two are labeled differently. §10.3. |
| 21 | **M12 ships the graphical privacy panel, revising M8 §13's deferral to M13.** M8 deferred it because M8 had no network data; M12 is the milestone that produces the data D-006 renders. M13 keeps demo polish. Bound to `PUNAR+P` (free as of the M10 grammar; if a concurrent milestone has claimed it, implementation takes the next free chord and records it in `keyboard-grammar.md`). §10. |
| 22 | **`m12-check`**, root oneshot chained after `m11-check`, boot-test **phase 14**, `punar-m12.png`. The offline enforcement proof is a **three-way probe**: allow-path connect succeeds, deny-path connect fails fast, and the **identical** deny-path connect from **outside** the scope as the same user **succeeds** — which is the only assertion that proves the rule is per-cgroup rather than global. §13. |

---

## 3. `punar-netd` — separate daemon (decision 1)

### 3.1 Separate daemon, per spec 11.7

Spec section 11 lists eight core local services and `punar-netd` is one of
them, described as "network policy / relay orchestration service". The
same sentence structure gave `punar-agentd` its own daemon in M7 and
`punar-secrets` its own in M9. Three further arguments, so the decision
does not rest on the list alone:

- **Blast radius.** punard is the device's privileged control plane —
  enrollment, reconcile, capability apply. Network policy compilation
  parses per-project data files that a *user* can author (a project
  manifest lives in the user's project directory). Parsing user-authored
  input inside the daemon that owns enrollment and the firewall is a
  worse failure mode than parsing it in a daemon that owns one table.
- **Lifecycle mismatch.** punard's work is timer-driven reconcile
  (M4, 120 s). netd's work is event-driven on session attach/detach and
  on user action. Folding them would put netd's event loop inside
  punard's timer discipline or vice versa.
- **The firewall ownership rule already exists and is the reason
  `nftables.service` is disabled** (M3 §4.1: two owners of one ruleset is
  the bug). Decision 2 extends that rule rather than breaking it: two
  daemons, two *tables*, never two owners of one table.

**Rejected: a `network.*` capability family inside punard.** It would put
per-session, per-project, high-churn state into the capability registry,
whose model is device-wide desired state with a small enum of allowed
values (`schemas/capability/`). A capability whose value is "the set of
currently attached agent sessions" is not a desired state; it is runtime.
The capability registry stays for the things M4 reconciles.

**Cost, stated:** a fourth daemon, a fourth socket, a fourth unit, and a
fourth row in the RSS gate. §12 carries the numbers.

### 3.2 Shape

Same frugal pattern as punard and agentd: std threads, blocking UDS
accept, envelope/framing/error codes reused from `punar-common::ipc`,
`SO_PEERCRED` authorization. No async runtime, no new crates.
Spawns `nft` and nothing else, with **fixed argv** built through
`std::process::Command` — never a shell string (M3 §4.1, M6 §3.2).

### 3.3 Unit hardening — the no-network daemon

```ini
RestrictAddressFamilies=AF_UNIX AF_NETLINK
IPAddressDeny=any
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/run/punar-netd /var/lib/punar/network
PrivateTmp=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_READ_SEARCH
```

`AF_NETLINK` is required because the `nft` child talks to nftables over
netlink; `AF_INET`/`AF_INET6` are absent, so **netd cannot open a network
socket**, and neither can any child it spawns. `CAP_DAC_READ_SEARCH` is
limited to reading validated project policy documents and other read-only
inputs. It is **not** sufficient for cross-user `/proc/<pid>/fd` reads on
Linux and is not claimed to be; managed attribution uses the kernel cgroup id
from `sock_diag` (§7.2), without `CAP_SYS_PTRACE`.

This is why decision 7 (CIDR-only zones) is not a limitation to be
engineered around later by "just adding a resolver to netd": doing so
would delete the strongest honesty property this daemon has.

---

## 4. Policy: zones, project routes, and the effective decision

### 4.1 Zone definitions and zone membership are two different things

`schemas/network/network-zone.json` is SHIPPED and carries `name`,
`display_name`, `description`, `kind`, `relay_mode` — and
`additionalProperties: false`. It has **no field for the addresses a zone
contains**, and M12 does not add one. Reasons, in the M8 Decision-0 voice:

- Zone *membership* is site data, not product contract. Acme's corp_dev
  CIDRs are not a Punar interface; the fixture VM's are not either.
- The first membership field would immediately want ports, protocols,
  exclusions and hostname semantics. Freezing that into `v1alpha1`
  before the enforcement model has ever run in a VM is how contracts rot.
- The schema's own `$comment` already draws this line: runtime network
  records are "deliberately OUT of the v1alpha1 contract layer".

Membership therefore lives in `/usr/share/punar/network/zone-members.json`
— a versioned data file with **no schema**, exactly the precedent of
`/usr/share/punar/agents/process-classes.json` (M8 §3.2) and
`signatures/suspected.json` (M7 §7.1): an internal input versioned by
review.

```json
{"v": 1, "zones": {
  "corp_dev":  {"cidrs": ["10.20.0.0/16"],      "names": {"10.20.0.7": "dev.api.acme.internal"}},
  "corp_prod": {"cidrs": ["10.30.0.0/16"],      "names": {}},
  "privileged_db": {"cidrs": ["10.30.9.0/24"],  "names": {}}
}}
```

`internet` is **never** a member list — it is the residual (§5.2).
`names` is a display-only address→name map that netd was *given*; netd
never derives one (§7.4).

**Proposed for a later milestone, not M12:** once the enforcement model
has actually run, `network-zone.json` gains a `members` block with a
justified shape. Recorded in §11.4 so the absence is a decision.

### 4.2 Inputs

| Input | Owner | Where | Trust |
|---|---|---|---|
| Zone definitions (`network-zone.json` documents) | image | `/usr/share/punar/network/zones/*.json` | root-owned, validated at build by `tools/validate-schemas.sh` |
| Zone membership | image / site | `/usr/share/punar/network/zone-members.json` | root-owned |
| Project route policy (`project-network-policy.json`) | project | `<project>/project-network-policy.json` | **user-authored** — validated, and may only *restrict* (§4.3) |
| Manifest grant (`permissions.network`) | project | `<project>/project-environment.yaml` | user-authored |
| Org policy | Smplify | — | **not implemented in M12** (§4.4) |

### 4.3 The effective decision (decision 6)

```text
effective(project, zone) = strictest(
      project_network_policy.rules[zone].decision,
      manifest.permissions.network[zone] )
where  deny  >  approval_required  >  allow
and    a zone absent from BOTH is `deny` inside a session chain
```

M4's layered model resolves conflicts by **precedence** (the higher layer
wins outright, §39). M12 deliberately does not, for the pair above, and
the reason must be stated because it is a divergence: the manifest and
the route policy are *co-equal statements by the same author about the
same project*. There is no authority ordering between them to appeal to.
When two co-equal statements disagree about a security boundary, the safe
reading is the restrictive one. (Org policy, when it exists, *is* a
higher layer and *does* win by precedence — §4.4.)

`punarctl network explain <project> <zone>` prints both inputs and which
one bound, in the section-73 voice (§10.4). An explanation that says only
"deny" would be exactly the `EPERM` spec 73 calls bad.

### 4.4 Org policy is absent, and that is a decision

M12 ships **no** desired-state path for network policy. Reasons:
unmanaged-first (DESIGN_LANGUAGE §8) says the personal device is the
default and must be complete without an org; the enrollment path (M5) is
mocked; and an org route that cannot be reached from a VM with `-nic none`
would be untestable ceremony. When org network policy lands (M13+), it
enters as a **precedence** layer above the project pair, may loosen as
well as tighten, and every loosening is auditable. Until then
`punarctl network policy` prints `ORG POLICY · NONE · NOT ENROLLED`, and
in personal mode does not print the row at all (§10.3).

### 4.5 `approval_required` in M12

The section-36 PRODUCTION INCIDENT table needs `approval_required`, and
M9 (landing concurrently) owns approvals. M12 does **not** touch M9's
files. Therefore:

- netd compiles `approval_required` to **deny**, with a distinct reason
  code `approval_required`, a distinct counter, and a section-73
  explanation that names the approval path and the exact command instead
  of stopping at "denied".
- The rule is torn down and recompiled to `accept` when an approval grant
  exists — and the grant lookup is the **proposed contract** in §11.3
  (`netd → punard approvals.request` / the `/run/punard/approvals.json`
  side file M9 §15 defines). M12 ships the deny half and the explanation;
  the join lands the milestone after M9's ipc.md sections are stable.
- Honest statement on the surface: `APPROVAL REQUIRED · DENIED UNTIL
  APPROVED · approval gate join lands with the M9 contract`.

Rejected: implementing a second, netd-local approval prompt. Two approval
mechanisms is precisely the "pile of resident agents" architecture spec 45
exists to prevent, and M9 Law 1 is the system's approval law.

---

## 5. Enforcement (decision 3) — the heart of this milestone

### 5.1 Two tables, one hook, zero shared ownership

```text
table inet punar-base   punard      M3    input drop / output accept   device posture
table inet punar-net    punar-netd  M12   output: per-principal egress policy
```

nftables evaluates every table's chains registered at a hook; a packet
must survive **all** of them, and a drop or reject in any one is final.
So the two tables compose without either knowing about the other. netd's
egress chain registers at `hook output priority filter - 10` — ahead of
punar-base's output chain, which has `policy accept` and no rules, so
ordering is not load-bearing today and is pinned only so it stays
predictable when punar-base grows.

Invariants, asserted in-VM (§13 group 3):

- netd never issues `nft` against `punar-base`; punard never against
  `punar-net`. The two argv sets are disjoint and grep-able.
- `m3-check` and `m4-check`'s existing punar-base assertions must keep
  passing **unmodified** after M12 — that is the regression test for the
  partition, and it is the reason M12 does not add rules to punar-base.

### 5.2 The ruleset shape

For project `atlas` (internet allow, corp_dev allow, corp_prod deny) with
one live session `agt_4f21…`:

```text
table inet punar-net {
  set z_corp_dev_v4  { type ipv4_addr; flags interval; elements = { 10.20.0.0/16 } }
  set z_corp_prod_v4 { type ipv4_addr; flags interval; elements = { 10.30.0.0/16 } }

  counter c_4f21_corp_dev_allow  {}
  counter c_4f21_corp_prod_deny  {}
  counter c_4f21_internet_allow  {}

  chain egress {
    type filter hook output priority filter - 10; policy accept;
    socket cgroupv2 level 5 "user.slice/user-1000.slice/user@1000.service/app.slice/punar-agent-4f21….scope" jump s_4f21
  }

  chain s_4f21 {
    # deny zones first — log-only rule, then the enforcing rule (decision 4)
    ip daddr @z_corp_prod_v4 limit rate 5/minute log prefix "punar-net deny corp_prod agt_4f21… " level info
    ip daddr @z_corp_prod_v4 counter name c_4f21_corp_prod_deny reject with icmpx type admin-prohibited

    # allow zones
    ip daddr @z_corp_dev_v4  counter name c_4f21_corp_dev_allow accept

    # local traffic is not a zone decision
    ip  daddr 127.0.0.0/8    accept
    ip6 daddr ::1/128        accept
    ip  daddr 169.254.0.0/16 accept
    ip6 daddr fe80::/10      accept

    # residual = the project's `internet` decision
    counter name c_4f21_internet_allow accept
  }
}
```

If the project denies `internet`, the residual rule becomes the log-then-
reject pair with counter `c_<sid>_residual_deny`, and a session that
reaches it has attempted a destination no zone claims.

**The cgroup path is read, never assumed.** netd resolves the scope's
path from `/proc/<pid>/cgroup` of the session's root process — the exact
string the kernel reports, which is also the string `agents.register`
verifies (M7 §4.3). The `level N` is the component count of that path.
Hardcoding `user.slice/user-<uid>.slice/user@<uid>.service/app.slice/…`
would break the moment a user manager arranges slices differently, and it
would break *silently and open*, which is the worst failure available.

**Loopback is not blanket-accepted before zone matching.** Zone sets are
evaluated first, so a zone may legitimately claim a loopback address —
which is exactly what the offline check fixture does (§13.2). On a real
device no product zone claims loopback and the accept rule applies.

### 5.3 Deny semantics, logging, and counters

- **`reject`, not `drop`** — `connect()` fails immediately instead of
  hanging for the TCP SYN timeout. Spec 73 requires a restriction to be
  legible; a two-minute hang is the least legible failure a network can
  produce. The cost (the process learns it was blocked) is irrelevant
  against a principal Punar launched on the user's own device.
  The check asserts **fails fast (< 2 s)**, not a specific errno: the
  ICMP-admin-prohibited → errno mapping is a kernel detail and pinning it
  would be a brittle assertion dressed as a security property.
- **Logging is a separate rule.** `limit rate 5/minute` is a *matching*
  statement: on a rule that also rejects, exceeding the limit makes the
  rule not match, and the packet falls through to whatever comes next —
  a flood would defeat the deny. The log-only rule carries the limiter;
  the reject rule carries the counter and is unlimited. This is the kind
  of detail that is a footnote in a design and a CVE in an
  implementation, so it is a decision here.
- **Log prefix is structured and destination-free by construction:**
  `punar-net deny <zone> <session> ` — the kernel appends the packet
  header (including `DST=`), which netd reads from the journal on demand
  (§7.1 source B). The prefix itself never carries user data.
- **Counters reset on regeneration** (decision 10), so netd reads all
  counters immediately before it regenerates and folds them into its
  in-memory per-session aggregate. Kernel counters are treated as deltas;
  the totals the user sees are netd's. Stated because a naive
  implementation would silently zero the user's denial history on every
  session attach.

### 5.4 Attachment lifecycle (decision 9)

```text
agentd writes /run/punar/agents.json  ──inotify──▶  netd wakes
                                                     │
                                    reads authoritative state via
                                    agents.list on the agentd socket
                                                     │
                        diff against installed sessions ──▶ regenerate table (one nft -f)
```

- The doorbell file is world-readable and lives in a **user-writable
  directory** — so it is used as a *signal only*. Authoritative session
  state (session id, root pid, project, classification, owner uid) comes
  from the agentd socket, which is `0660 root:punar` in a root-owned
  directory. A user who forges the doorbell buys one extra socket read.
- No new agentd method is required: `agents.list` already returns what
  netd needs (M7 ipc.md §10). netd → agentd is a new DAG edge and does
  not create a cycle; agentd never calls netd.
- **Detach**: a session that disappears from `agents.list`, or whose
  cgroup no longer resolves, has its chain, counters and jump removed in
  the next regeneration, its aggregate flushed to the ledger (§8), and an
  audit `network.session_detach` written.
- **No timer anywhere.** The inotify reader is one blocking thread
  (M8 §4.4's discipline). Idle CPU 0%.

### 5.5 What this can and cannot enforce — the honest limit

**It can:** stop a process inside a managed agent scope from reaching a
denied zone, at the kernel, with no cooperation from the agent, no
library interposition, and no ability for the agent to remove the rule
(nftables is root-only; punard denies non-root `capabilities.set`, proven
in-VM since M8).

**It cannot stop a process that deliberately leaves its cgroup.**
systemd delegates the `user@<uid>.service` subtree to the user, so a
process running as that user may create a sibling cgroup and write its
own pid into `cgroup.procs`, leaving `punar-agent-<id>.scope` and with it
the `socket cgroupv2` match. M12 states this plainly rather than
implying containment:

- The migration is **observable**: netd verifies each attached session's
  cgroup at every pass, and a session whose root process is no longer in
  its scope produces an audit `network.session_detach` with
  `reason: "cgroup_left"`, which the panel shows and which M8's ledger
  ingests as a security-event reference.
- It is **not preventable in M12**, and no wording anywhere may suggest
  otherwise. The surface reads `ENFORCED · below the agent · escapable by
  deliberate cgroup migration (see milestone-12 §5.5)`.
- The related, narrower gap: `socket cgroupv2` resolves a path to a
  cgroup **id** at ruleset load. If a cgroup is destroyed and its id is
  later reused, a stale rule could match an unrelated cgroup. netd's
  per-pass verification plus teardown-at-detach bound the window to one
  pass; the residual risk is recorded here rather than in a footnote.

**The escape-proof answer is a network namespace, and M12 does not ship
it — evaluated, rejected, scheduled.** Three concrete blockers, not
distaste:

1. A **user** scope cannot enter a **root-owned** netns: `setns(2)`
   requires `CAP_SYS_ADMIN` in the namespace's user namespace, which an
   unprivileged user does not have. So `punar-netd` cannot simply hand
   `punar-env` a namespace path.
2. The workable variant — the launcher does `unshare --user --net`, and
   netd (root) then inserts a veth — is genuinely escape-proof (the
   process cannot `setns` back to the host netns), but it requires
   address allocation, `net.ipv4.ip_forward=1` (a device-wide sysctl
   change), a masquerade rule, a forward-chain hole through punar-base's
   `policy drop`, and in-namespace DNS. That is a milestone, not a
   section.
3. It would be **untestable on the CI VM**, which has `-nic none`: a
   namespace with a veth to a host that has no uplink proves the plumbing
   and nothing about the policy.

Scheduled as the Phase-2 upgrade in §15, with the note that when it
lands, decision 3's rules remain as defense in depth rather than being
replaced.

### 5.6 M12 is not a device egress firewall

Only principals Punar launches are subject to `punar-net`. The browser,
the user's shells, and every other process keep the M3 posture (inbound
drop, outbound accept) unchanged. Reasons:

- Spec 36's sentence is about **AI network boundaries**, below the agent.
- A device-wide default-deny egress policy would need a per-application
  allowlist UX that does not exist and that spec 76 does not ask for
  until never.
- It would break the machine on first boot in exactly the way a
  keyboard-first workstation must not.

The panel **observes** every process (§7) and **polices** only the ones
Punar launched. The gap between "watched" and "policed" is stated in the
panel footer and in `punarctl privacy connections`, because a user who
sees their browser listed could otherwise reasonably assume it is
governed.

### 5.7 Capability probe — fail loud (decision 11)

At startup netd applies a throwaway probe table containing one
`socket cgroupv2 level 1 "user.slice"` rule. On failure (kernel without
`CONFIG_NFT_SOCKET`, cgroup v1 layout, nft too old):

- `enforcement_state = "unavailable"` with the nft error captured;
- one audit event `network.enforcement_unavailable`;
- every surface renders `POLICY DECLARED · ENFORCEMENT UNAVAILABLE ·
  <reason>` — the same dashed honesty grammar M7/M8 use for absences;
- no `punar-net` table is installed at all. A half-installed table that
  matches nothing is worse than none, because it looks like enforcement
  in `nft list ruleset`.

`m12-check` asserts the probe **succeeded** — because if it did not, every
enforcement claim in this document is false on that image and the check
must say so rather than skipping the group.

---

## 6. The container path (decision 12) — making M6's declaration partly real

M6 §5.3 runs every environment container with `--network none` and labels
the manifest's network block `declared · enforced M12`. M12 changes what
that argument *means* without changing the bytes for the Atlas fixture:

| Effective project policy | podman argument in M12 | Label |
|---|---|---|
| every zone `deny` (or none allowed) | `--network none` | **`ENFORCED · deny by construction`** |
| any zone `allow` | `--network none` | **`ALLOW DECLARED · connectivity Phase 2`** |

- The **deny half is genuinely enforced**, and by the strongest mechanism
  in this document: a container with no network namespace interface
  cannot reach anything, and nothing inside it can change that (podman
  set it up outside the container's reach).
- The **allow half is not grantable**. The image ships no `passt` and no
  `slirp4netns` (M6 §5.3 verified this against the pinned snapshot), so
  rootless podman has no user-mode network helper. M12 adds no package
  for it: a rootless network stack is a real integration with real
  budget consequences and it belongs to the milestone that can test it
  against a network.
- `punar-env status`'s network row changes from
  `Network       isolated (M6) · declared zones enforced M12` to
  `Network       none · deny enforced · allow declared (Phase 2)`, and
  the per-zone rows change from `declared · enforced M12` to
  `enforced (agent scope) · container: deny only` / `declared` as
  appropriate. **These are stale-assertion sites — §14.**

Why not give the container the agent's cgroup-matched treatment? Because
a container is already in its own netns; `socket cgroupv2` rules in the
host netns never see its packets. The container's enforcement point is
podman's `--network`, and in M12 that argument has exactly two useful
values.

---

## 7. Observability without tracing (decision 13)

### 7.1 The bounded sources

| # | Source | Owned since | Produces | Cost |
|---|---|---|---|---|
| A | **nftables counters** in `punar-net`, read with `nft -j list table inet punar-net` (fixed argv) | M12 | per (session, zone, decision) packet/byte totals — including denial totals | one `nft` invocation per pass |
| B | **Rate-limited nftables `log` on DENY rules only**, read from the journal on demand (`journalctl -k -o json --since <last>`) | M12 | the destination address of *refused* attempts | bounded by the kernel's own 5/minute limiter |
| C | **`/proc/net/tcp`, `/proc/net/tcp6`** | kernel | live TCP socket inode, remote address and state; local addresses and ports are parsing-only and never serialize | one pass over two files, on demand only |
| D | **Linux `NETLINK_SOCK_DIAG` / `INET_DIAG_CGROUP_ID`** joined to the inode of the authoritative cgroup-v2 directory | kernel + M7 §5.1 | which managed scope owns the socket, even when cross-user fd links are hidden | two bounded local netlink dumps per pass (IPv4 + IPv6) |
| E | **Best-effort `/proc/<pid>/fd` inode join plus `/proc/<pid>/cgroup`** | kernel | a display name/pid class for same-credential or otherwise-readable processes | stops when every candidate inode visible to the daemon is resolved; never required for managed attribution |
| F | **Authoritative `agents.list` join** | M7 §5.1, M8 §4.1 | session id, project and agent identity for the kernel-attested cgroup | one local authenticated UDS read |

Nothing else. Specifically **not**: eBPF (spec 77 lists it as Phase 2
"where justified" — M12 does not need it and therefore is not justified);
packet capture; `LD_PRELOAD` or any interposition; the conntrack flow
table (`/proc/net/nf_conntrack` — rejected: it carries no per-process
attribution, so it cannot answer section 37's *first* question, and a
device-wide UDP flow table edges toward the browsing-history problem for
zero added answer); parsing `ss` output (the M3 anti-`hostnamectl` rule:
Punar reads kernel files, it does not scrape CLI text).

### 7.2 The socket→managed-scope join

`/proc/net/tcp{,6}` gives, per socket: local address:port, remote
address:port, state, uid, and **inode**. A `NETLINK_SOCK_DIAG` dump returns
`INET_DIAG_CGROUP_ID` for the same inode. The cgroup-v2 filesystem inode of
the already authenticated `punar-agent-<id>.scope` is that kernel id, so the
join is direct and cannot be forged by the observed process. This fixes an
important Linux boundary: `CAP_DAC_READ_SEARCH` does not bypass the ptrace
credential check on another user's `/proc/<pid>/fd` symlinks. Punar does not
add `CAP_SYS_PTRACE` to work around that boundary.

The `/proc/<pid>/fd` walk remains best-effort enrichment for human-readable
process rows. It is never the authorization or managed-attribution source.

Bounds, because an unbounded `/proc` walk is how a "lightweight" OS gets
heavy:

- The walk runs **only** when a pass is requested (§7.3), never on a
  timer.
- Sockets in states Punar does not render (`TIME_WAIT`, `SYN_RECV`) are
  filtered before the fd walk, so the walk is proportional to live
  connections, not to socket-table size.
- The walk stops early once every candidate inode visible to it is resolved.
- A pid whose fds cannot be read (raced exit, another user, or `hidepid`)
  can still be attributed to a managed session by kernel cgroup id. If neither
  source resolves it, the row remains `unknown` rather than being dropped —
  an unattributed connection is information, and hiding it would make the
  panel quietly incomplete.

### 7.3 Passes are on-demand (decision 14, spec 6.3)

Triggers, exhaustively: privacy-panel open; panel refresh keystroke; any
`punarctl privacy connections` / `relay status` / `network policy`
invocation; session attach or detach; policy apply. **No systemd timer,
no interval, no background loop.** M10 added a timer for shadow-AI
detection because a detection nobody is looking at still matters; a
connection list nobody is looking at does not — nothing acts on it, and
its evidence (counters, deny logs, the ledger aggregate) accumulates in
the kernel and on disk regardless of whether anyone renders it.

`connections.json` (the panel's side file, §10.1) is rewritten **only
when the rendered set changes** — M10 decision 4 verbatim. A pass that
changes nothing writes nothing. Idle disk write rate: 0 B/s.
`scanned_at` is rendered on the panel and the CLI so the reader always
knows the age of what they are looking at.

### 7.4 What the panel can show, and what it cannot (the resolution limit)

**Can show** — per connection: the **process** (name and pid class),
the **destination** as an address, the destination **host name** *only
when netd's own zone data supplied one* (§4.1 `names`), the **zone** and
its `kind` (the section-37 "reason/category"), the **route** value
(`direct` / `private_relay` / `enterprise_route`, all SIMULATED except
`direct`), the **project**, and the **AI session** (`agt_… · atlas`) when
the owning cgroup is a managed agent scope. Per process: a live
connection count. Per session: denial totals by zone.

**Cannot show, and will not:**

- **Payloads.** No mechanism exists in M12 to read one, by construction.
- **Hostnames in general.** Punar never learns that `151.101.x.x` is
  `github.com`. Getting that requires either DNS observation or SNI
  observation, both rejected (§7.5). The panel renders an address, and
  the D-006 mockup's friendly hostnames are, in M12, **only** those a
  zone's `names` map supplied. The implementation must not paper over
  this with a reverse-DNS lookup — netd has no network access (§3.3),
  and a PTR record is a third party's opinion of a name, not the name the
  application asked for.
- **Per-request detail.** One TLS connection carrying two hundred HTTP
  requests is one row. Punar counts connections, not requests.
- **UDP flows and QUIC.** `/proc/net/udp` has no connection state worth
  rendering and QUIC would need payload parsing to be meaningful. M12
  renders TCP only, and says so on the surface (`TCP · UDP/QUIC not
  observed`) rather than showing a shorter list that looks complete.
- **The *reason* a connection was made,** beyond the zone category. "AI
  inference" in the spec-37 sketch is a category derived from the
  destination's zone, not an inferred intent. When no zone claims the
  destination the category renders `—`, never a guess.

### 7.5 Rejected forever: SNI and DNS logging (decision 15)

- **SNI inspection** means parsing the TLS ClientHello of the user's
  connections. That is content inspection of the connection payload.
  Spec 37 says do not do it "by default"; Punar's answer is stronger and
  simpler: it is not implemented, and a future milestone that wants it
  must argue against this paragraph. It also fails on its own terms —
  Encrypted Client Hello removes it — so it would be a privacy cost paid
  for a decaying benefit.
- **DNS query logging** would produce a complete record of everything the
  user or their agent looked up, i.e. a browsing history, on a device
  whose ledger deliberately refuses to record file reads (spec 21.2, 6.4).
- **The honest path to real names** is a first-party resolver that Punar
  operates, which knows the name because it answered the query, retains
  **aggregates only**, and is subject to the same purge command as the
  ledger. That is a Phase-2 design with its own privacy argument, named
  here so its absence is a decision and not an oversight.

---

## 8. Filling the M8 ledger (decision 18)

### 8.1 The event/source contract, and an honest correction

M8 §3.1 wrote: *"Network destinations arrive when `punar-netd` emits
per-session destination aggregates… When M9/M12 ship, no ledger code
changes."* The first half is exactly what M12 does. The second half is
**not literally keepable, and this document corrects it rather than
quietly stretching it** (spec 1.22):

- M8's Level-4 categories are derived from the **audit stream** (source
  B), so `production_access` needs only **one match arm** in
  `classify()` — precisely what M8 predicted, and precisely what M9 §9.4
  did for `policy_bypass_attempt`.
- M8's Level-**3** resources are derived from the cgroup and the
  workspace grant. There is **no** audit-derived Level-3 path. So
  `network_destinations` needs a new ingestion source, which is a code
  change.

What M8 actually guaranteed, and what M12 keeps: **no new ledger
*concepts*, no schema change, no new privacy surface, no new retention
rule, no new user-facing delete story.** The additions are one IPC
method, one evidence value, one classify arm.

### 8.2 The contract

**`ledger.network` on the agentd socket, root peer only** (implemented wire
text in §11.2):

```json
{"method": "ledger.network",
 "params": {"session_id": "agt_4f21c09ab3e1",
            "destinations": [
              {"destination": "10.20.0.7", "zone": "corp_dev",
               "count": 3, "first_seen": "…", "last_seen": "…"}],
            "source": "netd_aggregate"}}
```

- **Root-only.** A non-root peer writing ledger content would let a local
  process forge another principal's history. Denial carries the
  section-73 voice.
- Called by netd at **session detach** and at **pass end when the
  destination set for a session has changed** — not per connection
  (spec 6.4).
- agentd validates every `destination` through the existing
  `ResourceClass` newtype (M8 §2), so the schema pattern
  `^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$` and the no-`/`, no-`:`,
  no-whitespace rule apply unchanged. A port cannot be represented. A URL
  cannot be represented. This is why the method takes a destination and a
  zone as separate typed fields rather than a formatted string.
- New evidence value **`netd_aggregate`** joins
  `{cgroup_scope, audit_event, workspace_bind, adapter_metadata}`.
  **This makes an m8-check assertion stale — §14.**

**Identifier selection, in order:**

1. the host name, if netd's zone `names` map supplied one for that
   address;
2. otherwise the IPv4 literal (which the schema pattern accepts —
   digits and dots);
3. otherwise the **zone name** (`corp_dev`) — which the shipped schema
   explicitly sanctions as a destination identifier.

Case 3 is where **every IPv6 destination lands**, because the shipped
pattern rejects `:` (deliberately, so URLs cannot appear) and an IPv6
literal cannot survive it. M12 does not amend the schema to fit; it
records the zone and states the limitation on the surface:
`IPv6 destinations are recorded by zone (the ledger identifier forbids
':')`.

### 8.3 Level 3 vs Level 4, and Law 4

- **Level 3 `network_destinations` records destinations *reached*** —
  allowed connections that reached the ESTABLISHED state. A refused
  connection reached nothing.
- **Level 4** gets the denials, as **event references** into the audit
  log (M8 §4.3's model, unchanged):
  - deny in a zone whose `kind` is `production` → `production_access`;
  - deny in any other zone → `denied_access`;
  - a zone whose `kind` is `privileged` → `sensitive_resource_access`
    (M9 §9.3 re-milestoned this row to **M12**; M12 pays it).
- **The audit event carries the zone and the decision, never the
  destination host** (Law 4). The audit log is not purgeable; the ledger
  is. A user who runs `punarctl privacy purge` must not find their
  destinations preserved in a record they cannot touch. This asymmetry is
  the reason `ledger.network` exists at all instead of the simpler
  "netd writes audit, agentd's tail picks it up" design.
- Aggregate counts only. There is no per-connection log anywhere on disk
  in M12.

### 8.4 `not_yet_observed[]` after M12

| Row | Before M12 | After M12 |
|---|---|---|
| L3 `network_destinations` | `M12` | **removed** — producer ships |
| L4 `production_access` | `M12` | **removed** — producer ships |
| L4 `sensitive_resource_access` | `M12` (per M9 §9.3) | **removed** — producer ships (privileged-kind zones) |
| L3 `mcp_servers` | `M11+` (per M9 §9.3) | unchanged |
| L4 `unknown_ai_execution` | `M10` | unchanged (or removed by M10) |

Every removal is a **stale-assertion site** in `m8-check` — §14.

---

## 9. The relay (decisions 16, 17)

### 9.1 An abstraction, not a data path

`relay_mode` already exists as a three-value enum in the shipped
`network-zone.json`: `direct` | `private_relay` | `enterprise_route`.
M12 makes it a first-class runtime concept — a **route decision** computed
per (project, zone, session) and rendered on every connection row — and
makes it carry **no traffic whatsoever**.

Why no proxy, not even a loopback one:

- Putting a daemon on every connection's data path is the resident-agent
  architecture spec 45 and the executive summary exist to reject.
- It would add a device-wide failure mode and a throughput cost to all
  traffic, for a relay that connects to nothing.
- It would make the `SIMULATED` label *less* honest, not more: traffic
  really would flow through something, and that something would not be a
  privacy relay. A user who sees packets moving through "the relay"
  reasonably concludes the relay is real.
- It would require `AF_INET` in netd's unit, deleting decision 8 — the
  strongest honesty property the daemon has.

So in M12: **all three modes produce the identical packet path (direct).**
The mode is a recorded decision and a label, and the label says
`SIMULATED` wherever it is not `direct`.

### 9.2 The simulated dual-hop, and the property it does not have

`punarctl relay status --json` returns the section-34 model as data:

```json
{"mode": "private_relay", "simulated": true,
 "hops": [
   {"role": "ingress", "knows": ["client_identity", "connect_time"]},
   {"role": "egress",  "knows": ["destination", "connect_time"]}],
 "property_claimed": "no single hop holds both client identity and destination",
 "property_not_held": "both hops are the same process on the same device under one operator; nothing is partitioned across trust boundaries, and a single-operator relay may never claim the section 34 drawing",
 "real_relay_milestone": "phase_2"}
```

Structurally: the ingress hop record has **no `destination` key** and the
egress hop record has **no `client` key** — not empty strings, absent
keys, the M8 privacy-as-types discipline applied to a simulation. That is
assertable (§13 group 11) and it is the only thing about the relay that
M12 asserts.

The sentence that must appear, verbatim in spirit, on every surface that
names the relay:

> Simulated. Both hops are the same process on this device. A real
> dual-hop relay requires two independently operated hops in different
> administrative domains; routing everything through one Smplify VPN
> would not be one (spec §34).

Plate D-006 already encodes this at the drawing level: the dual-hop plate
is stroked **dashed** and captioned `drawn dashed — simulated in MVP`.
DESIGN_LANGUAGE §7 makes that stroke a claim, so the QML must reproduce
the dashed stroke, not a solid approximation of it. §13 group 11 asserts
the text label; the dashed stroke is verified by eye against
`punar-m12.png` and by `qmllint`-clean source review.

### 9.3 Personal toggle, enterprise mode

- `punarctl relay set direct|private_relay` writes a **user preference**
  (the M4 preference-layer mechanism, punard-side — proposed join in
  §11.3; until then netd persists it under `/var/lib/punar/network/`
  and the surface says which). Personal mode's relay is the user's own
  toggle (D-006 Sect I 01), and every `private_relay` render carries
  `SIMULATED`.
- `enterprise_route` is **only offerable when enrolled**, and in M12 it
  is a label with no route behind it. In personal mode the mode is not
  offered, not listed, not greyed out — it is absent (DESIGN_LANGUAGE §8:
  org chrome appears only when enrolled).

---

## 10. Surfaces

### 10.1 The privacy panel — Plate D-006 (decision 21)

`PUNAR+P` → `punar-shell` `PrivacyPanel` (IPC target `privacypanel`), the
full-surface D-006 layout:

```text
PUNAR · PRIVACY                                          punar-dev · Personal
──────────────────────────────────────────────────────────────────────────────
[ Private relay · Active  SIMULATED ]  [ DNS protection · Not configured · Phase 2 ]
[ Your device · Your rules ]

WHO IS TALKING TO THE NETWORK?                          scanned 14:31 · TCP only
  ● punar-mock-agent      agt_4f21… · atlas · 1 connection
      127.0.0.9           local fixture      Direct           Atlas · agt_4f21…
      corp_prod           DENIED · 3 attempts · production    punarctl network explain atlas corp_prod
  ● chromium              6 connections
  ○ punard                0 connections · nothing to report home
  ○ punar-netd            0 connections · cannot open one (AF_INET denied)
──────────────────────────────────────────────────────────────────────────────
↑↓ Process · ↵ Expand · Esc Close     No content inspection · punarctl privacy connections
Watched ≠ policed: only sessions Punar launched are governed (milestone-12 §5.6)
```

- Data path: a **root-owned side file** `/run/punar-netd/connections.json`,
  `0640 root:punar`, written atomically on change only. Same reasoning as
  M8 §8.2 and M10 decision 7: a connection list is personal data, and a
  forgeable privacy panel is a phishing primitive. `/run/punar` is
  user-writable and therefore disqualified. The shell reads it with an
  event-driven `FileView`; no socket client in the shell, no polling.
- Missing or unparsable → `No connection view available` and the reason,
  never an error surface (M7/M8 fail-closed rule).
- Denied rows are the only red on the surface (D-006's voice; the M8
  `.evrow` precedent), and each carries its explain command.

### 10.2 The DNS chip — a design state M12 must not render

D-006's status band draws `DNS protection · Active` with a green presence
dot. **M12 has no DNS protection at all.** Rendering that chip would be
the exact failure spec 1.22 exists to prevent. The panel renders
`DNS PROTECTION · NOT CONFIGURED · PHASE 2` in the dashed honesty grammar
M7 established. This is a deliberate, recorded divergence from the
mockup, and the mockup is not wrong — it is a design of the finished
state, and the milestone that earns the green dot may draw it.

### 10.3 Unmanaged-first (decision 20)

On a personal device the panel shows: the user's own traffic; **no** org
rows, **no** enterprise route values, **no** compliance chips, **no**
Smplify anything (DESIGN_LANGUAGE §8). Two zero-connection rows, labeled
differently because they are different facts:

- `punard · 0 connections · nothing to report home` — an **observation**.
  punard *can* reach the network; when enrolled it talks to
  `control.smplify.com` (D-006's managed variant shows exactly that row).
  In personal mode it does not, and the panel proves it by enumerating
  punard's cgroup sockets and finding none. The wording must not imply an
  incapability punard does not have.
- `punar-netd · 0 connections · cannot open one (AF_INET denied)` — a
  **structural** fact from decision 8, verifiable with
  `systemctl show punar-netd -p RestrictAddressFamilies`.

Both rows are asserted in-VM (§13 group 12/13). The first is the
personal-mode proof of silence D-006 Sect II calls the most important row
on the surface.

### 10.4 CLI (Plate D-014 grammar; spec 11.2)

- **`punarctl privacy connections [--json]`** — the spec-11.2 verb, now
  real. Terminal parity with the panel: masthead, status band, the
  who-is-talking list with per-destination tuples, denial rows, the
  footer boundary sentence. This **replaces the M8 placeholder that
  currently exits 1 naming Milestone 12 — a stale assertion, §14.**
- **`punarctl relay status [--json]`**, **`punarctl relay set <mode>`** —
  §9.
- **`punarctl network zones [--json]`** — zone definitions, kinds,
  membership counts, and which are enforceable (CIDR-backed) versus
  name-only (`NOT ENFORCEABLE · names are not membership`, §4.1).
- **`punarctl network policy <project> [--json]`** — the section-36 table:
  every zone, the manifest value, the route-policy value, the effective
  decision, which input bound, and the container-network consequence.
- **`punarctl network explain <project> <zone>`** — the section-73
  answer, and the surface every denial points at:

```text
PUNAR · NETWORK — WHY THIS WAS BLOCKED

WHAT HAPPENED     Claude Code (agt_4f21…) tried to reach the PRODUCTION zone
                  from the Atlas workspace. The connection was refused by the
                  kernel before it left this device.
WHY               Atlas declares corp_prod: deny in both its route policy and
                  its environment manifest.
WHO SET IT        You — this project's own files. No organization is enrolled.
WHICH POLICY      atlas/project-network-policy.json · atlas/project-environment.yaml
CAN YOU CHANGE IT Yes. Edit either file and run punarctl network apply atlas.
IS APPROVAL       Not applicable — this zone is deny, not approval_required.
NEXT STEP         punarctl network policy atlas   ·   punarctl privacy connections
ENFORCED BY       nftables · table inet punar-net · matched on this session's cgroup
                  Escapable by deliberate cgroup migration (milestone-12 §5.5)
```

### 10.5 The explanation is out-of-band — an honest limit

The kernel hands the blocked process an errno. Punar cannot inject prose
into `git`'s stderr. So the section-73 explanation reaches the user
through the panel row, the CLI, and the audit event — **not** through the
failing command. Stated plainly because spec 73's promise ("every
enterprise restriction should answer…") is otherwise easy to over-claim.
The inline path exists only where Punar wraps the process (`punar-env`
subcommands could translate a connect failure into the explanation), and
M12 does not build it; a shell notification on denial is M13.

---

## 11. Proposed contract (to land in `docs/api/ipc.md` at implementation time)

This document does not edit `ipc.md` — M9 and M10 are landing in it
concurrently. The following is the wire contract M12's implementation
adds, as new sections, additively.

### 11.1 New sibling socket: `punar-netd`

```text
/run/punar-netd/            0750 root:punar   (tmpfiles)
/run/punar-netd/netd.sock   0660 root:punar
/run/punar-netd/connections.json  0640 root:punar
/var/lib/punar/network/     0700 root:root
```

Same framing, envelope and error codes as `punar-common::ipc`
(ipc.md §2–§4). Admission by group `punar`; mutations by `SO_PEERCRED`.

| Method | Peer | Mutating | Audited |
|---|---|---|---|
| `network.status` | any admitted | no | no |
| `network.connections` | any admitted | no (runs a pass) | no |
| `network.zones` | any admitted | no | no |
| `network.policy` `{project}` | any admitted | no | no |
| `network.explain` `{project, zone}` | any admitted | no | no |
| `network.apply` `{project?}` | **root** | yes | yes (`network.apply`) |
| `relay.status` | any admitted | no | no |
| `relay.set` `{mode}` | session owner or root | yes | yes (`relay.set`) |
| everything else | — | — | `unknown_method` |

Reserved and honestly absent: `network.capture`, `network.inspect`,
`network.export` — these do not exist and must return `unknown_method`,
so a user who probes for them learns the boundary (the M8 `ledger.export`
precedent).

`network.connections` result shape:

```json
{"scanned_at": "…", "enforcement": "available",
 "relay": {"mode": "private_relay", "simulated": true},
 "dns_protection": {"state": "not_configured", "milestone": "phase_2"},
 "processes": [
   {"name": "punar-mock-agent", "pid_class": "agent",
    "session": {"id": "agt_4f21c09ab3e1", "project": "atlas"},
    "governed": true,
    "connections": [
      {"destination": "127.0.0.9", "name": null, "zone": "internet",
       "category": "local fixture", "route": "direct", "state": "established"}],
    "denied": [{"zone": "corp_prod", "kind": "production", "attempts": 3,
                "last_destination": "127.0.0.7",
                "explain": "punarctl network explain atlas corp_prod"}]},
   {"name": "punard", "governed": false, "connections": [],
    "note": "no connections · nothing to report home"}]}
```

`governed: false` is the machine-readable form of §5.6's watched-≠-policed
boundary; no surface may omit it.

### 11.2 Additive to the agentd socket (ipc.md §12/§13)

- **`ledger.network`** — root peer only, params per §8.2, result
  `{accepted: <n>, rejected: <n>}` where `rejected` counts destinations
  the `ResourceClass` newtype refused. Audited only on rejection
  (a rejection means a producer tried to write something the privacy type
  forbids — that is a security event about Punar, not about the user).
- **Evidence enum** gains `netd_aggregate` (ipc.md §13.1).
- **`not_yet_observed[]`** loses three rows (§8.4).
- `classify()` gains one arm: audit `action == "network.deny"` with a
  `zone_kind` of `production` → `production_access`; `privileged` →
  `sensitive_resource_access`; else `denied_access`.

### 11.3 Proposed joins deferred to the milestone after M9/M10 stabilize

- **netd → punard `approvals.request`** for `approval_required` zones
  (§4.5), reading M9's `/run/punard/approvals.json` side file for grant
  state.
- **relay mode as a punard preference key** so `punarctl policy effective`
  and `policy explain` cover it like every other user preference (M4).
  Until then netd persists it and the surface says which store holds it.

### 11.4 Data files (no schema, versioned by review)

- `/usr/share/punar/network/zone-members.json` (§4.1).
- `/usr/share/punar/network/zones/*.json` — `network-zone.json`-valid
  documents, validated by `tools/validate-schemas.sh` at build.
- **Proposed for a later milestone:** a `members` block in
  `network-zone.json` once the enforcement model has run in a VM.

### 11.5 Audit actions (spec 53 contract, additive)

`network.apply` · `network.deny` · `network.session_attach` ·
`network.session_detach` · `network.enforcement_unavailable` ·
`relay.set`. Every one carries `agent_session_id` where a session is
implicated, `project`, `zone`, `zone_kind`, `decision` — and, per Law 4,
**never a destination host**.

---

## 12. Budgets (spec 6.2–6.4, `PERFORMANCE_BUDGETS.md`)

- **RAM.** `punar-netd` target **≤ 6 MB** RSS: per-session aggregates
  only (bounded by zones × sessions), no socket table held between
  passes, no journal buffer retained. M7 measured **4 MB combined** for
  punard + punar-agentd; M9 adds `punar-secrets`; M12 makes it **four**
  daemons in one number. Target < 100 MB, MVP ceiling 150 MB — unchanged
  and not close.
- **The gate must be updated or it stops measuring.**
  `idle-ram.sh:63` currently reads
  `PUNAR_SERVICE_UNITS="punard.service punar-agentd.service"`. M12 appends
  `punar-netd.service`. **This is a merge point with M9**, which appends
  `punar-secrets.service` to the same line; whichever lands second keeps
  both. A `PUNAR_SERVICES_RSS_MB` that silently omits the new daemon
  would report a passing number for a budget nobody measured — call it
  out in review. **And it breaks an M11 assertion:** `m11-check`
  asserts the list is *unchanged*, because M11 deliberately adds no
  daemon. That assertion must be rewritten to the invariant M11 means
  (§14.3), not deleted — M11's point is worth keeping.
- **CPU.** Zero at idle by construction: one blocking inotify thread, no
  timers, all other work on user action or session lifecycle.
- **Disk.** `connections.json` written on change only; per-session
  network aggregate ≤ 2 KiB, folded into the M8 ledger record whose
  4 MiB directory budget is unchanged. Idle write rate **0 B/s**.
- **Kernel.** One nftables table, O(sessions × zones) rules, regenerated
  in one transaction on change. Deny logging is rate-limited by the
  kernel at 5/minute per rule — the journal cannot be flooded by a
  process in a loop.
- `PERFORMANCE_BUDGETS.md` §2 gains a `punar-netd` row with these
  numbers, and §2.3's combined-services paragraph gains the third (or
  fourth) unit.

---

## 13. In-VM exercise plan — `m12-check`

`/usr/lib/punar/m12-check.sh`, root oneshot (`punar-m12-check.service`,
**never enabled** — vendor `/usr/lib/systemd/system/…wants/` symlink only,
and the check asserts symlink + `Wants=`, never `is-enabled`), started
synchronously by `idle-ram.sh` **after `m11-check`**; `set -u`, always
exits 0; verdict lines to `/run/punar/m12-report.txt`, final
`PUNAR_M12_OK` / `PUNAR_M12_FAIL`; host gate `boot-test.sh` **phase 14**
(M11 claims phase 13 — `milestone-11.md` §12; if M11's numbering moves,
M12 takes the next free phase and this line records it).
**Committed 0755** or the unit fails `ExecStart`. All verdict greps are
case-insensitive (`fmt::verdict` uppercases). **No `cmp`/`diff`** — the
image has no diffutils; use `sha256sum`. `qs` invocations pass
`-p /usr/share/punar/shell`. A missing verdict is a hard failure.

### 13.1 Image facts that shape the plan

`nftables 1.1.6` (M3), `iproute2` (from `base`), `git`, `jq`, `grim`,
`chromium`, `podman`+`crun`+`netavark`, **`bash`** (from `base`). **No**
`socat`, `nc`, `python`, `curl`, `diffutils`, `passt`, `slirp4netns`.
The VM runs `-nic none`: **loopback is the only network that exists.**

### 13.2 Generating real traffic with no network

Two tools already in the image do all of it:

- **Listener:** `git daemon --listen=127.0.0.9 --listen=127.0.0.7
  --port=9418 --export-all --base-path=/var/lib/punar/m12 --init-timeout=0`
  started by the check (outside any agent scope) over a fixture bare
  repository. A real TCP listener, fixed argv, offline.
- **Client:** `bash`'s `/dev/tcp` redirection —
  `exec 3<>/dev/tcp/127.0.0.9/9418` — opens a real outbound TCP
  connection with no extra package. Holding fd 3 open plus a blocking
  `sleep infinity` gives a **long-lived ESTABLISHED** socket for the
  observability pass to find.

**Fixture zone data** (staged only for the check, and labeled as fixture,
never product data): `corp_prod → 127.0.0.7/32`, `internet` residual
allow. Because zone sets are evaluated before the loopback accept
(§5.2), a loopback address is a legitimate zone member and the whole
enforcement chain is exercised without a NIC. The report prints one
`info` line saying so in plain words, so no reader mistakes a loopback
fixture for a production zone.

**Probe injection into the live scope**, on the M8 mock-agent precedent:
`punar-mock-agent` gains one opt-in behavior, `PUNAR_MOCK_AGENT_NET=1`
(unset by default), which creates `.punar-agent-net-fifo` and **blocks
reading it** (a blocking read, not a poll loop — spec 6.3). The check
writes `go` into the fifo *after* it has asserted that the session chain
exists in `nft`, which removes the install-vs-probe race entirely. The
agent then runs the allow probe (long-lived), the deny probe (once), and
writes both exit codes and elapsed times to
`.punar-agent-net-result`.

### 13.3 Assertion groups (target ≈ 60 assertions)

1. **Preflight** — `punar-netd.service` active; socket
   `0660 root:punar` inside `0750 root:punar`; `punar-netd-check` unit
   is a vendor `.wants` symlink with `Wants=` and is **not** asserted via
   `is-enabled`; `/usr/share/punar/network/zones/*.json` parse and each
   validates structurally (jq: required `name`, `kind` in the four-value
   enum, `relay_mode` in the three-value enum); `zone-members.json`
   parses with `v == 1`.
2. **Enforcement capability probe** — `punarctl network status --json`
   reports `enforcement == "available"`. **If this fails the group emits
   FAIL, never skip**: every enforcement claim below is void on that
   image and the report must say so.
3. **Table partition** — `nft -j list table inet punar-net` exits 0 and
   contains chain `egress` at `hook output`; `nft -j list table inet
   punar-base` still lists the M3 chains with `policy drop` on input
   (punard's table untouched); the `punar-net` JSON contains **no**
   `punar-base` chain names and vice versa.
4. **Policy compilation** — `punarctl network policy atlas --json`:
   `internet` allow, `corp_dev` allow, `corp_prod` deny; each rule names
   which input bound; a synthetic project whose manifest says `allow` and
   whose route policy says `deny` compiles to **deny** with
   `bound_by == "project_network_policy"` (the strictest-wins proof,
   §4.3); a zone in neither document compiles to `deny` with
   `bound_by == "residual"`.
5. **Managed launch + attach** — launch the mock agent with
   `PUNAR_AGENT_MOCK=1 PUNAR_MOCK_AGENT_NET=1` under
   `systemd-run --user --pipe --wait --collect` (the M7 cgroup-delegation
   lesson: started by the **user** manager, never migrated from
   `system.slice`); session id captured; within a bounded wait,
   `nft -j list table inet punar-net` names a chain for that session and
   the `socket cgroupv2` expression's path **equals** the path read from
   `/proc/<agent pid>/cgroup` and its `level` equals that path's component
   count (no hardcoded slice layout).
6. **Enforcement — allow** — the mock agent's allow probe to
   `127.0.0.9:9418` returns exit 0; the `internet` allow counter for that
   session is > 0.
7. **Enforcement — deny** — the deny probe to `127.0.0.7:9418` returns
   non-zero **within 2 s** (the `reject`-not-`drop` property, asserted as
   elapsed time, not as an errno); the `corp_prod` deny counter for that
   session increments by ≥ 1.
8. **The control probe — the assertion that makes group 7 mean
   anything** — the **identical** `bash /dev/tcp` connect to
   `127.0.0.7:9418`, run as the **same user** but **outside** the agent
   scope, **succeeds**. Without this, group 7 is equally consistent with
   "the port is shut". This also doubles as the `/dev/tcp` capability
   probe: if the control connect fails, the group reports FAIL rather
   than letting group 7 pass vacuously.
9. **Explanation (spec 73)** — `punarctl network explain atlas corp_prod`
   prints the six section-73 elements (what/why/who/which policy/can you
   change it/next step) and names `punar-net`; `punarctl privacy
   connections` shows a `DENIED` row naming `corp_prod` with an attempt
   count ≥ 1.
10. **Audit + Law 4** — the audit log has `network.deny` with
    `decision == "deny"`, `agent_session_id ==` the real `agt_` id,
    `project == "atlas"`, `zone == "corp_prod"`,
    `zone_kind == "production"`; and **`127.0.0.7` appears 0 times in
    `/var/log/punar/audit.jsonl`** (the destination-host prohibition,
    asserted as a byte-level grep).
11. **Observability** — while the allow probe's socket is open,
    `punarctl privacy connections --json` lists a process row whose
    `session.id` is the real `agt_` id, `governed == true`, with a
    connection to `127.0.0.9` in state `established`; `scanned_at` is a
    timestamp; a second invocation with no change **does not rewrite**
    `/run/punar-netd/connections.json` (mtime + `sha256sum` unchanged —
    the spec 6.4 assertion); no `punar-netd` systemd **timer** exists
    (`systemctl list-timers` names none).
12. **Relay** — `punarctl relay status --json` has `simulated == true`,
    `hops[0]` has **no** `destination` key, `hops[1]` has **no** `client`
    key, and `property_not_held` mentions a single operator; the text
    output contains `SIMULATED`; `punarctl relay set private_relay`
    persists and still prints `SIMULATED`; `enterprise_route` is **not
    offered** in personal mode (`relay set enterprise_route` refuses with
    a not-enrolled message).
13. **Unmanaged-first** — `punarctl privacy connections` shows `punard`
    with **0 connections** and the words *nothing to report home*; shows
    `punar-netd` with 0 and the structural reason; and the whole output
    contains **0** occurrences (case-insensitive) of `acme`, `smplify`,
    `enterprise route`, `compliance`.
14. **netd's own silence is structural** — `systemctl show punar-netd -p
    RestrictAddressFamilies` contains `AF_UNIX` and `AF_NETLINK` and
    **not** `AF_INET`; `IPAddressDeny=any` present; no socket in
    `/proc/net/tcp{,6}` maps to a pid in `punar-netd.service`'s cgroup.
15. **Ledger fill (M8 join)** — `punarctl agents access <id> --json`:
    `summary.resources.network_destinations` contains `127.0.0.9`;
    `not_yet_observed[]` **no longer** names `network_destinations`,
    `production_access` or `sensitive_resource_access`;
    `security_events[]` contains an entry with
    `event_type == "production_access"` whose `event_id` **matches
    verbatim** the `evt_` id of the `network.deny` audit line (the join
    key, compared across two files); `detail.entries[]` includes one with
    `evidence == "netd_aggregate"`.
16. **Ledger privacy regression** — across
    `/var/lib/punar/agents/ledger/*.json`, `index.json`,
    `/run/punar-agentd/ledger.json`, `/run/punar-netd/connections.json`:
    the string `9418` appears **0** times (no ports); no value in
    `resources.*` contains `:` or `/`; the keys `payload`, `sni`,
    `dns_query`, `url`, `uri`, `cmdline` appear **0** times.
17. **Container path** — `punar-env up atlas` →
    `.HostConfig.NetworkMode == "none"`; `punarctl network policy atlas
    --json` reports `container_network == "none"` with
    `reason == "allow_not_grantable"`; `punar-env status` renders the new
    M12 network wording (§6) and **not** the M6 string.
18. **Detach** — end the scope; within a bounded wait the session's
    chain, jump and counters are gone from `nft -j list table inet
    punar-net`; audit has `network.session_detach`; the ledger record
    retains the destination (detach flushes, it does not erase).
19. **Idempotence / self-heal** — `nft destroy table inet punar-net`;
    the next `punarctl privacy connections` (a read, which triggers a
    pass) reinstalls the table; `punar-base` is unaffected throughout
    (re-assert group 3's punar-base facts after the destroy).
20. **Negative probes** — `debug rpc network.bogus --socket netd` →
    `unknown_method`; `network.capture`, `network.inspect`,
    `network.export` → `unknown_method` (the boundary is probeable);
    `network.apply` as `punar` → refused with a section-73 message;
    `ledger.network` from a non-root peer → refused; malformed
    `zone-members.json` (staged by the check, then restored) → netd
    refuses to compile and **the previously installed table survives**
    (fail-safe, not fail-open).
21. **Panel** — `qs -p /usr/share/punar/shell ipc call privacypanel open`,
    settle, `grim /run/punar/punar-m12.png`; assert non-empty; assert
    `/run/punar-netd/connections.json` is `0640 root:punar` and names the
    session; assert the JSON's `dns_protection.state ==
    "not_configured"` (the chip M12 must not render green, §10.2).
    Screenshot failure is a noted `FAIL` line (the m2 precedent).
22. **Stale-assertion sweep** — assert the **new** strings exist in the
    surfaces §14 lists, and that the **old** ones do not: `punarctl
    privacy connections` exits **0** (it no longer refuses naming
    Milestone 12); `punar-env status` no longer contains
    `enforced M12`; `PUNAR_SERVICE_UNITS` in `/usr/lib/punar/idle-ram.sh`
    contains `punar-netd.service` (and `m11-check`'s "unchanged"
    assertion has been rewritten per §14.3, not merely satisfied).

**Exports** (swept by the existing tar glob): `m12-report.txt`,
`m12-nft-punar-net.json`, `m12-nft-punar-base.json`, `m12-policy.json`,
`m12-connections.json`, `m12-relay.json`, `m12-explain.txt`,
`m12-audit-deny.json`, `m12-access.json`, `m12-probe-results.txt`,
`punar-m12.png`.

**Host-side (CI, not in-VM):** `tools/validate-schemas.sh` gains the M12
zone fixtures under `fixtures/network/valid/` (already present for
`corp_dev`, `corp_prod`, `internet`, `privileged_db` and the Atlas route
policy — M12 adds the loopback **fixture** zone document and one invalid
document per new failure mode). A `punar-netd` unit test pins the
ruleset generator against a golden `.nft` text for a fixed session +
policy input, so the rule *order* (log before reject; zones before
loopback; residual last) is regression-tested where a VM cannot see it.

### 13.4 What genuinely cannot be tested offline — Phase 2, stated plainly

The CI VM is `-nic none`. The following are **not** tested by `m12-check`
and no claim in this document depends on them:

| Untestable offline | Why | Where it gets tested |
|---|---|---|
| Egress to any real destination | there is no route off the box | Phase 2, hardware/networked CI |
| Real hostname behavior, DNS, split-horizon names | no resolver, no queries | Phase 2 |
| Whether `reject` vs `drop` matters on a real path (ICMP filtering upstream) | no upstream | Phase 2 |
| Enterprise route, VPN interaction, roaming, multi-NIC | no NICs at all | Phase 2 |
| Real relay latency, throughput, failure modes | no relay exists | Phase 2 (spec 77) |
| IPv6 global addressing and its ledger fallback in the wild | link-local only | Phase 2 |
| netns + veth + masquerade isolation (§5.5) | needs an uplink to prove anything | Phase 2 |
| Container connectivity under an allow policy | no rootless-net helper in the image | Phase 2 |
| Behavior under connection flood / conntrack pressure | no traffic source | Phase 2 |

The loopback fixture proves **policy, attachment, enforcement,
attribution, observation and the ledger join**. It proves nothing about
the internet, and the report says so in an `info` line.

---

## 14. Stale assertions this milestone creates (spec 1.22)

M12 fulfills placeholders M6 and M8 shipped honestly. Those placeholders
are now **wrong**, and every one of them is asserted somewhere. Each must
be changed to assert the **invariant**, not the promise — leaving them is
how a green check starts certifying a lie.

### 14.1 `m6-check.sh`

| Line | Current assertion | Must become |
|---|---|---|
| 245–247 | `status network row` == `Network       isolated (M6) · declared zones enforced M12` | the M12 wording (§6): `none · deny enforced · allow declared (Phase 2)` |
| 265–270 | three rows `network <zone> <decision> declared · enforced M12` | `enforced (agent scope) · container: deny only` for the enforced paths; `declared` only where §6 says it stays declared |
| 290 | `.enforcement.network == "M12"` in the status JSON | `.enforcement.network == "enforced"` (or the object form the implementation picks) — a milestone name in an enforcement field is a promise, and the promise has come due |
| 190–192 | `.HostConfig.NetworkMode == "none"` | **keeps passing unchanged**, but its comment ("M6 honesty: no faked networking") must be rewritten to say the value is now *derived from policy* (§6) — same byte, different meaning, and the comment is what tells the next reader which |
| 22, 31–32 | header comments "enforced M12/M9/M7" | updated to the post-M12 truth |

### 14.2 `m8-check.sh`

| Line | Current assertion | Must become |
|---|---|---|
| 329–333 | `network_destinations == []` **and** `not_yet_observed` names it with `milestone == "M12"` | `network_destinations` is **non-empty** for a session that reached a destination, and `not_yet_observed` **does not** name it |
| ~345 (L4 group) | the five producerless Level-4 categories include `production_access` and `sensitive_resource_access` | both **removed** from the expected set; the remaining set shrinks accordingly |
| 353 | `[.detail.entries[].evidence]` drawn only from `{cgroup_scope, audit_event, workspace_bind, adapter_metadata}` | the set gains **`netd_aggregate`** (§8.2) |
| 508–512 | `punarctl privacy connections` **refuses** and names "milestone 12" (exit ≠ 0) | the verb **succeeds** (exit 0) and renders the connection view; the refusal assertion is deleted, not inverted |
| 788 | `info` line: "network destinations … absent because no mediation point observes them yet — punar-netd is M12" | rewritten: netd now observes them; the remaining absence (`mcp_servers`) keeps its label |
| 19, 31–33 | header comments naming M12 as the network milestone | updated |

### 14.3 `m11-check.sh`

`milestone-11.md` §12 assertion 41 asserts that `PUNAR_SERVICE_UNITS` in
`/usr/lib/punar/idle-ram.sh` is **unchanged** (M11 adds no daemon, and
pins that as a regression test). M12 **does** add a daemon, so that
assertion goes stale the moment `punar-netd.service` is appended. It must
be rewritten from "unchanged" to the **invariant M11 actually cares
about**: that the list contains no browser or web-app unit and that M11's
own work added nothing to it — e.g. assert the list does not match
`chromium|webapp` rather than asserting a literal string. Leaving it as a
literal comparison would make an M12 success turn m11-check red for a
reason that has nothing to do with M11.

### 14.4 Documents

- **`milestone-6.md` §5.3 / §7** — the `enforced M12` labels and the
  status sample. Add an "As built by M12" note in place rather than
  rewriting history (the M7/M8 precedent).
- **`milestone-8.md` §3.1, §13** — the `network_destinations` row, the
  "no ledger code changes" sentence (**corrected in §8.1 above**), and
  the deferral of the graphical privacy panel to M13 (**superseded by
  decision 21**).
- **`milestone-9.md` §9.3** — the re-milestoned
  `sensitive_resource_access → M12` row is now paid.
- **`docs/api/ipc.md`** — §12/§13 additions (§11.2) at implementation
  time.
- **`IMPLEMENTATION_STATUS.md`, `PERFORMANCE_BUDGETS.md`,
  `ARCHITECTURE_DECISIONS.md`** — the third/fourth daemon, the RSS row,
  and an ADR for the table-partition rule (decision 2) and the
  cgroup-vs-netns enforcement choice (decision 3 / §5.5).
- **`docs/development/keyboard-grammar.md`** — `PUNAR+P` (verified free
  against the M9/M10/M11 grammars as of this writing).

**Rule for the implementation workflow:** a stale assertion is not
"updated to still pass". It is rewritten to assert the *new invariant*.
If M12's enforcement regresses, m6-check and m8-check must go **red** —
that is the whole point of changing them.

---

## 15. Scope-out table

| Deferred | Milestone / phase | Why, in one line |
|---|---|---|
| Real private relay (ingress + egress hops) | **Phase 2** (spec 77 names it) | Requires two independently operated services in different administrative domains; nothing on a device can simulate that property |
| Any relay carrying traffic at all | Phase 2 | A userspace proxy on the data path is the resident-agent architecture spec 45 rejects (§9.1) |
| DNS protection / first-party resolver | Phase 2 | The only honest route to real hostnames; needs its own privacy design (aggregate-only retention, purgeable) — §7.5 |
| Escape-proof per-session network namespace + veth | Phase 2 / M13+ | Needs address allocation, `ip_forward`, masquerade, a forward-chain hole, in-ns DNS — and an uplink to test (§5.5) |
| Container connectivity under an `allow` policy | Phase 2 | No `passt`/`slirp4netns` in the image; M12 adds no package it cannot test (§6) |
| Device-wide egress filtering for unmanaged processes | Not planned for MVP | M12 is a per-principal policy, not a device firewall; a device default-deny needs a per-app UX that does not exist (§5.6) |
| Enterprise routes with real routing | Phase 2 | Needs a real org, a real network, and enrollment beyond the M5 mock |
| Org-supplied network policy via desired state | M13+ | Unmanaged-first; and an org route is untestable on a netless VM (§4.4) |
| `approval_required` executing a real M9 approval | Milestone after M9's ipc.md stabilizes | M9 is landing concurrently; M12 ships deny-until-approved + the explanation and proposes the join (§4.5, §11.3) |
| Inline (in-process) restriction explanations | M13 | The kernel returns an errno; Punar cannot inject prose into a third-party binary's stderr (§10.5) |
| Shell notification on denial | M13 | Notification surface is M13's; M12 ships panel + CLI + audit |
| SNI inspection | **Never** | Content inspection of the connection payload (spec 37); also defeated by ECH (§7.5) |
| DNS query logging | **Never** as a log | It is a browsing history on a device that refuses to log file reads (§7.5) |
| eBPF-based attribution | Phase 2 "where justified" (spec 77) | M12 does not need it, so it is not justified (§7.1) |
| Per-request / per-URL visibility | Never | One connection is one row; a URL cannot appear in the ledger by schema (§8.2) |
| `network-zone.json` `members` block | Later milestone | Freeze a membership shape only after the enforcement model has run (§4.1, §11.4) |
| MCP servers in the ledger | M11+ | No tool/MCP gateway mediates anything (M9 §9.3) |

---

## 16. Verification status (spec 1.22)

**Implementation and the clean ARM64 runtime proof are complete locally. This
milestone is not marked verified until a fresh x86_64 image and canonical
dual-architecture CI also emit `PUNAR_M12_OK`.**

- The `punar-netd` binary, systemd hardening, typed IPC, nft transaction
  generator, bounded observation, deny-log parser, agent-ledger bridge,
  relay model, CLI verbs, Privacy panel, and `PUNAR+P` binding are present.
- Host verification is green: Rust formatting, full-workspace clippy with
  warnings denied, full-workspace tests from a clean target directory,
  schema/fixture validation, pinned shellcheck, and QML lint.
- The exact 2026-08-29 ARM64 image, SHA-256
  `62081fb3a5d7fbf58115c35d5b04a5eb6957caf5d101ebe0089eba85612c14c9`,
  emitted `PUNAR_M12_OK` with 66 assertions. The three-way loopback probe,
  kernel socket-to-cgroup attribution across the user boundary, counters,
  audit/ledger privacy join, malformed-data fail-safe, missing-table self-heal,
  service confinement (including no `CAP_SYS_PTRACE`), closed method table and
  panel screenshot all passed.
- `m12-check.sh` hard-gates the real three-way loopback probe,
  counters, audit/ledger privacy join, malformed-data fail-safe, missing-table
  self-heal, service confinement, closed method table, and panel screenshot.
- **Not yet claimed:** x86_64 parity, canonical CI, real internet/VPN/relay
  behavior, physical NICs, Raspberry Pi firmware/peripherals, or an
  escape-proof per-session network namespace. The loopback proof establishes
  policy, attachment, enforcement, attribution, observation and the ledger
  join only; any failed assertion in the remaining lanes stays red rather than
  becoming a softened claim.
