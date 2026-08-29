# ADR-007 — Per-principal network enforcement and nftables table ownership

- Status: **Accepted** — implementation complete; clean x86_64 and ARM64
  runtime evidence remains an M12 verification gate
- Date: 2026-08-29
- Spec references: `docs/product/SPEC_v0.2.md` §§11.7, 21, 34, 36–39,
  45, 73, 77, 80; `docs/development/milestone-12.md`

## Context

Punar needs enforceable project network policy without turning its local
management daemon into a general traffic proxy, weakening unmanaged-device
privacy, or allowing two services to mutate the same firewall state. A managed
AI session already has a kernel-attested systemd scope and cgroup path. The
desktop also already has a device firewall owned by `punard` in the
`inet punar-base` nftables table.

The MVP must work offline in CI, use native kernel primitives, fail loudly when
unsupported, attribute traffic without payload inspection, and preserve the
device's behavior outside a Punar-launched session. It must also state the
known escape boundary: a process that can leave its cgroup before connecting
is not contained by a cgroup-only rule.

## Options considered

### Option A — Add session rules to `punard`'s `punar-base` table

This reuses one daemon but creates two incompatible lifecycles inside it:
device-wide desired-state reconciliation and high-churn session attachment.
It also makes a regression in user-authored project-policy parsing capable of
damaging the enrollment/firewall control plane.

### Option B — Put every managed session in a network namespace

This is the stronger containment boundary: the session cannot escape merely by
moving a process to another cgroup. It also requires address allocation,
forwarding, an uplink, DNS behavior, container integration and substantially
more physical-network testing than the offline M12 gate can support. Shipping
it without that evidence would trade a known limitation for a larger unproven
network stack.

### Option C — A separate daemon and nftables table keyed by cgroup

`punar-netd` owns only `inet punar-net`. It compiles the strictest effective
project policy, obtains each live session's actual cgroup path through trusted
agent state, and installs output-chain rules using nftables `socket cgroupv2`
matching. `punard` remains the sole owner of `inet punar-base`. Full table
regeneration is one atomic `nft -f` transaction. Unsupported kernels produce
an explicit unavailable state rather than a declared-as-enforced lie.

### Option D — A userspace proxy or resident VPN for all traffic

This adds a network-capable privileged intermediary to every connection,
creates a new availability bottleneck and conflicts with the requirement to
prefer native primitives. It would not make M12's simulated private-relay
model real; both hops would still share one device and operator.

## Decision

Use Option C for the MVP. `punard` exclusively owns `inet punar-base`, while
`punar-netd` exclusively owns `inet punar-net` and enforces only traffic from
Punar-managed agent-session cgroups. The identical traffic outside those
cgroups is deliberately unaffected.

Network namespaces are the Phase-2 containment upgrade, not an unspoken
property of the MVP. A cgroup match is real enforcement within its stated
boundary; it is not described as escape-proof.

## Consequences

- Device policy and session policy have separate failure and ownership
  domains. Neither daemon may create, flush or destroy the other's table.
- `punar-netd` needs `CAP_NET_ADMIN`, `AF_NETLINK` and read access required for
  policy inputs, but it is denied `AF_INET`/`AF_INET6` and all IP addresses.
  Live managed-socket attribution joins Linux `INET_DIAG_CGROUP_ID` to the
  known cgroup-v2 inode; it does not require `CAP_SYS_PTRACE`, process tracing,
  or cross-user `/proc/<pid>/fd` access. The daemon cannot resolve hostnames or
  become a network client.
- A deny uses a separate rate-limited log rule followed by an unconditional
  reject rule, so log throttling can never make enforcement fail open.
- Observation is aggregate and on demand: counters, denied destinations,
  `/proc/net` socket rows and kernel socket-cgroup metadata. No payload, URL,
  SNI or DNS-query history is read.
- Unmanaged processes and ordinary desktop apps retain the device default.
  Punar therefore does not claim this is a device-wide egress firewall.
- A process with enough authority to escape its managed cgroup can escape this
  policy. That limitation remains user-visible until a network-namespace
  implementation is built and proven.
- Acceptance of this architecture does not equal release verification. M12
  remains unverified until clean x86_64 and ARM64 images pass the scoped
  allow/deny/out-of-scope control, audit/ledger, privacy and self-heal gates.

## Revisit triggers

- Managed agents need an escape-proof boundary or can legitimately create
  child scopes outside the session cgroup.
- Org policy expands from per-session controls to device-wide application
  egress policy.
- The target kernel removes or materially changes `socket cgroupv2` matching.
- Namespace networking can be tested across Ethernet, Wi-Fi, VPN, suspend,
  containers, IPv4/IPv6 and supported physical ARM/x86 hardware.
- The fourth resident daemon breaks the measured service RSS or idle CPU/write
  budgets.
