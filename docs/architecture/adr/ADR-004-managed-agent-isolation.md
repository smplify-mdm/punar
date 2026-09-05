# ADR-004 — Managed host-agent filesystem and process isolation

- Status: **Accepted — bounded first slice; image/runtime proof remains open**
- Date: 2026-09-04
- Spec references: `docs/product/SPEC_v0.2.md` §§17, 19–22, 26–29, 36;
  `docs/development/milestone-7.md` §5

## Context

Punar launches a declared AI agent as a host process so it can use the project's
native tools. The existing transient `punar-agent-<session>.scope` proves
cgroup attribution and supplies a lifecycle anchor, but a scope alone does not
restrict filesystem or process visibility. An agent could otherwise read the
user's SSH and cloud credentials, other projects, shell startup files and user
session sockets, or write persistence into the real home directory.

This first boundary must keep cgroup attribution for the agent registry and
ADR-007 network policy, avoid a resident privileged launcher, work on both
supported architectures, and fail closed if an isolation primitive or exact
network proof is missing. All desktop image profiles include `/usr/bin/bwrap`
through the `bubblewrap` package. That dependency is a compile-time image
contract as well as a runtime preflight.

## Options considered

### Option A — Keep the systemd scope without a filesystem boundary

This preserves attribution and lifecycle, but does not enforce any filesystem
grade. Displaying the manifest as authority would therefore remain a claim,
not a kernel boundary. Rejected.

### Option B — A Podman container for the agent itself

The project environment already uses rootless Podman, but moving the agent
into that container changes the product contract: installed host tools and the
agent executable are no longer naturally present, and its cgroup/lifecycle
identity becomes a container-runtime concern. This may become a separate
execution mode; it is not the least disruptive host-agent boundary.

### Option C — A transient systemd service with unit sandbox directives

Systemd can express much of the policy, but the current user-scope launch is
the proven attribution/lifecycle mechanism and a user manager cannot apply all
system-service sandbox controls uniformly. Creating per-session unit files or
a privileged launcher would add another control surface. Rejected for this
slice.

### Option D — Bubblewrap inside the existing systemd scope

Bubblewrap constructs an empty mount namespace from a fixed argv, adds only
the required immutable OS trees and exact project mount, and unshares PID, IPC
and UTS namespaces without unsharing the cgroup namespace. It needs no daemon
and no shell. Chosen.

## Decision

Launch every managed host agent behind a fixed `/usr/bin/punar-env
__agent-gate` inside its transient systemd scope. The outer launcher invokes
only canonical `/usr/bin/systemd-run`; the gate ultimately invokes only
canonical `/usr/bin/bwrap`; teardown invokes only canonical
`/usr/bin/systemctl`. Each file and every selecting ancestor must be root-owned
and not group/world-writable. There is no PATH lookup or unsandboxed fallback,
and the agent path is never probed by executing it before confinement.

The gate is the pre-exec barrier:

1. prove its own PID is in the exact `punar-agent-<session>.scope` cgroup;
2. register that PID with the fixed punar-agentd socket and require the daemon
   to return `managed` (an honest downgrade is a launch failure here);
3. call the internal, typed `network.session_ready {session_id}` method on the
   fixed punar-netd socket;
4. require punar-netd to re-read the authoritative agentd session, atomically
   reconcile policy, read back this exact cgroup selector/jump/target from the
   kernel nftables table, and re-check the socket peer's cgroup; and
5. write a private nonce-bound proof and wait for the outer launcher's matching
   release file before `exec` of Bubblewrap.

Counts, service status, a pending state and timeout are not success states. Any
error ends a possible registration and stops/reaps the exact scope. The gate's
specification, proof and release files are outside every sandbox mount.

The namespace contains:

- `/usr` and `/etc` as read-only OS trees, a private `/proc` and `/dev`, and a
  tmpfs `/tmp`;
- the declared project only at `/workspace`, read-write, read-only, or replaced
  by an empty read-only directory according to `filesystem.project`; its
  canonical directory must be strictly below HOME, and it plus every ancestor
  to HOME must belong to the invoking uid and not be group/world-writable;
- a fresh per-session home and XDG runtime tree below the user's private
  `/run/user/<uid>`, mounted at the account's normal home and runtime paths;
- only resolver files under an otherwise empty `/run`; agentd, netd, punard and
  the secrets broker sockets are deliberately absent, so adapter code cannot
  end itself, invoke readiness, or reach a broad product control/broker API;
- for a user-installed agent, only its canonical executable as a read-only
  file, not the directory or real home tree containing it.

The environment is cleared and rebuilt from a small allowlist. In particular,
the real home, `~/.ssh`, `~/.aws`, shell startup files, other projects, the
user D-Bus socket and user-systemd sockets are not mounted or forwarded.
Adapter arguments remain individual argv items after Bubblewrap's `--`; no
shell interprets them. Third-party version commands are no longer executed
before the boundary and real-agent version is reported as `unknown` until
trusted package metadata can supply it.

This decision deliberately narrows `filesystem.home`: regardless of a
manifest's declared home grade, a managed host agent receives a fresh private
home and never the user's real home. The row is explicitly rendered as
`narrowed · private session home`; other non-project rows are
`declared · not mounted`. Neither is silently presented as fulfilled.

## Consequences

- The gate `exec`s Bubblewrap without changing cgroup. Because the PID
  namespace is unshared, the registered lifecycle PID becomes Bubblewrap's
  outer monitor and the adapter runs as its child inside the new namespace;
  the registry row's `exe`/`comm` therefore show `bwrap`, while attribution,
  ADR-007 matching, stop behavior and lifecycle stay attached to the same
  scope cgroup (the monitor exits with the adapter's status).
- The project directory must be exactly `~/<project.name>`: punar-netd
  locates the session's manifest and policy there, and any other layout would
  be enforced as `deny_all` behind a daemon-side warning while the launch
  block claimed an exact rule. The launcher refuses the mismatch before a
  scope exists.
- The agent cannot escape its mount namespace through the exposed filesystem.
  A project symlink to another host path resolves against the sparse namespace,
  where that destination is absent.
- **Real Claude compatibility is not claimed.** Claude's complete package
  closure and secure persistent OAuth/authentication state are still open.
  `claude-code` real launch currently fails explicitly before a scope is
  created; the labelled image-test mock remains available. Authentication or
  plugins that assume persistent real-home files need a future audited
  package/state mount or credential broker. Broadly mounting a package manager,
  home subtree or credential directory is not a compatibility fallback.
- Session home/runtime state is removed on normal exit and best-effort on
  unwind. It lives under the logout-scoped runtime directory, not persistent
  storage.
- This bounded decision is **not the network enforcement design**. The agent
  shares the host network namespace so traffic remains attributable to the
  systemd cgroup; ADR-007 owns rules, zones and nftables. ADR-004 owns only the
  condition that ADR-007 must return an exact kernel proof before adapter exec.
- This is **not per-agent UID or LSM confinement and not a hostile same-UID
  host-peer boundary**. Another process
  already running as the user can inspect or alter agent-owned state and may be
  able to trace same-UID processes under the host's ptrace policy. The agent's
  namespace does not expose the host paths needed to reverse that relationship,
  but future per-agent UID plus SELinux/AppArmor/Landlock work is required for
  mutual isolation and stronger state integrity.
- Unit tests pin mount grades, control-socket and sensitive-path absence,
  environment allowlisting, executable exposure, tool provenance, project
  hierarchy, closed gate argv and exact network responses. A Linux-only hostile
  child integration test runs when Bubblewrap is usable. M7/M12 image gates are
  the eventual clean-VM proof; a host/container that disables unprivileged user
  namespaces cannot supply that runtime evidence, and a skipped hostile child
  is not counted as proof.
- This slice still exposes the whole host `/etc` read-only. That is materially
  narrower than writable host access, but it is broader than an eventual
  least-disclosure filesystem view. A follow-up security review must replace
  it with the smallest audited compatibility allowlist; this ADR does not
  treat read-only as equivalent to confidential.
- The existing M8 hostile-call fixture expected an agent to invoke punard
  directly. That route is now intentionally closed and the mock reports the
  missing evidence instead of treating a socket-connect failure as a policy
  denial. Restoring that image proof requires a narrow session-aware tool
  gateway; remounting the broad punard socket is not an acceptable fix.

## Revisit triggers

- A supported agent requires a multi-file runtime payload that cannot be
  represented as an audited, declared read-only package mount.
- Managed agents must retain durable state between sessions.
- The threat model expands to malicious or compromised same-UID host peers.
- ADR-007 adopts network namespaces or the cgroup attribution contract changes.
- A supported kernel or image can no longer provide unprivileged Bubblewrap
  with the required mount, PID, IPC and UTS namespace operations.
