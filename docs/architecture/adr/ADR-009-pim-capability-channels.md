# ADR-009 — Unnamed capability channels for first-party PIM applications

- Status: **Accepted — transfer and root-peer admission implemented; privileged launch and runtime proof remain open**
- Date: 2026-09-22
- Spec references: `docs/product/SPEC_v0.2.md` §§10–11, 29, 44, 61;
  `docs/api/pim-ipc.md`; ADR-008

## Context

Mail, Calendar, Reminders and their account settings need a narrow channel to
the profile's `punar-pimd` instance. Linux process uid is not an application
identity: an unrelated editor, downloaded binary or developer tool normally
runs as the same person. A `0600` socket plus `SO_PEERCRED` would therefore let
every same-uid process ask for mail bodies, mutate events or remove accounts.

The local store is intended to run under a service identity distinct from the
human uid. Letting applications read its files would erase that boundary. A
solution must also work on ARM64 and Raspberry Pi without requiring TPM
hardware, remain idle when no PIM app is open, and avoid a large always-running
desktop portal.

Linux already supplies the needed primitives. `socketpair()` creates an
unnamed connected pair; `SCM_RIGHTS` transfers an open descriptor over another
Unix socket. There is no pathname for an ambient process to discover or open.
The Linux manual also makes the residual theft boundary explicit:
`pidfd_getfd()` is governed by a ptrace access check, and a non-dumpable process
cannot be attached with `PTRACE_ATTACH`. Sources:
[socketpair(2)](https://man7.org/linux/man-pages/man2/socketpair.2.html),
[unix(7)](https://man7.org/linux/man-pages/man7/unix.7.html),
[pidfd_getfd(2)](https://www.kernel.org/pub/linux/docs/man-pages/book/man-pages-6.15.pdf),
[PR_SET_DUMPABLE(2const)](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html).

## Options considered

### Filesystem or abstract Unix socket readable by the human uid

Rejected. Filesystem permissions distinguish users, not applications. Abstract
sockets remove pathname permissions entirely. `SO_PEERCRED` proves the same
insufficient uid.

### Per-launch bearer token over a user-readable socket

Rejected. A random token prevents guessing but creates a secret that must
cross argv, environment, a file, D-Bus or another same-uid channel. It also
does not prevent descriptor/token theft from a dumpable sibling process.

### Cgroup name or executable path inspection

Rejected as the authority. A user controls their user service manager and can
execute root-owned binaries with different inputs. Process observation may be
useful audit evidence but cannot mint access.

### Mandatory-access-control label only

Deferred as defense in depth. SELinux/AppArmor peer labels can provide strong
process domains, but the current image has no production-wide MAC policy. PIM
must not silently depend on an LSM that is disabled or on a generic QML runtime
whose path says nothing about which root-owned document it loaded.

### Privileged launch with an unnamed inherited channel

Chosen. A root-side typed broker creates a `SOCK_STREAM` pair, launches one of
four fixed first-party clients with one endpoint inherited, and transfers the
other endpoint to the already profile-bound PIM service over a private
root/service-only `SOCK_SEQPACKET` control channel. The human caller may ask to
open an app but never receives the endpoint.

## Decision

There is **no application-connectable PIM socket**. Each application session
gets one preconnected unnamed Unix stream. Possession of that descriptor is the
unforgeable launch capability.

The broker/service transfer is one bounded sequenced-packet record containing:

- exactly one `SCM_RIGHTS` descriptor;
- contract version 1;
- a non-secret `grant_<id>` for audit correlation;
- the service-bound profile uid; and
- one closed client kind: `mail`, `calendar`, `reminders` or `settings`.

The service control listener is accessible only to the privileged broker and
the separate service identity. It verifies the control peer before receiving a
grant. The transferred descriptor is close-on-exec by default. The broker
drops its copy after a successful transfer and never logs the descriptor
number as authority.

Client kind is authorization, not decoration. Before method-specific params
are parsed, `punar-pimd` applies a closed method partition:

- Mail: read-only account metadata, mail reads/mutations, contact completion
  and changes;
- Calendar: read-only account metadata, calendar/event reads/mutations,
  contact completion and changes;
- Reminders: read-only account metadata, reminder/list reads/mutations and
  changes;
- Settings: account lifecycle, sync and status.

All three applications need the same bounded public account records to name
their rail, distinguish an empty synced account from no account, and show
authentication/connectivity recovery. Those records contain no provider
endpoint or credential. Only Settings can begin, cancel or remove an account
or trigger synchronization.

No client kind admits generic execution, arbitrary storage, raw provider
requests, credential retrieval or another app's mutations.

The fixed launch must enter the reviewed application sandbox, preserve only
the one intentional descriptor, set the app/bridge process non-dumpable before
untrusted content is handled, disable core dumps, and expose only root-owned
application code/configuration. Punar may add an LSM label later, but an absent
label never becomes an allow path.

The implementation in `crates/punar-pimd/src/channel.rs` covers descriptor
creation, bounded transfer, kernel-attested root control-peer admission,
strict grant parsing, profile binding and the least-privilege method table
using safe `rustix` APIs. It rejects a non-root control peer before reading its
grant. It is a library proof, not yet a shipping launcher or service.
`crates/punar-pimd/src/process_security.rs` now groups and verifies the
irreversible process-side controls: `RLIMIT_CORE=0`, non-dumpable state and
`no_new_privs`. The fixed launcher/service still must invoke this before
authority or untrusted content and pass the hostile runtime theft gate.

## Consequences

- Same-uid applications have no address to connect to and no token to steal
  from a file, argv or environment.
- User intent to open an app is separate from possession of its PIM channel;
  the privileged broker delivers the endpoint straight to the fixed child.
- Four smaller method sets reduce the result of a compromised renderer or
  malformed-content bug.
- Every open application consumes one socket pair and one service connection;
  there is no idle polling or resident portal.
- The broker becomes a security boundary. Its launch table must be fixed,
  root-owned, shell-free and tested against argv/environment/descriptor
  injection.
- Non-dumpable state and sandbox isolation are required because a same-uid
  attacker must not duplicate the inherited descriptor through `/proc`,
  ptrace or `pidfd_getfd`.

## Required runtime proof before production staging

1. The production image has no filesystem, abstract or TCP PIM application
   listener.
2. The privileged broker can launch only the four fixed root-owned clients and
   passes exactly one intentional descriptor.
3. A valid app can use its allowed methods, and every cross-client method is
   denied and audited before params are acted on.
4. An unconfined same-uid process cannot connect, inherit, inspect or duplicate
   the channel through `/proc`, ptrace or `pidfd_getfd`.
5. Another uid/profile and a forged/extended/truncated/multi-descriptor grant
   fail closed without leaking whether a resource exists.
6. Closing or crashing the app closes its endpoint, cancels bounded in-flight
   work and leaves durable local/offline state consistent.
7. The service and broker are absent at stabilized idle and meet the active
   memory/latency budgets on x86_64 and ARM64.

## Revisit triggers

- The desktop adopts an enforcing, measured MAC policy that can add peer-label
  verification without becoming the only allow mechanism.
- The app moves from a QML bridge to a dedicated compiled process; retain the
  inherited-channel boundary and re-measure the sandbox.
- Kernel or systemd changes provide a smaller fully typed fixed-launch route;
  the caller still must never receive the application endpoint.
