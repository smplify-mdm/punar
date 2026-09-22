# PIM local store — durable core before service exposure

Status: **implemented and tested as a library; not installed in an image.**

`crates/punar-pimd` is the first executable-code slice behind Punar Mail,
Calendar and Reminders. It deliberately solves local data durability before it
opens a process or network boundary. The accepted external contract remains
[`docs/api/pim-ipc.md`](../api/pim-ipc.md); credential custody remains
[`ADR-008`](../architecture/adr/ADR-008-pim-account-credentials.md).

## What exists

- one state root bound to one `profile_id` and Linux uid;
- one blank local **Personal** calendar and one blank local **Reminders** list;
- zero accounts, messages, events, reminders or activity fixtures;
- provider-neutral Calendar and Reminders records matching
  `schemas/pim/records.json`;
- create, update, complete and delete operations with optimistic revision
  checks;
- local-only, pending and durable-offline mutation posture;
- an ordered bounded change log including deletion tombstones;
- exact 0600 state files in an owned, exact 0700 service directory;
- descriptor-relative state reads that do not follow symbolic links and reject
  hard-linked aliases, foreign ownership and inputs above a 64 MiB pre-parse
  cap;
- same-directory exclusive temporary writes, file `fsync`, atomic rename and
  parent-directory `fsync` before a mutation reports success;
- fail-closed handling for corrupt, future-version, cross-profile,
  over-permissive and structurally inconsistent state;
- a one-way v0-to-v1 migration with a durable, non-overwritten backup.

`crates/punar-pimd/src/channel.rs` additionally proves the accepted ADR-009
transport primitive: an unnamed application/service stream endpoint is moved
over a bounded root/service-only sequenced-packet control channel with
`SCM_RIGHTS`. The receiver requires one descriptor, one strict grant header,
the bound profile uid and the client's least-privilege method partition. It
also checks the control socket's kernel-attested peer uid is root before it
reads the grant; a service cannot accidentally treat an accessible control
socket as sufficient authority.

`crates/punar-pimd/src/protocol.rs` implements the next boundary without
opening a service: 8 MiB request and 16 MiB response caps, newline framing,
strict v1 envelopes, the closed method enum, authorization before typed params,
safe error correlation and exact result/error responses. Unsafe ids and method
text are never reflected. A disallowed client receives `denied` even when the
method-specific params are malformed, proving the service will not parse an
unauthorized operation first.

`crates/punar-pimd/src/process_security.rs` provides one irreversible,
postcondition-checked process lockdown operation: hard and soft core limits are
zero, the process is non-dumpable and `no_new_privs` is set. The future fixed
launcher and service must call it before handing over a capability or loading
account data; the library alone does not prove that runtime ordering.

The store contains no password, OAuth code/token, provider secret or encryption
key field. QML is not linked to it. It starts no resident process and performs
no periodic work.

## Why the blank containers are not demo data

An empty event/task array without a writable calendar/list would be a dead end:
the first real item would have nowhere to live. The two local containers are
operating-system structure, analogous to a new account's empty home directory.
They carry no invented person, date, content, sync success or account. Their
random ids are created once and survive restarts.

## Crash and conflict semantics

Mutations are applied to a cloned candidate state. The candidate is validated
and durably replaced on disk before it becomes the in-memory state or is
returned to the caller. A failed write leaves both the old file and the old
in-memory state authoritative.

Every update and delete supplies the record revision it observed. A stale
revision returns a conflict and performs no write. Offline provider-bound work
is represented in the persisted record before success returns; a future sync
adapter can resume it after a crash without relying on an in-memory queue.

The change sequence in this library is internal and is never exposed directly.
`crates/punar-pimd/src/cursor.rs` now wraps a sequence/position with an
HMAC-SHA-256 cursor bound to the profile, typed method and hashed canonical
filter/sort set. Tampering and cross-profile/method/filter/key reuse fail
closed. The random profile key is persisted with create-new durability, exact
private ownership/modes and fail-closed corruption, alias and profile checks;
restart preserves existing cursors. The future service still must wire this
state into its dispatcher and map a cursor older than retained history to
`cursor_expired`.

`crates/punar-pimd/src/pager.rs` retains the exact serialized values selected
for a multi-page list, so a mutation between pages cannot produce a mixed
snapshot. It is intentionally volatile and bounded: 16 active snapshots,
8 MiB encoded per snapshot, 32 MiB total and five minutes since last use.
Missing state fails as `cursor_expired`; it never falls through to current
store contents. Single-page queries allocate no cache entry.

`crates/punar-pimd/src/dispatcher.rs` now provides the first store-backed
method slice: service status, honest empty account state, structural Calendar
and Reminder lists, durable local event/reminder mutations and the bounded
change stream. It checks the grant uid before method params, uses the strict
store validators, returns typed optimistic conflicts and signs a mutation's
change cursor only after the durable write. It intentionally leaves provider,
Mail/contact and filtered event/reminder methods unstaged.

## Tests currently required

The crate's unit suite proves:

1. a first open has only blank structural containers and no credential/demo
   keys;
2. Calendar events and reminders survive process restart;
3. stale revisions cannot overwrite newer data or rewrite the file;
4. offline queue posture survives restart;
5. deletion emits and preserves a tombstone;
6. corrupt state fails closed and is not replaced;
7. cross-profile, foreign-owned and non-exact-mode files are refused;
8. v0 migration creates an exact durable backup and is idempotent; and
9. future versions fail closed and remain untouched;
10. one unnamed endpoint transfers and carries application data;
11. cross-profile, extended, descriptor-free and extra-descriptor grants fail
    closed; and
12. Mail, Calendar, Reminders and Settings cannot invoke one another's
    mutation sets or generic execution/secret methods;
13. oversized and unterminated frames fail before dispatch, and responses are
    newline-delimited and bounded;
14. unsafe correlation fields are not reflected, while a safe unknown method
    receives a schema-valid `unknown_method` response; and
15. typed parameters reject extensions only after the app/method partition
    admits the call;
16. cursor payload/signature tampering, cross-profile/method/filter/key replay,
    extensions and constant keys fail closed without exposing raw bindings;
17. the private cursor key survives restart and keeps prior cursors valid; and
18. cross-profile, corrupt, over-permissive, hard-linked and symbolic-link key
    state is rejected without replacement or following the link;
19. unsafe correlation closes without reflection while safe denial and typed
    method errors retain only their validated request correlation; and
20. a partial frame hits an absolute deadline rather than holding the channel
    open indefinitely;
21. later pages retain the original values after the source mutates;
22. a page cursor cannot cross a method or canonical filter binding; and
23. expiry and bounded eviction return cursor expiry instead of live data;
24. service status and structural lists contain no demo/account records;
25. a local calendar mutation is durable and appears in the change stream;
26. stale revisions return a typed conflict without rewriting state; and
27. a mismatched grant uid is denied before malformed params are parsed; and
28. malformed record ids return `invalid_params` without resource disclosure;
29. hard-linked and symbolic-link state paths fail closed without touching the
    target; and
30. oversized state is rejected before an unbounded allocation or JSON parse;
    and
31. a non-root control peer is denied before its grant is read; and
32. process lockdown is idempotent and verifies zero core limits,
    non-dumpable state and `no_new_privs`.

Both x86_64 and ARM64 workspace jobs compile and test this crate automatically
because it is a Cargo workspace member.

## Explicitly still blocked

This work does **not** close Build Queue stage 3. Before a production image may
install or activate `punar-pimd`, it still needs:

- the privileged half of ADR-009: fixed app launch with direct descriptor
  inheritance, non-dumpable state, sandboxing and hostile same-UID theft tests;
- the remaining store-backed method dispatcher: filtered event/reminder reads,
  event responses, account/provider, Mail and contacts methods;
- service-private credential wrapping on verified encrypted storage;
- power-loss/fault-injection tests in addition to restart tests;
- per-profile systemd socket/service units with zero idle residency proof;
- schema-parity, fuzz and hostile-content tests; and
- a real application binding with empty, offline, conflict and error states.

No desktop entry, MIME handler or onboarding suggestion is enabled by this
library slice.
