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
- 0600 state files in a 0700 service directory;
- same-directory exclusive temporary writes, file `fsync`, atomic rename and
  parent-directory `fsync` before a mutation reports success;
- fail-closed handling for corrupt, future-version, cross-profile,
  over-permissive and structurally inconsistent state;
- a one-way v0-to-v1 migration with a durable, non-overwritten backup.

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

The change sequence in this library is internal. It must not be exposed as the
IPC cursor. The service layer must integrity-protect it and bind it to the
profile, method, filters and snapshot as `pim-ipc.md` requires.

## Tests currently required

The crate's unit suite proves:

1. a first open has only blank structural containers and no credential/demo
   keys;
2. Calendar events and reminders survive process restart;
3. stale revisions cannot overwrite newer data or rewrite the file;
4. offline queue posture survives restart;
5. deletion emits and preserves a tombstone;
6. corrupt state fails closed and is not replaced;
7. cross-profile and over-permissive files are refused;
8. v0 migration creates an exact durable backup and is idempotent; and
9. future versions fail closed and remain untouched.

Both x86_64 and ARM64 workspace jobs compile and test this crate automatically
because it is a Cargo workspace member.

## Explicitly still blocked

This work does **not** close Build Queue stage 3. Before a production image may
install or activate `punar-pimd`, it still needs:

- a hostile same-UID application admission mechanism stronger than
  `SO_PEERCRED` alone;
- bounded IPC framing, deadlines, signed cursors and the full closed method
  dispatcher;
- service-private credential wrapping on verified encrypted storage;
- power-loss/fault-injection tests in addition to restart tests;
- per-profile systemd socket/service units with zero idle residency proof;
- schema-parity, fuzz and hostile-content tests; and
- a real application binding with empty, offline, conflict and error states.

No desktop entry, MIME handler or onboarding suggestion is enabled by this
library slice.
