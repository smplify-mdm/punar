# ADR-012 — Descriptor-bound durable Mail record store

- Status: **Accepted — unstaged durable record store implemented; real synchronization and application binding remain open**
- Date: 2026-09-22
- Spec references: `docs/product/SPEC_v0.2.md` §§1.22, 10–12, 15–16,
  44, 53, 61; `docs/design/mail-calendar-contacts.md` §§0, 3, 7–9

## Context

Calendar and Reminders currently fit a small, atomically replaced JSON file.
Mail does not: rewriting and cloning a whole mailbox for every synchronization
batch would create avoidable latency, memory growth and a 64 MiB capacity
ceiling. The replacement must be crash-durable, pageable, idle-process-free,
compatible with Rust 1.88 and openable without a path race that follows a
symbolic link supplied by another same-uid process.

SQLite offers mature query and full-text facilities, but the safe Rust wrapper
opens by pathname. Retrofitting a descriptor-owned custom SQLite VFS only to
retain Punar's existing `O_NOFOLLOW`/inode identity contract is disproportionate
for the first record store. A bundled SQLite would also duplicate a native
library already present on typical desktop closures; a dynamically linked
SQLite would add builder and target-image coupling before the PIM service is
staged.

## Decision

Punar pins `redb` 2.6.3 with default features disabled. It is pure Rust,
ACID/copy-on-write, compatible with Rust 1.85+, and accepts an already opened
`File`. Punar acquires that descriptor with `O_NOFOLLOW`, exact 0600 mode and a
single-link/owner check, retains a cloned identity descriptor, and verifies the
path still names the same device/inode before every operation. Parent state is
an owned exact-0700 directory.

The store is separate from the small Calendar/Reminders JSON state. It holds
only bounded Punar `MailSummary` and `MailMessage` records produced by ADR-010,
small message/thread indexes and IMAP mailbox cursors. It cannot represent raw
MIME, HTML, passwords, tokens or attachment payloads. Synchronization batches
and cursor advancement commit atomically. UIDVALIDITY replacement removes the
old mailbox generation in the same transaction; duplicate delivery is an
idempotent upsert.

The database cache is fixed to 8 MiB instead of redb's 1 GiB builder default.
One batch is capped at 200 messages, one record at 2 MiB, application pages at
100 records, total messages at 500,000 and the database file at 16 GiB. Those
are safety ceilings, not product promises; quota UX and account-specific
retention remain open.

## Consequences

- Mail no longer rewrites the Calendar/Reminders state file and can retain a
  real inbox across service and device restarts.
- Account removal deletes its message records, thread indexes and sync cursors
  in one transaction; a UIDVALIDITY reset affects only its mailbox.
- The file-descriptor boundary preserves the same no-follow and path-identity
  posture as the smaller PIM stores without a custom native VFS.
- Full-text search is not supplied by the engine. Punar must add and measure a
  bounded search index before claiming finished mailbox search.
- Thread metadata is recomputed only for touched threads. Extremely large
  threads and the 500,000-message ceiling still require performance and
  resource tests on x86_64 and ARM64.
- redb's file format and repair behavior become long-term compatibility
  responsibilities. Schema/file-format migration and fault injection are
  required before production staging.

## Required proof before Mail ships

1. Parsed messages, sync cursors and account removal survive restart without
   raw MIME, HTML, attachment payloads or credentials reaching the file.
2. Duplicate delivery is idempotent; UIDVALIDITY change atomically replaces
   only the affected mailbox generation.
3. Symbolic links, hard links, over-permissive files, path replacement and
   cross-profile open all fail closed without rewriting the target.
4. Power loss and injected commit failures preserve the previous complete
   state or the next complete state, never a mixed cursor/message generation.
5. Paging, large-thread behavior, file growth, cache residency and compaction
   remain inside the published x86_64/ARM64 resource budgets.
6. A migration test opens every previously shipped Mail store version. No Mail
   store is production-staged until that version policy exists.

## Revisit triggers

- bounded local full-text search cannot meet the latency or resource budget;
- redb receives an unresolved security/correctness advisory or stops
  supporting the pinned Rust floor;
- physical power-loss testing exposes a durability limitation; or
- a descriptor-owned SQLite VFS becomes a maintained, materially smaller and
  better-tested option for Punar's exact boundary.

## Dependency review sources

- redb 2.6.3 documentation and Rust-version declaration:
  <https://docs.rs/crate/redb/2.6.3>
- redb upstream design and source: <https://github.com/cberner/redb>
