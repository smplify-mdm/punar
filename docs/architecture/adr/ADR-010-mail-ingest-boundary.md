# ADR-010 — Bounded mail ingest and rendering boundary

- Status: **Accepted — bounded MIME-to-record conversion implemented as an unstaged library; ADR-011 selects and implements authentication transport, while durable Mail storage and synchronization remain open**
- Date: 2026-09-22
- Spec references: `docs/product/SPEC_v0.2.md` §§1.22, 10–12, 15–16,
  44, 53, 61; `docs/design/mail-calendar-contacts.md` §§0, 3, 7–9

## Context

Every synchronized message is hostile input. MIME permits nested parts,
multiple encodings, very large bodies and attachments, legacy character sets,
HTML, remote resources and malformed-but-common messages. Passing a provider's
raw bytes or parser tree to QML would put parsing, network privacy and resource
limits in the window process. Writing a new MIME parser would create an
unnecessary security-critical protocol implementation.

## Decision

Punar uses the safe-Rust `mail-parser` 0.11.9 crate, pinned in `Cargo.lock`, for
RFC 5322/MIME decoding. Optional serialization and legacy multibyte encoding
features remain disabled in the first slice. `punar-pimd` owns the parser and
immediately converts its borrowed result into Punar records; no raw message,
HTML document, parser tree or attachment payload crosses application IPC.

The ingest boundary rejects empty input and any raw message above 32 MiB before
parsing. It requires adapter-supplied account, mailbox, UIDVALIDITY, UID and
received-time identity; stable local ids bind those values with SHA-256. A
message body is plain text only and is capped at 262,144 Unicode scalar values;
the preview is whitespace-collapsed and capped at 512. Subjects, names,
addresses, labels, recipients and attachment metadata have the schema's fixed
limits. Sender absence or invalidity is an explicit malformed-input result,
never replaced with a sample person.

Actual HTML parts are converted to text and mark `remote_content_blocked=true`.
Attachment bytes are discarded at ingest; only bounded name, media type and
size metadata is retained with `not_downloaded`. Opening an attachment must be
a separate fetch, quarantine and release flow. Body and attachment completeness
are reported separately rather than silently claiming truncated data is whole.

The parser has no network authority. ADR-011's IMAP/SMTP verifier now owns
TLS-authenticated account checks, but the future synchronization adapter remains
responsible for incremental cursors, download limits and backoff. The QML
window remains responsible only for rendering the already-bounded plain-text
records it receives through the authorized PIM channel.

## Consequences

- Remote images, tracking pixels, scripts and CSS cannot be fetched by reading
  a message; the first UI path receives no HTML.
- Large or malformed input becomes a typed provider error without allocating
  an unbounded Punar record.
- Full attachment support requires a separate quarantine design and cannot be
  smuggled in as a MIME-parser side effect.
- The 32 MiB whole-message ceiling may later be replaced by bounded IMAP
  section/chunk fetches. Raising it requires new memory and adversarial tests.
- Legacy multibyte encodings remain a known compatibility gap until the
  optional dependency is reviewed and measured on x86_64 and ARM64.

## Required proof before Mail ships

1. Oversized input is refused before parse and long Unicode bodies truncate on
   character boundaries.
2. HTML and remote resource URLs never appear as renderable HTML; the blocked
   state is explicit.
3. Attachment payload bytes do not enter records, logs or IPC.
4. Missing/invalid senders and invalid adapter identity fail without fixture
   substitution.
5. Parser panics, memory growth and deep/nested MIME are fuzzed and measured on
   both architectures.
6. Initial and incremental IMAP sync prove restart, UIDVALIDITY change,
   duplicate delivery, cancellation and malformed-message isolation.

## Dependency review sources

- `mail-parser` 0.11.9 documentation, feature set, RFC coverage and fuzz/Miri
  claims: <https://docs.rs/crate/mail-parser/0.11.9>
- Upstream source and release history:
  <https://github.com/stalwartlabs/mail-parser>
