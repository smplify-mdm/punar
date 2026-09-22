# Punar PIM local IPC — `punar-pimd` wire contract (v1alpha1)

Status: **accepted contract; protected read-only Mail and one-use account
connection paths exposed.** The fixture-free,
profile-bound Calendar/Reminders persistence core, LUKS-gated encrypted vault,
TLS-only open-protocol verifier, bounded read-only INBOX adapter and
non-resident sync coordinator exist in `crates/punar-pimd`. A production
executable now accepts exactly two named systemd activation descriptors and
the image stages hardened per-profile service/socket units. Those sockets are
root-only and have no install target. A human-only `pim.mail.open` call now
uses a fixed root broker to verify the live desktop session and transfer an
own-profile Mail channel plus an already-connected Wayland descriptor to a
separate locked `punar-mail` service. A second human-only
`pim.mail.account_add` call transfers one opaque account-entry capability and
the verified display stream to a separate locked `punar-mail-account` service;
passwords never enter ordinary Mail IPC, JSON, argv, environment, or logs.
`punar-pimd` verifies both TLS mail endpoints, commits atomically into the
LUKS-gated vault, and queues the first bounded INBOX sync. Neither the human uid
nor another app can open any root control socket. Account listing and removal
are exposed only through a third locked `punar-mail-accounts` Settings surface;
removal quiesces sync and deletes cached mail, provider configuration and
encrypted credentials locally without claiming to delete remote mail. The
machine-readable authority is
[`schemas/pim/ipc-message.json`](../../schemas/pim/ipc-message.json), with
provider-neutral records in
[`schemas/pim/records.json`](../../schemas/pim/records.json). ADR-008 owns
credential custody and the open-standards-first provider sequence. Release
promotion may not enable account connection until the authorization,
credential, encrypted-image and live-provider gates in that ADR pass.

The local-store implementation and its intentionally narrower boundary are
recorded in
[`docs/development/pim-local-store.md`](../development/pim-local-store.md).

## 1. Boundary and transport

Each Linux profile has a separate socket-activated service instance and state
root. The instance identity determines the profile. Applications do not
connect to a filesystem or abstract-namespace PIM socket. ADR-009 requires a
privileged launcher to give each fixed first-party application one end of an
unnamed Unix socket and transfer the other end to the service over its private
control plane. A request has no
`profile_id`, uid, home path or state path field; callers cannot select another
profile by parameter.

The application transport is that preconnected Unix `SOCK_STREAM` capability
channel. The tested descriptor-transfer primitive lives in
`crates/punar-pimd/src/channel.rs`. Mail's production launch path now uses a
root-only fixed broker, a non-dumpable locked bridge, a separate service uid,
and a private `0700` runtime socket. A filesystem-readable
socket plus `SO_PEERCRED` uid alone is explicitly forbidden because unrelated
applications run as the same human uid. There is no localhost TCP control API.

Messages are newline-delimited UTF-8 JSON. One connection processes requests
in order. Request lines are bounded to 8 MiB (a plain-text draft may be 4 MiB);
response lines are bounded to 16 MiB (a thread may contain bounded bodies and
attachment metadata). Each complete request and response has its own absolute
10-second deadline; sending or reading occasional bytes does not reset it.
Mutations return an operation record rather than holding a UI connection
across remote sync; sync and provider work have their own bounded jobs,
cancellation and backoff.

The transport-independent bounded frame reader, strict envelope parser,
closed method enum, per-client authorization-before-parameter parsing and
exact success/error encoders now live in `crates/punar-pimd/src/protocol.rs`.
Malformed frames without independently valid correlation fields close without
reflection; an error response is produced only when both `id` and `method`
are safe. `crates/punar-pimd/src/connection.rs` consumes only an already-granted
unnamed channel and applies the absolute frame deadlines; it creates no
listener. `crates/punar-pimd/src/service.rs` now composes process lockdown,
private state/key open, root-broker admission and that connection runner for
one bound profile and one already-connected control channel. The production
runtime now polls separate root-only application-grant and helper-claim
listeners, caps active connections at 32, and exits after a bounded idle
interval using an unnamed completion socket rather than a polling timer. The
socket-activated executable rejects unnamed, missing, extra, non-listening or
non-`SOCK_SEQPACKET` descriptors. The staged units run as the locked
`punar-pim` identity, keep each uid's state in an exact 0700 systemd state
directory, and grant no ambient capability. The Mail bridge additionally has
no network namespace or device access; its Qt scene graph uses the software
backend rather than broadening that authority.

The envelope is:

```json
{"v":1,"id":"reminder-1","method":"reminders.complete","params":{"reminder_id":"reminder_A1","if_revision":7,"completed":true}}
```

Success echoes `v`, `id` and `method` and carries one method-specific `result`.
Failure echoes safe `id` and `method` fields and carries one typed `error`.
Every response is encoded as protocol version `1`; an unsupported request
version receives `supported_versions: [1]` rather than making the service emit
an unsupported envelope. Exactly one of `result` or `error` is present. The
request method set is closed; an `unknown_method` error may echo only a method
name that passes the strict dotted-name grammar. Unknown properties fail
rather than being ignored.

## 2. Identity, credentials and content

- The service verifies profile ownership and the first-party launch identity
  before parsing a method. Cross-profile ids are not a discovery mechanism:
  they return `not_found`, not ownership information.
- The broker stamps one of `mail`, `calendar`, `reminders`, `settings`,
  `account_connect`, or `account_manager` on
  each transferred channel. The service enforces the closed per-client method
  partition before parsing params. Mail, Calendar and Reminders may read the
  bounded non-secret account records needed to label their own UI. Mail may
  request a bounded sync for an account it can already read. The general
  Settings identity may manage accounts and trigger sync; the password-entry
  broker can only begin or cancel a setup, and the account manager can only
  list or remove accounts. Mail cannot delete an event and Reminders cannot
  remove an account.
- Normal IPC never contains passwords, authorization codes, access or refresh
  tokens, provider client secrets, vault keys or callback query strings.
  `accounts.begin_connect` carries only a provider type. OAuth browser launch
  and the short-lived password-entry helper use the separate ADR-008 paths.
- The password path now has a tested unnamed one-use sequenced-packet channel.
  Its helper endpoint becomes non-dumpable, disables core dumps and future
  privilege gain before input exists; one bounded value is then moved directly
  into the vault and both caller and receiver buffers are cleared. Settings can
  now create or cancel a bounded five-minute setup session using only a
  provider type and opaque setup id. At most four sessions exist; the one-use
  helper descriptor remains available only to the privileged launcher side of
  the service and never crosses application IPC. Its strict root-broker control
  exchange accepts only the opaque id and profile uid, returns no provider
  data, and transfers exactly one descriptor only on success. The installed
  fixed launcher now claims that descriptor and hands it, plus a verified
  Wayland stream, to a locked one-use account-entry service. Its QML sends
  configuration and the password as separate bounded frames; a failed attempt
  cannot reuse the consumed credential capability.
- The implemented vault encrypts each credential with profile/account/kind
  associated data and refuses to open unless the service-private state path is
  kernel-observed on a LUKS2 device-mapper filesystem. A library coordinator
  now stores separately typed IMAP/SMTP records, calls a provider-verification
  interface, publishes private server settings plus public account metadata
  only after verification, and rolls back checked failures. A TLS-only network
  verifier authenticates both configured IMAP and SMTP endpoints under fixed
  deadlines. The installed account-entry surface exposes Gmail and iCloud
  presets plus custom TLS IMAP/SMTP settings. It requires an app password where
  the provider does; OAuth provider registration remains a later acceptance
  gate.
- QML windows have no direct network authority. The service owns transport,
  parsing, sync, durable state and credential use.
- Mail bodies, event descriptions and reminder notes may cross this IPC because
  the first-party applications must render them. They are content, not audit
  data: they never enter device audit, Smplify inventory or diagnostics.
- `service.status` may report the bound profile id/uid as observed service
  identity. Requests never provide or override either value.

## 3. Closed method set

| Area | Methods | Result |
|---|---|---|
| Service | `service.status` | bound profile, encryption posture, connectivity and account count |
| Accounts | `accounts.list`, `accounts.begin_connect`, `accounts.cancel_connect`, `accounts.remove` | account pages, setup state or operation |
| Sync | `sync.trigger` | bounded asynchronous operation |
| Mail | `mail.list`, `mail.thread`, `mail.message_body`, `mail.draft_create`, `mail.draft_update`, `mail.send`, `mail.archive`, `mail.delete` | page, bounded thread/body chunk, draft or operation |
| Calendar | `calendar.list`, `events.list`, `events.create`, `events.update`, `events.delete`, `events.respond` | page, event or operation |
| Reminders | `reminder_lists.list`, `reminders.list`, `reminders.create`, `reminders.update`, `reminders.complete`, `reminders.delete` | page, reminder or operation |
| Contacts | `contacts.search` | bounded address-completion page |
| Change stream | `changes.since` | ordered bounded change page and next cursor |

There is no SQL, file read, URL fetch, shell, exec, arbitrary provider request,
generic secret get/set or raw protocol method.

## 4. Pagination and change cursors

List methods take an opaque cursor or `null` and a bounded limit. A returned
page carries:

- `next_cursor`: the next page within the same stable snapshot, or `null`;
- `snapshot_cursor`: the change cursor representing that snapshot.

A cursor is integrity protected and bound to the profile, method, filter set,
sort and snapshot. Reusing it with another method/filter/profile returns
`invalid_cursor`. A cursor outside the retained change window returns
`cursor_expired`; the client must refresh a snapshot and must not guess a
replacement.

`crates/punar-pimd/src/cursor.rs` now implements that integrity primitive with
HMAC-SHA-256 and constant-time verification. The payload carries only fixed
digests of the profile and canonical filter/sort binding, not their raw values,
and is capped below the schema's 512-byte limit. `CursorSigner::load_or_create`
creates or loads the random 32-byte profile key in private state. Creation is
durable and create-new; the parent and file must be owned by the service user
with exact `0700`/`0600` modes, and existing corrupt, cross-profile, aliased or
over-permissive state is refused without replacement. Key reads use a
no-follow descriptor and validate that exact opened file, closing filename
check/read races. Key material is zeroized from transient buffers.
The profile service loads this signer before admitting an application channel.
The dispatcher uses it for structural lists, the change stream, and Mail page
and thread cursors. Mail continuation positions remain only in the private
service process, expire after five minutes, and are capped at 1,024 entries;
the cursor carries a random signed token rather than a database key.

`crates/punar-pimd/src/pager.rs` supplies the stable-snapshot half of list
pagination. A first page retains the exact provider-neutral values for at most
five minutes; later pages never fall through to the mutable live store. The
cache permits at most 16 active snapshots, 8 MiB of encoded data per snapshot
and 32 MiB total. Expiry, bounded eviction or process restart returns
`cursor_expired`, so the client refreshes instead of rendering a mixed result.
Only lists with another page consume cache space.

`crates/punar-pimd/src/dispatcher.rs` now connects the protocol to the durable
local stores/runtime for `service.status`, `accounts.list`,
`accounts.begin_connect`, `accounts.cancel_connect`, `accounts.remove`, `calendar.list`,
`reminder_lists.list`, local event/reminder create, update, complete and delete
operations, `mail.list`, `mail.thread`, and `changes.since`. Service status
reports the durable account count rather than a fixture constant. Mail reads
come only from the parsed durable store: no fixture fallback is possible.
Their signed cursors are bound to the profile, method, account or thread, and
the durable Mail revision. A sync between pages therefore returns
`cursor_expired` instead of mixing inbox generations. The dispatcher rechecks
the trusted grant uid before parsing params, maps optimistic conflicts to
bounded typed errors and emits signed cursors only after persistence succeeds.
The setup methods expose only an opaque id and closed state; they cannot carry
a password, server configuration or helper descriptor. Automatic retry
scheduling, Mail mutation/send, contacts, event responses and filtered
event/reminder reads remain explicitly unavailable. Mail can now reach this
dispatcher through the protected launch path, ask for one bounded refresh on
open, and refresh every five minutes while its window is open. A fresh profile
can add an open-protocol account through the separate one-use account surface,
and can list or remove it through the separate account manager. Live-provider
and installed encrypted-image acceptance remain open.

`changes.since` returns ordered upsert/delete metadata and a `next_cursor`.

`sync.trigger` never performs provider I/O on the application request thread.
The service returns an `accepted` operation, coalesces another trigger for the
same account into that operation, admits at most two account jobs at once and
exits each worker after one bounded INBOX batch. Success or a closed
offline/auth-required/error result is persisted on the public account record;
provider response text and credentials are not representable. There is no
resident background timer: Mail requests a bounded refresh while its window is
open, and closing the window lets the socket-activated service return to zero
residency. The stored `next_retry_at` remains the service's bounded retry
posture rather than an always-running scheduler.
`has_more` requires the client to continue before rendering the cursor as
current. Change events identify records but do not repeat message bodies or
other content. Clients fetch changed records through their typed method.

## 5. Offline and conflict behavior

Every mutable record carries `sync` metadata with one of:

- `local_only` — intentionally never submitted to a provider;
- `synced` — local and observed remote revisions agree;
- `pending` — a durable local mutation awaits upload;
- `offline` — work is retained and waits for connectivity;
- `conflict` — local and remote changes require a typed resolution;
- `error` — a named bounded failure needs retry or user action.

Offline is a state, not data loss. A mutation may return
`queued_offline`; the local change and change cursor are durable before the
response. Updates, completion, sends and destructive actions use
`if_revision`; a stale value returns `conflict` with `current_revision` and
does not overwrite either side. Conflict records name fields and permitted
resolution strategies without placing the two content bodies in logs.

## 6. Errors

The closed error set is encoded in the schema:

`malformed_request`, `unsupported_version`, `unknown_method`,
`invalid_params`, `denied`, `not_found`, `conflict`, `offline`,
`invalid_cursor`, `cursor_expired`, `rate_limited`,
`storage_encryption_required`, `upstream_auth_required`,
`upstream_unreachable`, `unsupported_provider`, and `internal`.

Messages are safe user-facing prose. `details` is deliberately small: a
resource id, current revision, retry time or supported protocol versions. Raw
server responses, URLs, headers and credential material are not error details.

## 7. Required contract tests

The schema harness validates positive status, reminder mutation, change-page
and conflict records. Negative fixtures prove that:

- a password cannot enter `accounts.begin_connect`;
- a request cannot add a `profile_id` override;
- a response cannot pair a method with the wrong result kind;
- generic `system.exec` is not a method;
- an account record cannot expose a refresh token; and
- `sync.state=conflict` cannot omit typed conflict details.

Runtime work must add the privileged peer/capability denial proof, retained
history expiry, power-loss tests and secret-leak scans before a production
application is exposed. Absolute read/write deadlines, frame limits,
cross-client denial, crash/restart, offline queue, optimistic concurrency and
cursor tampering/replay are already unit tested below the unexposed service
boundary.
