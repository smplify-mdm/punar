# ADR-008 — Persistent PIM account credentials and first provider sequence

- Status: **Accepted — record vault and one-use entry channel implemented as unstaged libraries; fixed launcher, account integration and runtime proof remain open**
- Date: 2026-09-22
- Spec references: `docs/product/SPEC_v0.2.md` §§1.22, 10–11, 15–16,
  30, 36, 44, 53, 61; `docs/design/mail-calendar-contacts.md` §§0, 7–9;
  `docs/design/profiles.md`

## Context

Mail, Calendar and Reminders need credentials that survive logout, restart and
offline use. Those credentials include IMAP/SMTP passwords or app passwords,
OAuth refresh tokens and provider account identifiers. They are not ordinary
application preferences: disclosure lets another process read mail, send as
the person, inspect calendars and contacts, or retain access after the local
account is removed.

The existing `punar-secrets` service is intentionally the wrong owner. It is a
short-lived agent credential broker with no state directory and no persistent
provider. Reusing it would silently invalidate that security contract and
would put human communications credentials behind an API designed for
time-bounded developer-tool grants.

The desktop currently ships `gnome-keyring` so third-party applications that
declare `org.freedesktop.secrets` access can work. That service is a shared
same-session store. It is useful compatibility infrastructure, but it does not
provide the first-party suite's required app boundary and cannot become the
reason Punar claims per-application credential isolation.

The service must also work on x86_64 and ARM64, including Raspberry Pi systems
without a TPM. Punar's mandatory foundation is LUKS2 device encryption; a
future profile vault may add a separately keyed boundary. An implementation
that only works when a TPM is present, or that stores an encryption key beside
plaintext-equivalent user-readable state, is not a portable answer.

Provider order is part of this decision because it determines which
credential path must be proven first. The final product must support both open
protocols and Google/Microsoft provider adapters, but implementing all three
families simultaneously would multiply authentication, policy and recovery
states before the local model is proven.

## Options considered

### Option A — Store credentials in `punar-secrets`

Rejected. It would turn a deliberately stateless, short-lived agent broker
into a human-account vault, couple unrelated authority domains and break its
published no-state invariant.

### Option B — Store first-party credentials directly in the desktop Secret Service

Rejected for the first-party suite. It is the correct compatibility route for
applications such as Evolution, but the session-wide service is reachable by
other applications granted the same D-Bus name. Punar would be unable to claim
that Mail credentials are isolated from unrelated same-profile applications.

### Option C — User-owned files below `~/.local/share`

Rejected. Mode `0600` separates Linux users but not processes running as the
same profile uid. It also makes accidental backup, indexing and application
sandbox exposure easier. Encrypting the record while leaving the usable key in
the same user-readable tree does not fix that boundary.

### Option D — A separate generic persistent credential daemon

This can provide a strong reusable primitive, but it creates another privileged
API and another resident service before Punar has a second first-party use
case. A generic “get secret” operation would also enlarge the attack surface.
Deferred unless another reviewed product needs the same primitive.

### Option E — Service-private credentials owned by `punar-pimd`

`punar-pimd` is socket activated per Linux profile, runs under a service
identity distinct from the human profile uid, owns service-private state and
uses credentials internally. Its UI API exposes account and operation ids but
has no method that returns a password, authorization code, access token,
refresh token, client secret or decrypted vault record. Chosen.

### Provider order A — Google or Microsoft first

This gives the most familiar sign-in experience, but requires production OAuth
registrations, redirect custody, tenant-policy behavior and provider-specific
APIs before the provider-neutral store and offline model are proven. Rejected
as the first slice; both providers remain required release gates.

### Provider order B — Open standards first

Prove one complete account against IMAP/SMTP plus CalDAV/CardDAV, with local
Calendar and Reminders available before any account. This exercises passwords,
TLS, discovery, folders, pagination, MIME/iCalendar input, sync cursors,
offline operation, send/update and removal without making the schema a Google
or Microsoft mirror. Chosen.

## Decision

The first real account vertical slice uses **open standards first**: IMAP and
SMTP for Mail, CalDAV for Calendar and `VTODO`, and CardDAV for shared contact
completion. Google and Microsoft adapters follow against the same typed model;
provider-specific fields stay inside their adapters.

Persistent credentials belong to a socket-activated
`punar-pimd@<profile-id>` system service, not to the QML applications,
`punar-secrets`, the session Secret Service, or Smplify. The service instance
has a distinct service identity and a private state directory; the profile uid
cannot read its database or vault files directly. One profile instance cannot
name or open another profile's accounts, state, callback listener or vault.

Credential records use XChaCha20-Poly1305 from RustCrypto's
`chacha20poly1305` 0.11 crate, locked by checksum in `Cargo.lock`; Punar does
not implement a cipher. The selected crate has an MSRV below Punar's pin, was
already present in the reviewed dependency closure through the exact HPKE
dependency, publishes the extended-nonce construction through the common
RustCrypto AEAD API, and its ChaCha20-Poly1305 lineage has a public NCC Group
implementation review. The version's official changelog and source were
reviewed before making it a direct dependency. This is dependency selection,
not a claim that Punar itself has received an independent security audit.

Every record gets a kernel-random 192-bit nonce and is authenticated with its
schema version, profile id, account id and credential kind as associated data.
The wrapping key is a random service-private 256-bit file on the already
encrypted LUKS2 data volume, is zeroized on drop, and never enters normal PIM
IPC. Vault open checks the state directory's actual device id against the
kernel device-mapper UUID and requires cryptsetup's `CRYPT-LUKS2-` identity;
a UI assertion or file mode is not encryption evidence. This prevents same-uid
file reads but **does not add an independent offline cryptographic boundary
beyond LUKS2**, and the UI must not claim that it does. A device without
verified encrypted storage cannot persist a real PIM credential. When
separately keyed profile storage ships, the wrapping key moves under that
profile key and account records are rewrapped transactionally.

The normal PIM IPC carries opaque account ids and operation results only. It
never carries credential values. OAuth uses the governed external browser,
authorization-code flow with PKCE, unpredictable state and nonce, and an exact
short-lived loopback callback owned by the service; no embedded web view and no
custom callback handed through an arbitrary browser tab. Native public clients
do not embed a client secret. Password-based open-protocol setup uses a
separate, short-lived credential-entry helper with no durable state. The
implemented channel primitive is an unnamed `SOCK_SEQPACKET` pair with a fixed
64 KiB frame limit and five-minute deadline. The helper becomes non-dumpable,
disables core dumps and future privilege gain before input exists, sends
exactly one value over the pre-established private endpoint, clears its input
on every result and exits. The service receives into a zeroizing buffer and
moves that value directly into the encrypted vault. The ordinary Mail window
never receives the password. The executable, fixed launcher and QML account
flow remain implementation work; this library is not a sign-in feature.

Account removal is a transaction: stop new work, revoke remote authorization
when the provider supports it, delete the local credential and sync cursors,
then separately ask whether cached content should be deleted. Revocation
failure is reported honestly and does not preserve the local secret as a
retry mechanism. Logs, audit, crash reports, notifications, portal inventory
and diagnostics contain credential classes and result states only, never
values or callback query strings.

The application channel follows
[`ADR-009`](ADR-009-pim-capability-channels.md): a privileged broker hands an
unnamed preconnected Unix endpoint directly to a fixed first-party launch and
transfers its peer to the service. There is no application-connectable PIM
socket. Peer uid alone remains insufficient because unrelated applications run
as the same person. Until the broker, non-dumpable sandbox and hostile same-uid
denial pass at runtime, the fixture-backed apps remain dev/CI only and no
production desktop entry or MIME handler may ship.

## Consequences

- The provider-neutral schema and offline state are proven before vendor
  adapters, while Google and Microsoft remain explicit definition-of-done
  work rather than being deferred implicitly.
- A self-hosted or standards-based provider can work without a Punar cloud
  account. Automatic discovery must be bounded and TLS authenticated; manual
  server entry remains available and never downgrades certificate validation.
- The suite adds no always-resident process. The service is socket activated,
  exits after a bounded idle period and is measured both stopped and with a
  representative synced account.
- Credentials and communication data are not available through ordinary file
  permissions to the profile uid. The service becomes a high-value parser and
  network boundary, so it needs response limits, backoff, sandboxing,
  adversarial protocol fixtures and a small dependency closure.
- Device LUKS2 remains the first at-rest boundary. Until independently keyed
  profile storage exists, Punar must describe the vault as service-private on
  the encrypted device, not as protection from an offline attacker who already
  defeated device encryption or from root.
- Third-party applications may continue to use `org.freedesktop.secrets` under
  their disclosed permissions; that compatibility path is separate from the
  first-party vault and is still reported as shared where appropriate.
- A fixed password-entry executable/launcher and a verifiable first-party
  launch capability remain implementation work. The one-use transport and
  pre-input process lockdown are implemented as an unstaged library. Falling
  back to a normal Mail text field, a world- or user-readable socket, peer uid
  alone, or a generic “get secret” method is not permitted.

## Required proof before provider sign-in ships

1. Production boots with no fixture account or credential and no PIM service
   process resident.
2. Valid profile/application clients can create, use, rotate and remove an
   account without any credential value crossing the normal PIM IPC.
3. Another uid, another profile and a hostile same-uid non-Punar process are
   denied; direct state-file reads fail.
4. Logs, audit, core dumps, environment, argv, `/proc`, notifications and
   Smplify inventory contain no password, code, token, callback query or vault
   key under positive and failure paths.
5. OAuth success, cancel, state mismatch, nonce mismatch, callback replay,
   redirect race, browser absence, revocation and network loss are distinct and
   recoverable. A callback cannot be delivered to a different profile.
6. Password entry cancellation, helper crash, service crash and power loss
   leave no recoverable plaintext and no half-created account.
7. A stolen user-owned home or same-uid process cannot read the service-private
   vault. An offline-disk claim is made only after the LUKS2 gate proves the
   device is encrypted.
8. Open-protocol initial/incremental sync, offline edits, conflicts, send,
   recurrence, removal and deletion pass on x86_64 and ARM64 before Google or
   Microsoft adapter work can alter the common schema.

## Revisit triggers

- A second first-party subsystem needs persistent credentials and can justify
  a generic narrow broker without a secret-return API.
- The profile-storage spike selects a separately keyed backend; rewrap the PIM
  vault and update the at-rest claim.
- A supported provider rejects loopback redirects for native applications or
  requires a confidential client secret on the device.
- The measured service identity, socket activation or encrypted vault exceeds
  the constrained-device RAM, wakeup or storage budget.
- The app launch-capability spike cannot deny a hostile same-uid caller without
  an LSM, per-app uid or broader desktop isolation change.

## Cryptographic dependency review sources

- RustCrypto `chacha20poly1305` 0.11 API and XChaCha20-Poly1305 usage:
  <https://docs.rs/chacha20poly1305/0.11.0/chacha20poly1305/>
- RustCrypto 0.11.0 changelog and dependency/MSRV changes:
  <https://github.com/RustCrypto/AEADs/blob/master/chacha20poly1305/CHANGELOG.md>
- NCC Group's public RustCrypto AES-GCM and ChaCha20-Poly1305 implementation
  review (2020):
  <https://research.nccgroup.com/2020/02/26/public-report-rustcrypto-aes-gcm-and-chacha20poly1305-implementation-review/>
