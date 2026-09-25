# ADR-011 — TLS-only open-protocol mail transport

- Status: **Accepted — account verification and bounded INBOX synchronization implemented as unstaged libraries; live-provider/runtime proof remains open**
- Date: 2026-09-22
- Spec references: `docs/product/SPEC_v0.2.md` §§1.22, 10–12, 15–16,
  44, 53, 61; `docs/design/mail-calendar-contacts.md` §§0, 3, 7–9

## Context

The first real Mail vertical slice needs to authenticate an IMAP account and
its SMTP submission endpoint without placing passwords in the QML process,
accepting invalid certificates, writing a protocol implementation, or moving
the workspace beyond its pinned Rust 1.88 toolchain. The chosen client code
must also bound hostile server responses before they reach a parser with a
larger internal ceiling.

The currently published `imap-rs` 0.2.4 requires Rust 1.95. Its own upstream
documentation also describes the implementation as young, primarily
AI-assisted, and not yet production audited or battle-tested. It is therefore
not an acceptable foundation for this release even independently of the
toolchain mismatch.

## Decision

Punar pins `async-imap` 0.11.3 for IMAP, `mail-send` 0.6.0 for authenticated
SMTP submission, Tokio 1.51.0 for their asynchronous network runtime, and
Rustls 0.23.45 with `rustls-platform-verifier` 0.7.0 for the platform CA trust
policy. Default features remain disabled where the selected functionality does
not require them. The resolved dependency set must remain compatible with
Rust 1.88 and locked in `Cargo.lock`.

The open-protocol verifier supports implicit TLS and STARTTLS. It validates
the configured hostname, requires STARTTLS when selected, has no insecure
certificate option, and applies an absolute 20-second deadline to every
network phase. The password stays inside the service-side verifier and is
borrowed directly from the vault-backed account transaction.

IMAP verification is wrapped in a 1 MiB aggregate read budget with 8 KiB
individual reads. This deliberately narrows `async-imap`'s substantially
larger internal parser ceiling before untrusted bytes can accumulate. Provider
diagnostics are mapped to a closed Punar error set and are not returned to an
application or log.

The current synchronous library entry point creates a single-thread Tokio
runtime and blocks on it. It is intended only for the future fixed PIM service
worker, not for QML or for invocation from an existing Tokio runtime. The
runtime service composition must make that ownership explicit before staging.

## Consequences

- A real account setup can prove both incoming and outgoing credentials over
  authenticated TLS without exposing credentials to ordinary application IPC.
- Enterprise and private CAs installed into the OS trust policy are honored;
  users cannot bypass certificate verification for a single account.
- The transport adds 89 resolved transitive packages to the current workspace
  lockfile. This is source-build cost, not a measured image-size or idle-RAM
  result. Release image delta and service peak memory must be measured before
  production staging.
- The next library slice now opens INBOX read-only and fetches at most twenty
  numerical UIDs per transaction. It requests only 32 MiB plus one byte per
  message, converts responses through ADR-010 and atomically commits them with
  ADR-012's cursor. It still does not send mail or establish scheduled
  retry/backoff, and it has no live-provider integration proof yet.
- SMTP response bounding currently relies on `mail-send`'s parser and timeout;
  it must receive an explicit adversarial-response proof before sending ships.
- Cancellation and crash reconciliation across the credential/account
  transaction remain separate release gates.

## Required proof before Mail ships

1. Implicit TLS and STARTTLS both reject an untrusted or mismatched
   certificate and never expose an override.
2. IMAP authentication cannot read more than the wrapper's aggregate limit,
   and SMTP authentication has an independently proven response bound.
3. Wrong credentials, timeout, malformed response and unreachable service map
   to closed errors without returning server text or credential material.
4. The service runtime never nests this blocking verifier inside another Tokio
   runtime and releases all connections after verification.
5. Initial and incremental synchronization retain the same TLS, deadline,
   response-size and error-redaction guarantees. The bounded range planner is
   unit-proven; a hostile live-server test remains required.
6. x86_64 and ARM64 builds pass with the pinned Rust toolchain, and the image,
   peak-memory and idle-residency deltas remain within the release budgets.

## Revisit triggers

- `imap-rs` reaches the pinned Rust toolchain, completes an independent
  security review and demonstrates the maturity required by this boundary;
- either selected crate becomes unmaintained or receives an unresolved
  security advisory;
- SMTP response-size enforcement cannot be proven without replacing or
  wrapping `mail-send`; or
- measured image or runtime cost breaks Punar's published budgets.

## Dependency review sources

- `async-imap` 0.11.3 documentation: <https://docs.rs/async-imap/0.11.3>
- `mail-send` upstream: <https://github.com/stalwartlabs/mail-send>
- Rustls platform verifier: <https://github.com/rustls/rustls-platform-verifier>
- Rejected `imap-rs` 0.2.4 documentation: <https://docs.rs/crate/imap-rs/0.2.4>
