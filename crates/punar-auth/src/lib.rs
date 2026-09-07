#![forbid(unsafe_code)]
//! `punar-auth` — verify a session user's own password, as root.
//!
//! WHY THIS EXISTS. Onboarding creates accounts as systemd userdb records; there
//! is no `/etc/shadow` entry, and the release gate asserts every `/etc/shadow`
//! account is locked. systemd serves a userdb record's *privileged* section —
//! where `hashedPassword` lives — only to a caller running as uid 0. An
//! unprivileged `pam_unix` therefore cannot authenticate such an account at all.
//!
//! THE CONSEQUENCE SHIPPED, and it was severe: greetd runs as root, so signing
//! in worked, while punar-shell runs as the session user, so THE LOCK SCREEN
//! COULD NOT BE UNLOCKED BY ANYONE. A machine that locked itself after ten
//! minutes idle could not be reopened by its owner.
//!
//! BOTH SUBSTRATES FAIL, for different reasons, and the distro-neutral statement
//! is the one to keep in mind:
//!
//!   * Debian ships `/usr/sbin/unix_chkpwd` as mode 2755 — setgid `shadow`, not
//!     setuid root — so the helper's *effective* uid is the caller's. Measured on
//!     the owner's machine: `-rwxr-sr-x 1 root shadow`, and
//!     `userdbctl user <name> --json=short | grep -c hashedPassword` returned 0
//!     as uid 1000 while the journal recorded
//!     `pam_unix(punar-lock:auth): authentication failure; uid=1000 euid=1000`.
//!   * Arch ships it 6755 — setuid root — so the effective uid IS 0, but the
//!     *real* uid is the caller's, which nss-systemd also refuses. That refusal
//!     is deliberate: it stops a setuid binary leaking hashes.
//!
//! So "unprivileged PAM cannot read a userdb credential" is the invariant, and
//! the helper's mode only changes which check refuses first.
//!
//! systemd offers no supported unprivileged path: `io.systemd.UserDatabase`
//! exposes only `GetUserRecord`, `GetGroupRecord` and `GetMemberships` — lookup,
//! never authentication — and `pam_systemd_home` refuses anything it does not
//! manage. Adopting homed would mean per-user home encryption, which collides
//! with Punar's LUKS data partition and the ADR-003 subvolume layout. A
//! privileged verifier is the remaining design, and this is it.
//!
//! THE PROPERTIES THAT MAKE IT SAFE:
//!
//!   1. THE CALLER CANNOT CHOOSE WHO THEY ARE. The username comes from
//!      `SO_PEERCRED` — the kernel's word about the peer — and never from the
//!      request, which carries no username field at all. A caller can only ever
//!      attempt their own account. This is the whole security argument; if the
//!      username came off the wire, this would be a device-wide password oracle.
//!   2. IT RUNS THE REAL STACK, `punar-lock`, the same file the lock surface
//!      names. pam_faillock's counting and lockout therefore apply exactly as
//!      they would at a keyboard, and — because this process is root — the tally
//!      in `/run/faillock` can actually be written, which an unprivileged
//!      pam_faillock could never do.
//!   3. IT DISTINGUISHES ONLY THREE OUTCOMES, and never by the secret. `ok`,
//!      `denied`, `unavailable`. Nothing varies with the candidate password
//!      beyond allowed-or-not, so it cannot become a finer oracle than PAM
//!      already is — but a plumbing failure is NOT reported as a wrong password,
//!      because telling a locked-out owner their correct password is wrong is
//!      how a diagnosable problem becomes an unrecoverable one.
//!   4. NOTHING IS RESIDENT. systemd owns the socket and starts one process per
//!      connection, which serves a single request and exits — the pattern
//!      punar-onboardd uses, for the same reason.

pub mod protocol;
pub mod server;
