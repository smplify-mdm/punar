# Punar Platform SSO — identity-bound accounts (trajectory design)

**Status:** Design · **trajectory, explicitly a later phase** · 2026-08-26 ·
**Owner:** `punard` (record authority) + a replaceable IdP provider process
**Phase placement:** **Phase 2** (§77 — *Google/Entra/Okta*, *hardware-backed
identity*, *real Smplify cloud*). Nothing here is MVP work and nothing here is
scheduled for M13.
**Spec authority:** §49 (enrollment chain — the *user authentication* step),
§47 (identity graph), §48 (just-in-time privilege), §55 (offline behaviour),
§44.1/§44.2 (boot integrity, LUKS2, TPM-assisted unlock, recovery), §60 (hard
safety constraints), §61 (local IPC security), §65 (first-boot UX), §66
(installation), §8/§3.2/§11 (unmanaged-first, additive enterprise), §73 (every
restriction explains itself), §54/§24.2 (telemetry, user visibility), §77
(Phase 2), §1.5/§1.8 (no generic root RPC; typed capabilities), §1.22
(honesty), §6.2/§6.3 (budgets, no polling loops).
**Binding prior contracts:** `docs/architecture/adr/ADR-003-ab-slots-over-snapper.md`
(shared `/home` and `/var`, vendor `/etc` per slot, Punar-owned `/etc` state is
a **capability output**), `docs/development/update-and-rollback.md`,
`docs/development/milestone-5.md` (§3 — the enrollment chain and its *documented
gap*), `docs/development/milestone-9.md` (§7 — the grant, the 60-minute ceiling,
the no-agent-grants rule, the reason string), `docs/development/milestone-13.md`
(§5.4 — account creation deferred to the installer, and *why*),
`docs/design/execution-trust.md` (the `/home` partition prerequisite it shares
with this design), `docs/design/DESIGN_LANGUAGE.md` §7 (stroke = coverage) and
§8 (unmanaged-first), `docs/design/mockups/first-boot.html` (Plate D-008 — its
stage 06 already draws `Authentication · alice@acme.com · SSO`, which is the
row this document is about), `docs/development/user-blocked.md` items 1, 2, 4
and 5.

> **An organization does not want a Linux box that happens to trust a password
> a person typed once. It wants the machine to know *who* is sitting at it,
> keep knowing while the network is gone, and stop knowing when the directory
> says the person is gone. Apple built that by owning the login window, the
> Secure Enclave and the extension API. Punar owns none of those three. This
> document says what is therefore still possible, what is not, and which
> decisions taken in the next three weeks would close the door permanently.**

This is a **trajectory** document. Per the user's framing it describes a later
phase. Its job is to be right about what is possible and to constrain what
ships **now** — §6 is the part that binds today's work.

---

## 0. Claim register (spec §1.22 · design language §7)

**Nothing in this document is implemented. No line of it is scheduled.** The
stroke rule applies to prose: a **solid** claim is a verified fact about the
world or an existing Punar contract; a *dashed* claim is designed and unbuilt.

| # | Claim | Stroke | Standing, 2026-08-26 |
|---|---|---|---|
| 01 | Apple Platform SSO's mechanism, methods and version gates as described in §1 | **solid** | Verified against Apple Platform Deployment, page dated 2026-06-12 [S1] |
| 02 | The systemd userdb Varlink API, JSON user-record sections and field set (§3) | **solid** | Verified against systemd.io [S6][S7]; `systemd` 261.2-1 in Arch `core`, 2026-07-24 [S12] |
| 03 | User records carry **no** OIDC/OAuth/SAML/IdP fields | **solid** | Verified by reading `USER_RECORD.md` field list [S7]. This is a gap Punar must fill itself |
| 04 | Himmelblau's capability set, TPM binding, uid mapping and distro list (§2) | **solid** | Verified against himmelblau-idm.org and heise, 2026-03-05 [S3][S4][S5] |
| 05 | Himmelblau is **not** packaged for Arch and the AUR package is reported broken | **solid**, with a caveat | Arch is absent from the supported list [S4]; AUR `himmelblau` / `himmelblau-git` exist with comments reporting build failure [S13]. **Not independently built by us** |
| 06 | Linux has no platform-authenticator (passkey) API in 2026 | **solid** | *Credentials for Linux*, FOSDEM 2026: PAM passwordless login is stated as a long-term goal [S10][S11] |
| 07 | The `io.punar.Identity` userdb provider, `pam_punar`, `identity.*` capabilities | *dashed* | §3–§5. No code, no IPC method, no schema |
| 08 | The bind/unbind migration preserving uid and home (§6.1) | *dashed* | Designed here; its acceptance property is testable offline, see §11 |
| 09 | Entitlement → JIT reconciliation (§7) | *dashed* | Reuses M9's shipped grant machinery unchanged; the org-policy block is new |
| 10 | Any hardware-bound ("Secure Enclave analogue") credential | *dashed*, and **blocked** | user-blocked item 2 (TPM hardware) and item 1 (Secure Boot keys). Renders `SOFTWARE ONLY` until proven on metal |
| 11 | A real directory user, real groups, real conditional access | *dashed*, and **blocked** | user-blocked item 5 (IdP tenants) and item 4 (real control plane) |
| 12 | Login-window IdP authentication, pre-boot (LUKS) IdP unlock, password sync, smartcard, passkeys | **never in Phase 2** | §9.2. Refusals with reasons, not roadmap |

---

## 1. What Apple Platform SSO actually is, mechanism by mechanism

Read this section as a specification of the *problem*, not as a target to
clone. Punar cannot clone it; §9 says why.

### 1.1 The split that matters: framework vs extension

Apple ships the **framework** — the login window, the registration handler
API, the token plumbing, the local-account machinery. The **identity provider
ships the extension**: a bundle implementing
`ASAuthorizationProviderExtensionRegistrationHandler` and friends, which calls
`saveLoginConfiguration` with an `ASAuthorizationProviderExtensionLoginConfiguration`
carrying OIDC-shaped endpoints — issuer, token endpoint, JWKS [S2]. MDM
delivers the Extensible SSO payload that binds the extension to the device.

Three parties, three jobs: **OS vendor owns the login surface; IdP owns the
protocol; MDM owns the configuration.** That decomposition is the single most
portable idea in Platform SSO, and §3 adopts it deliberately.

### 1.2 What it does at the login window

The user authenticates at the login window against the IdP, and macOS obtains
or refreshes tokens on their behalf; a full login against the IdP is required
every 18 hours by default, configurable [S1]. Tokens then serve native and web
apps without further prompting — the SSO half of the name.

### 1.3 The three authentication methods

| Method | What the local password becomes | What the IdP verifies | Character |
|---|---|---|---|
| **Password** | The IdP password **replaces** the local account password; the two stay in sync [S1][S14] | The password itself (WS-Trust for federated cases) | Simplest, weakest: a password is still a password, but it is now *one* password |
| **Secure Enclave** | Unchanged — the local password still signs the user in to the Mac [S14] | A hardware-bound key provisioned at user registration; passwordless and phish-resistant to the IdP; Touch ID / Apple Watch unlock [S1][S14] | The strong method. Requires Apple silicon [S14] |
| **Smart Card** | Mapped via local attribute configuration | A smart card registered with the IdP [S1] | The government/PIV case |

The Secure Enclave method is the one that makes Platform SSO interesting, and
it is exactly the one that depends on Apple shipping the same hardware in
every Mac.

### 1.4 Identity-bound local account creation

On-demand account creation lets a user with **no local account** create one at
the login window using IdP credentials, a smart card, or web authentication
(macOS 14+). The account name can be assigned from an IdP attribute or from
the UPN prefix (macOS 15.4+) [S1]. The resulting local account persists and
stays bound, so a returning user on a shared Mac finds their account.

**That is the property this document is named after**: an account whose
existence and name were decided by a directory, not by an installer, and whose
sign-in is validated against that directory.

### 1.5 Offline

Without network, users authenticate with the **cached local account password**
for a number of days set by IT; when a login policy demands live IdP
authentication and the IdP is unreachable, an offline grace period lets the
local password work temporarily [S1]. Note the shape: **local credential
first, freshness as a separate clock.** §4.3 copies it, because it is the only
shape that survives a tunnel.

### 1.6 Requirements and the version ladder (all [S1])

macOS 13 minimum; on-demand account creation macOS 14; login policies macOS
15; UPN-prefix naming and attestation for device identifiers macOS 15.4;
Platform SSO *during Automated Device Enrollment* macOS 26; required Touch ID
macOS 27; captive-portal authentication at FileVault unlock macOS 27.

Four years of OS releases to get from "it exists" to "it works at enrollment
and at pre-boot". That ladder is the honest estimate of the size of this
problem, and it is why §10 phases so conservatively.

### 1.7 The limit Apple itself states

**Passkeys are unavailable at FileVault unlock**, because the pre-boot
environment cannot run them [S1]. Apple, owning the entire stack, still cannot
authenticate a user against a cloud identity before the disk is unlocked. Any
Punar design claiming IdP authentication before LUKS unlock is claiming
something Apple does not.

---

## 2. The Linux survey, honestly assessed

Maturity is judged on four axes: *does it authenticate a human against a
modern IdP*, *does it create and own the local account*, *is it packaged on
the substrate Punar actually pins (Arch)*, and *how does it fail*.

| Project | What it actually delivers | Arch packaging (2026-08-26) | Failure modes |
|---|---|---|---|
| **Himmelblau** 3.0.0 (GPLv3, David Mulder / SUSE-backed) [S4][S5] | The closest Linux analogue to PSSO that exists. `himmelblaud` + `nss_himmelblau` + `pam_himmelblau` + browser SSO + a QR greeter. Device registration to Entra ID on first login via **device authorization grant**; "Linux Hello" PIN and TOTP bound to the device; PRT and Hello keys stored in a TPM or a TPM-bound software HSM; Intune compliance; generic OIDC since 3.0 (Keycloak etc.) [S3][S4][S5][S8] | **Not in `extra`/`core`. Not on the upstream supported-distro list** (openSUSE, SLE, Fedora, RHEL, Ubuntu, Debian, NixOS, Amazon Linux, Gentoo) [S4]. AUR `himmelblau` and `himmelblau-git` exist; AUR comments report the package failing to build [S13] | Does **not** create traditional local accounts: identities are mapped dynamically to uids in a default range of 200000–2000200000, homes auto-created on first login [S3]. That uid scheme is a one-way door (§6.2). GPLv3 — cannot be linked into Apache-2.0 first-party binaries; process separation only. SSH remote access requires MFA and cannot use PIN alone [S3] |
| **Microsoft Intune Company Portal / `intune-portal`** | Device enrollment, compliance policy, conditional access to Microsoft resources **through Edge**. Not a login mechanism [S9] | Not applicable. Supported only on **Ubuntu Desktop 24.04 / 26.04 LTS with GNOME, x86-64**; 22.04 support ends August 2026 [S9] | Vendor-scoped to one distro and one desktop. Nothing to reuse; useful only as evidence of what Microsoft itself considers shippable on Linux — and it is *not* login-window auth |
| **`aadsshlogin` / Entra login for Azure Linux VMs** | Entra-authenticated **SSH** with certificate-based auth and Azure RBAC roles [S15] | Azure VM extension; not a desktop mechanism | SSH only, Azure only, requires outbound 443 to `login.microsoftonline.com` per login flow [S15]. Not a console/desktop path at all |
| **SSSD** (+ realmd, AD or FreeIPA) | The mature, boring, deployed answer for **LDAP/Kerberos** directories. Enumerates directory users through NSS, authenticates through PAM, caches credentials for offline use | `sssd` **2.13.1-1 in `extra`**, updated 2026-06-09; `ding-libs` 0.7.0-1 in `core` [S12]. The only option on this list that is genuinely packaged | Domain-join thinking: DNS, NTP skew and join-account permissions are the classic join failures. Offline auth requires `cache_credentials`, and failures with `PAM_SESSION_ERR` while offline are reported even when caching is enabled [S16]. **CVE-2025-11561**: default AD configurations that do not enable the Kerberos local-authorization plugin can allow impersonation of privileged users via AD attribute modification [S16] — the exact class of bug a design that maps directory attributes to local authority invites |
| **Kanidm** (+ `kanidm-unixd`) | A modern, Rust, self-hosted IdP with a first-class Unix daemon: NSS + PAM, credential caching with **optional TPM-backed** operations, improving offline behaviour for roaming users; recent releases allow non-Kanidm backends [S17] | **Not in the official Arch repositories** (0 matches) [S12]; upstream recommends openSUSE, Fedora, FreeBSD packages [S17] | It is an *IdP you would have to run*. Punar's §77 targets are Google, Entra and Okta — tenants a customer already has. Excellent reference architecture for `unixd`; not a path to a customer's existing directory |
| **`oddjob-mkhomedir` / `pam_mkhomedir`** | Creates a home directory on first login for a directory-provided account | `oddjob` **not in the official Arch repositories** (0 matches) [S12]; `pam_mkhomedir` ships with Linux-PAM | Solves the smallest part of the problem (a directory), and does so by *not* deciding uid, name, quota, encryption or ownership. Fine as a fallback; not a design |
| **systemd-homed** (systemd 245+) | Portable, self-describing human accounts: a signed `~/.identity` record travelling with the home, LUKS/subvolume/directory/fscrypt storage, FIDO2 / PKCS#11 / recovery-key unlock | Ships **inside** the `systemd` package on Arch (261.2-1) [S12] | Solves *home portability*, not *directory binding*. Home directories are not accessible remotely over OpenSSH because PAM cannot activate a homed home in that path [S18]; network-dependent services are awkward because the home is not readable before login [S18]. And it owns storage — which collides head-on with ADR-003 (§3.3) |
| **systemd userdb / JSON user records** | The **record model and lookup API** underneath homed: Varlink services in `/run/systemd/userdb/`, `io.systemd.UserDatabase.GetUserRecord(uid, userName, service)`, records in seven sections (`regular`, `privileged`, `perMachine`, `binding`, `status`, `signature`, `secret`), fields including `uuid`, `realm`, `service`, `disposition`, `binding.uid/gid`, `privileged.hashedPassword`, `fido2HmacCredential`, `pkcs11TokenUri`, `recoveryKey`, Ed25519 signatures over the portable sections, and `io.systemd.DropIn` reading `.user` files from `/etc/userdb`, `/run/userdb`, `/usr/lib/userdb` [S6][S7] | In the base `systemd` package Punar already ships | **Carries no OIDC/OAuth/SAML/IdP fields at all** [S7]. It is a vocabulary and a socket protocol, not an identity system. That is precisely why it is the right substrate: it has no opinion to fight with |
| **PAM + OIDC modules** (`pam_oauth2_device` and its forks) | RFC 8628 device-authorization-grant login through PAM; several independent implementations, mostly aimed at SSH on servers [S19] | Not in official Arch repos; several unrelated forks | No single maintained implementation, no device registration, no offline story, no account lifecycle, no compliance. Useful as **proof the DAG flow works through PAM** — which is the flow §5.2 selects — and as nothing else |
| **FIDO2 / passkey login** | `pam_u2f` and homed's `fido2HmacCredential` cover *hardware-key* unlock. Platform passkeys do not exist: *Credentials for Linux* (FOSDEM 2026) is building `libwebauthn` and `credentialsd` to give Linux the FIDO2 platform API it lacks, and states that a PAM module for passwordless login is a **long-term goal** [S10][S11] | `credentialsd` is pre-1.0 work in progress | Linux in 2026 has no platform authenticator. A "sign in with your passkey" login window is not available to Punar in Phase 2, at any price |

### 2.1 The rejections, stated

- **Himmelblau as the substrate: rejected. Himmelblau as the first *provider*:
  recommended.** It is the best Entra client on Linux and it should not be
  reimplemented. But it ships its own NSS module, its own PAM module, its own
  daemon and its own uid policy — a second authority on a machine whose entire
  architecture is *one typed authority* (§1.5, §1.8, §60). Adopting it whole
  means Punar's account model is decided by an upstream that does not package
  for Arch. Adopting it as a **process behind a typed provider interface**
  keeps the Entra protocol work and discards the authority conflict — and
  keeps GPLv3 code out of Apache-2.0 binaries by construction (separate
  process, socket, no linking).
- **SSSD as the substrate: rejected for the §77 targets, retained as a
  provider.** Google, Entra and Okta are OIDC IdPs; SSSD's centre of gravity is
  LDAP/Kerberos. An org that genuinely runs AD or FreeIPA should get SSSD —
  it is packaged, mature and boring — behind the same provider interface.
  CVE-2025-11561 [S16] is the standing warning about what "the directory says
  this attribute, therefore local authority" costs when it is done implicitly.
- **systemd-homed as the account manager: rejected.** ADR-003 already gives
  Punar full-disk LUKS2 with a **shared `/home` partition**, and makes
  Punar-owned `/etc` state a capability output. homed would add a *second*
  encryption layer inside the first, per user, with its own unlock path, its
  own recovery material and its own interaction with A/B slot rollback — for a
  portability property (carry your home to another machine) that no Punar
  requirement asks for. It also cannot serve a home over SSH [S18], which
  would silently break developer workflows the product exists for.
- **Rolling our own NSS module: rejected.** `nss-systemd` already resolves
  userdb records. Writing a fourth NSS module in 2026 is choosing a maintenance
  burden with no benefit (§1.24, §1.25 — prefer upstream).
- **A `pam_punar` that talks to an IdP itself: rejected.** PAM modules run
  inside every authenticating process. A module that opens TLS to the internet
  from inside `login` is a footgun; the module must be a thin client to
  `punard` over the existing local IPC (§61), and `punard` must be the only
  thing that talks to a provider.

### 2.2 What no Linux stack has, and Punar cannot conjure

1. **A vendor-owned login window with a documented IdP extension API.** No IdP
   will implement a Punar-specific extension. Punar must write each provider
   itself, against the IdP's public OIDC surface (or vendor Himmelblau for
   Entra). This is the true recurring cost of this feature.
2. **A universally present secure element with a uniform attestation story.**
   TPM presence, firmware quality and PCR stability vary per machine (§9.1).
3. **A platform authenticator** [S10][S11].
4. **Pre-boot identity.** Apple does not have it either for passkeys [S1].

---

## 3. The recommended substrate

> **Punar owns the framework — the user record, the local broker and the typed
> capability. The IdP-specific work is a replaceable provider process behind a
> typed interface. This is Apple's three-party split (§1.1) with Punar in
> Apple's seat, `punard` in the MDM's seat, and a provider in the extension's
> seat.**

### 3.1 The four pieces

```text
  ┌──────────────────────────────────────────────────────────────┐
  │ greeter / login / lock  ──PAM──▶ pam_punar (thin, no network) │
  └──────────────────────────────────────┬───────────────────────┘
                                         │  existing punard UDS (§61)
  ┌──────────────────────────────────────▼───────────────────────┐
  │ punard — the RECORD AUTHORITY                                 │
  │  · identity.* typed capabilities (observe/apply/verify)       │
  │  · serves /run/systemd/userdb/io.punar.Identity  (Varlink)    │
  │  · owns the freshness clock, the entitlement cache, audit     │
  └──────────────────────────────────────┬───────────────────────┘
                                         │  typed provider interface (UDS)
  ┌──────────────────────────────────────▼───────────────────────┐
  │ punar-idp-<vendor> — the ONLY process that speaks to an IdP   │
  │  · absent entirely on a personal device (§8)                  │
  │  · entra (may vendor Himmelblau) · oidc · sssd-bridge         │
  └──────────────────────────────────────────────────────────────┘
                                         │
  ┌──────────────────────────────────────▼───────────────────────┐
  │ getent / NSS ◀── nss-systemd ◀── userdb multiplexer            │
  └──────────────────────────────────────────────────────────────┘
```

- **The record model is systemd's JSON user record**, served by `punard` on a
  Varlink socket at `/run/systemd/userdb/io.punar.Identity`, resolved through
  the stock `nss-systemd`. Punar writes no NSS module and invents no format.
- **`pam_punar` is a thin local client.** It never opens a network socket. It
  asks `punard` two questions — *is this account bound, and is its credential
  fresh enough to permit a session?* — and otherwise defers to `pam_unix`.
- **The provider is a separate process, separately packaged, absent unless
  bound** (§8). It is the only network client in the design.

### 3.2 Why the userdb record model, specifically

1. **It is already on the machine.** `systemd` 261.2-1 is in Arch `core`
   [S12]; the multiplexer, the Varlink API and `nss-systemd` ship with it.
   Punar adds a socket, not a subsystem.
2. **Its field set is almost exactly the identity-binding vocabulary**:
   `uuid` (a stable cross-machine identifier), `realm` (which *distinguishes
   users with the same name from different organizations*), `service` (which
   names the manager of the record), `disposition`, `binding.uid/gid` (machine-
   local values that override the portable ones), `privileged.hashedPassword`,
   `fido2HmacCredential`, `pkcs11TokenUri`, and Ed25519 `signature` over the
   portable sections [S7].
3. **The `binding` section is the migration mechanism.** Because uid and gid
   live in a machine-local section that *overrides* the portable record, a
   record can be attached to an account **without changing its uid** — which
   §6.1 shows is the property that makes local→bound migration reversible and
   lossless. No other Linux account model on this list offers it.
4. **It carries no IdP opinion** [S7], so Punar's OIDC binding is an extension
   Punar defines rather than a fight with someone else's model.
5. **Multiple providers coexist by construction.** Clients connect to every
   socket in `/run/systemd/userdb/` in parallel and take the first positive
   answer [S6]. An org running AD alongside an OIDC tenant is a second socket,
   not a redesign.

### 3.3 What Punar takes from homed and what it refuses

**Takes:** the record format, the signature idea, the `.identity` notion of a
self-describing account. **Refuses:** homed's *storage management*. Home
directories stay ordinary directories on ADR-003's shared `/home`, protected
by the full-disk LUKS2 the installer already owes us. Stated as a rule:

> **Punar's identity layer never owns encryption.** Disk encryption is §44.2's
> job, at the volume level, once. A per-user encrypted home under a
> full-disk-encrypted volume is two recovery stories, two TPM policies and two
> interactions with A/B rollback, in exchange for a portability property
> nothing in the spec asks for.

### 3.4 Where the extension fields live

The OIDC binding Punar needs and userdb does not define goes in a single
namespaced object in the record's `regular` section (the format permits
extension fields; anything Punar-specific stays under one key so upstream
never collides):

```json
{
  "userName": "alice",
  "realm": "acme.com",
  "uuid": "…UUIDv5(issuer, subject)…",
  "realName": "Alice Nakamura",
  "service": "io.punar.Identity",
  "disposition": "regular",
  "binding": { "…machine-id…": { "uid": 1000, "gid": 1000,
                                 "homeDirectory": "/home/alice" } },
  "io.punar.identity": {
    "v": 1,
    "issuer": "https://login.example.com/acme/v2.0",
    "subject": "…IdP subject claim, opaque…",
    "upn": "alice@acme.com",
    "boundAt": "2026-09-14T09:12:04Z",
    "method": "oidc-dag",
    "credential": "software",          // "tpm-sealed" only when proven
    "lastIdpAuthAt": "2026-09-14T09:12:04Z",
    "graceSeconds": 1209600,
    "entitlementsSyncedAt": "2026-09-14T09:12:04Z"
  }
}
```

Two deliberate choices:

- **`uuid` is UUIDv5 over (issuer URL, subject claim)** — not the IdP's own
  object id. It is stable, it is scoped to the issuer, it does not require the
  IdP to expose a UUID, and two tenants of the same vendor cannot collide.
- **No preferences, no policy, no group list is stored in the record.** The
  record is an org-facing artefact; `~/.config` is not. Theme, wallpaper,
  keyboard layout and every other choice stay where they are today (§6, rule
  9). Entitlements are cached in `punard`'s own store, not in the record, so a
  record leak is not an authority leak.

---

## 4. What identity-bound means for Punar, concretely

### 4.1 The three facts a bound account asserts

1. **Provenance** — this local account was created (or adopted) after a human
   authenticated interactively to the organization's IdP.
2. **Correspondence** — the local record carries the directory identity
   (`issuer`, `subject`, `upn`, `realm`), and exactly one local account may
   hold a given `(issuer, subject)` pair on a machine.
3. **Continued validity** — sign-in is permitted while the binding is fresh,
   and stops being permitted when it is not. Not "the password still matches".

Everything Punar claims about identity-bound accounts must reduce to one of
those three. Nothing else is claimed.

### 4.2 Online sign-in

1. Greeter collects the local credential. `pam_unix` verifies it (unchanged).
2. `pam_punar` asks `punard`: *is `alice` bound, and is the binding usable?*
3. `punard` — **not** the PAM module — asks the provider to refresh: an OIDC
   token refresh, a PRT-equivalent renewal, whatever that provider's protocol
   is. On success it updates `lastIdpAuthAt`, refreshes the entitlement cache,
   and answers `permit`.
4. Session starts. The refresh is **best-effort and time-boxed** (2 s budget);
   a slow IdP degrades to §4.3, it never holds the login window.

The user's password never leaves the PAM conversation, and never crosses the
shell (M9 §6; M13 decision 6). This is a hard constraint, not a preference.

### 4.3 Offline sign-in — precisely (§55)

Spec §55 requires a managed device to remain usable offline, to keep enforcing
local policy, to expire temporary credentials anyway, and to **never silently
downgrade enrollment**. The rules, in order of precedence:

| Rule | Behaviour |
|---|---|
| **R1 — local first, always** | The local credential (`onboarding.md` §1.10's authenticator store — `/var/lib/punar/identity/shadow` served through `nss-systemd`, or the record's `privileged.hashedPassword`, or the `/etc` materialisation if spike V1 selects the fallback) is the *only* thing that gates the keystroke. The IdP is never in the critical path of a session start. LUKS unlock happens before the network exists and the greeter starts before NetworkManager settles; a design that phones home to log in is a design that fails on a train |
| **R2 — freshness is a second, independent clock** | `lastIdpAuthAt` + `graceSeconds` (org policy; Punar default **14 days**, Punar ceiling **90 days**). Inside grace: sign in normally, no nag. Outside grace: **refuse, with §73 text** naming the policy, the last successful authentication, and the one action that fixes it ("connect this machine to a network") |
| **R3 — refusal is never a lockout** | Outside grace, the recovery path is the LUKS recovery flow of §44.2 plus a documented `punarctl identity unbind` performed by a local administrator at the console. There is always a way back into your own machine, and it is written down before the feature ships |
| **R4 — no silent downgrade** | A device that cannot reach its IdP is *enrolled and stale*, never *personal*. The bar chrome keeps saying so; the compliance category reports `stale`, not `compliant`, and the honest word appears on the surface |
| **R5 — offline never widens authority** | The entitlement cache is frozen at last sync and **decays**: an entitlement whose own expiry has passed is dropped; a new one cannot appear. M9 grants continue to expire on the wall clock. Approvals that require a second human are unavailable offline and say so |
| **R6 — no polling (§6.3)** | The refresh is attempted on session start, on the existing 120 s reconcile pass **only when a network transition has been observed**, and on `punarctl identity refresh`. There is no timer that ticks against an unreachable endpoint, and there is no retry storm — exactly M5's pending-report pattern (bounded, latest-wins) |
| **R7 — the clock cannot be won by moving it** | Freshness is evaluated against a monotonic-plus-wallclock pair, and a wallclock that jumps backwards past `boundAt` marks the binding `unverifiable`, not `fresh` |

### 4.4 What sign-out and de-provisioning mean

A directory disabling a user does **not** reach a disconnected laptop. That is
physics, and §1.22 forbids pretending otherwise. What Punar can honestly say:

- **Online:** revocation takes effect within one reconcile pass (≤120 s) —
  session-start is refused and active JIT grants for that uid are revoked.
- **Offline:** it takes effect when grace expires, and no sooner. The grace
  window *is* the organization's exposure window, which is why it is a policy
  value with a Punar-imposed ceiling and why the compliance surface renders it
  as a number the admin can see.
- Punar does **not** claim remote session kill, remote wipe, or instant
  revocation. Those are control-plane features and none of them is in Phase 2.

---

## 5. How this meets M5's enrollment (§49)

### 5.1 Today's honest gap

M5 §3 maps the §49 chain and writes, of the *user authentication* step:
**absent — no IdP in the MVP; the enrolling actor is the root admin running
the verb.** user-blocked item 5 says the same. Plate D-008's stage 06 already
*draws* the row (`Authentication · alice@acme.com · SSO`) — the drawing is
ahead of the code, deliberately and legibly.

Platform SSO is the thing that fills that row. It changes nothing else in the
chain.

### 5.2 The protocol delta

| §49 step | Today (M5) | With PSSO | Note |
|---|---|---|---|
| Device bootstrap identity | `device-id` + per-enroll bootstrap secret | unchanged | |
| Choose personal / organization | `punarctl enroll start <domain>` | unchanged | The fork stays a fork (§8) |
| Organization discovery | `org.discover{domain}` → `org.json` | **`org.json` gains an `idp` block**: issuer, `authorization_endpoint`, `token_endpoint`, `device_authorization_endpoint`, `jwks_uri`, `client_id`, permitted methods, account-name mapping rule, `graceSeconds` | This is Apple's `saveLoginConfiguration` [S2] delivered by the control plane instead of by MDM payload |
| **User authentication** | **absent** | **New step: RFC 8628 device authorization grant.** `punard` asks the provider to begin; the provider returns a `verification_uri` and a `user_code`; the OOBE surface renders code + URL (+ QR); the human completes it **on another device**; the provider polls its own token endpoint and returns an assertion | §5.3 — this is the load-bearing design choice |
| Device registration | `enroll.register{device_id, bootstrap}` → `device_token` | `enroll.register{device_id, bootstrap, user_assertion}`; the issued `device_token`'s subject becomes **(device_id, user_uuid)** | One transaction binds device and person. The control plane learns the pair; that is what makes the §47 graph real |
| Attestation | `"simulated"`, labelled | unchanged, still **SIMULATED** | **But the two rows now separate**: *user* authentication can go solid while *device* attestation stays dashed. Stage 06 must render them independently — that is a real honesty gain and costs one row |
| **User provisioning** | n/a | **New step**: `identity.account` apply — create or adopt the local account, write the record, seal the offline credential, create `/home/<name>` if absent | §6.1 |
| Desired state / Policy | `policy.fetch{device_token}` | policy envelope gains the **`entitlements`** block (§7) | Additive; the M4 loader/merge is unchanged in shape |
| Provision / Verify / Managed desktop | reconcile pass | unchanged, plus one new reconciled capability | |

### 5.3 Why device authorization grant, and not a password field

Three constraints collide at first boot: §65 forbids shell commands; M13
decision 6 and M9 §6 forbid a credential surface in the shell; and modern IdP
sign-in is a browser flow with MFA, conditional access and possibly a passkey
— none of which a QML form can host.

The device authorization grant dissolves all three. The OOBE surface renders a
short code and a URL. The **secret never exists on this machine at all**; the
user authenticates on a phone that already holds their MFA. Punar's first-boot
surface stays a display, not an input. It is also the flow Himmelblau uses for
first login [S3] and the flow the PAM OIDC modules implement [S19], so it is
the flow with the most Linux prior art.

Corollary, and it is a real one: **first boot needs a network for the
organization path**, which D-008 already states in as many words ("the
organization path simply stays closed until a network exists"). The plate was
right.

### 5.4 The §47 graph afterwards

```text
Organization ─── realm/issuer ───▶ IdP tenant
     │                                  │
     │                            (issuer, subject)
     ▼                                  ▼
   Device ◀────── binding: device_token(device_id, user_uuid) ─────▶ User
     │                                                                │
     └────── local record: binding.uid ──────────────────────────────┘
                     │
        Project · Application · AI Agent · Service   (unchanged, below uid)
```

**Audit does not change shape.** Events keep carrying `uid`; the directory
identity is resolved **at render time** through the record, never written into
each event. Reasons: `schemas/audit/audit-event.json` stays untouched; an
audit log does not become a directory of employee UPNs on disk; and unbinding
does not orphan history. This is a hard rule, not an optimisation.

---

## 6. What must not be precluded now

**This is the section that binds today's work.** M13 §5.4 defers account
creation to the installer; whenever that lands — in `docs/design/onboarding.md`
or in the installer itself — it must respect these eleven rules. Each is
cheap now and expensive later.

| # | Rule | Why, in one line |
|---|---|---|
| **1** | **The uid must be allocatable and then permanent.** Allocate from an on-disk allocator with a persistent map; never derive a uid from a name, an email, or a directory object id | Himmelblau derives uids from object ids in a 200000–2000200000 range [S3]. That is a one-way door: an existing local account can never *become* that uid without `chown -R` over a home, and the migration in §6.1 stops being reversible |
| **2** | **Nothing may assume uid 1000.** Read it from the account | The dev image's `punar` user happens to be 1000. A bound account on a shared machine will not be |
| **3** | **Usernames come from a POSIX-portable charset** — `^[a-z][a-z0-9_-]{0,31}$`, no trailing hyphen — and are **never** an email address | So a directory-derived name (Apple maps from the UPN prefix [S1]) can equal the local name without a rename. `/home/alice@acme.com` breaks on every domain change. *(Aligned 2026-08-26 with `onboarding.md` §1.3, which owns this rule. An earlier draft here said `{0,30}`; the two documents differed by one character, which is exactly the kind of divergence that becomes a rejected directory name eighteen months from now. 32 characters total is what `useradd` on the substrate accepts.)* |
| **4** | **The login name and the login *identity* are different fields.** Store the human name in `realName`/GECOS; never encode the UPN in the username or the home path | Rename is the commonest directory event there is |
| **5** | **`/home/<username>`, on ADR-003's shared `/home`, mode 0700, primary group per-user.** No per-user encrypted container, no storage manager | §3.3. Also the hard prerequisite `execution-trust.md` already depends on |
| **6** | **There is exactly one local verifier, it holds a yescrypt hash, and the password reaches it only through a privileged helper** — never as a string over IPC, never on a command line, never through the shell | M9 §6; M13 decision 6. If the QML surface ever posts a password, the whole PSSO offline story inherits a credential path it cannot defend. *(Restated 2026-08-26. An earlier draft named `/etc/shadow` as that verifier. `onboarding.md` §1.10 subsequently decided — for an ADR-003 reason this document does not get to overrule — that the authenticator lives at `/var/lib/punar/identity/shadow` and is served to `pam_unix` through `nss-systemd`, with `/etc` materialisation kept as the fallback if spike V1 fails. **The rule PSSO actually needs is "one verifier, reached only by a privileged helper", and that survives either outcome.** Naming `/etc/shadow` here also contradicted §3.1 of this very document, which recommends the userdb substrate.)* |
| **7** | **Account creation happens through one typed capability — `identity.local-account` (`onboarding.md` §1.11) — which is the only writer of the account store**, whichever materialisation §1.10's spike selects | Without a chokepoint there is nothing for migration to hook, nothing for drift to reconcile, and nothing for audit to attribute. ADR-003 already requires Punar-owned `/etc` state to be a capability output — and `onboarding.md` §1.10's chosen path satisfies that rule by never engaging `/etc` at all. *(Renamed 2026-08-26 from `identity.account`; `onboarding.md` owns the name.)* |
| **8** | **No production account is in `wheel` by default, and no code decides authority by group membership** | §48. `punard` authorizes on SO_PEERCRED uid + M9 grants; keep it that way. A directory group mapped to `wheel` is exactly the fudge §7 refuses, and CVE-2025-11561 [S16] is what that class of shortcut costs |
| **9** | **User preferences never enter the user record.** Theme, layout, wallpaper, app choices stay in `~/.config` / `~/.local/state` | The record is org-facing. A theme choice is not |
| **10** | **Never read `/etc/passwd` directly.** Every enumeration — product code, check scripts, fixtures — uses `getent passwd` / `userdbctl` | The day a userdb provider exists, direct readers see a machine with a missing user and fail in the least debuggable way possible. This is enforceable in CI **today**, offline, for free |
| **11** | **Reserve the names.** `punar` (the dev user), `root`, and any name below `SYS_UID_MAX` cannot be bound; uid 0 can never be bound | A directory user called `punar` must not be able to adopt the dev account |

Two smaller ones worth writing down: the first-boot marker must keep recording
**the mode and not the answers** (M13 §5.6) — a bound identity in that file
would be a second source of truth — and choosing `personal` at the fork must
keep writing **nothing at all**, so that §8's inertness assertion stays true.

### 6.1 The migration sketch — local account → bound account

The acceptance property, stated first because everything else serves it:

> **Binding adds a record. It never rewrites the POSIX account. Therefore
> unbinding is deleting a record, the uid never moves, the home is never
> touched, and no user data is at risk in either direction.**

**Preconditions:** the device is enrolled; the org's `idp` block is present; a
local account `alice`, uid `U`, gid `G`, home `/home/alice` exists.

1. **`punarctl identity bind --user alice`** — root-only, `--reason` required,
   audited. It creates an M9 approval of a new kind `identity_bind`, resolvable
   **only by a human at this console** (M9 §4.4). Changing who owns an account
   is not a background operation.
2. **Interactive proof.** `punard` asks the provider to run the device
   authorization grant (§5.3). The human completes it on another device. The
   provider returns `issuer`, `subject`, `upn`, display name and the raw group
   claims.
3. **Conflict checks, all fail-closed.** Is `(issuer, subject)` already bound
   on this machine? Is `alice` already bound to a different subject? Is `alice`
   reserved (rule 11)? Is uid `U` below `SYS_UID_MAX`? Any yes → refuse with
   §73 text; write nothing.
4. **Name divergence is recorded, never acted on.** If the directory's
   preferred name is `alice.nakamura`, the local name **stays `alice`**. The
   directory name lands in the record; the home is not renamed; no symlink is
   created. Renaming a home is how migrations lose data.
5. **Write the record.** `service: io.punar.Identity`, `realm`, `uuid` =
   UUIDv5(issuer, subject), `binding.<machine-id>.uid = U`, `.gid = G`,
   `.homeDirectory = /home/alice`, and the `io.punar.identity` object of §3.4
   with `credential: "software"`. Atomic write, `0600 root:root`, schema-
   versioned per ADR-003's N-1 rule.
6. **Seal the offline credential.** With a verified TPM: seal a key to the
   measured-boot policy and set `credential: "tpm-sealed"`. Without one (every
   VM, and every machine until user-blocked item 2 clears): keep the existing
   local authenticator (`onboarding.md` §1.10's store, wherever spike V1 puts
   it) and leave `credential: "software"`, which renders
   `SOFTWARE ONLY` dashed on every surface that mentions it. **Note the ADR-003
   interaction:** an A/B slot swap changes what is measured, so a TPM-sealed
   identity credential must be re-sealed by the update flow in the same place
   the LUKS TPM enrollment is — one mechanism, not two.
7. **Activate the plumbing, in this order.** Start the userdb socket → verify
   `getent passwd alice` returns **identical** uid, gid, home and shell → only
   then write the `pam_punar` drop-in. If the verify step fails, stop: the
   record is deleted and PAM was never touched. **PAM is the last thing
   changed and the first thing reverted**, because a broken PAM stack is an
   unbootable machine.
8. **Verify (the capability's `verify` half).** `punarctl identity status`
   reports bound, uid unchanged, freshness fresh; one audit event
   `identity.bind` with the approval id and the reason.
9. **Rollback — `punarctl identity unbind`.** Remove the PAM drop-in, stop the
   socket, delete the record and any sealed key. The POSIX account as
   `getent` resolves it, the local authenticator store, the uid, the gid and
   `/home/alice` are **byte-for-byte untouched**. *(Stated by observable
   behaviour rather than by filename, because `onboarding.md` §1.10 owns where
   the account and its authenticator physically live and spike V1 has not yet
   chosen between the two candidates.)* The
   account is local again and the user notices nothing but the loss of SSO.

**The reverse direction (bound → local)** is step 9, and it is the same
operation an administrator performs when a device leaves the organization. It
is also what `punarctl enroll stop` must call, so that unenrollment cannot
leave a machine holding accounts that reference a directory it no longer talks
to.

**What migration explicitly does not attempt:** merging two local accounts;
adopting an account whose home is on removable media; binding more than one
directory identity to one uid; changing a uid under any circumstances.

---

## 7. The privilege interaction (§48 + M9)

An organization says *"these twelve people are administrators."* Punar says
*"nobody is a standing administrator."* Both sentences can be true at once,
and the reconciliation is not a compromise — it is a translation.

### 7.1 The translation

> **A directory group is imported as an *entitlement*: a named, expiring
> eligibility to *request* privilege. It is never a right to hold it.**

The org policy envelope (M5's `policy.fetch`, M4's merge, org rank) gains an
`entitlements` block:

```yaml
identity:
  entitlements:
    - group: "acme-linux-admins"          # directory group, opaque to Punar
      capabilities: ["system.install-package", "security.firewall"]
      maxDurationMinutes: 30              # ≤ Punar's own 60-minute ceiling
      approval: "self"                    # "self" | "second-human"
    - group: "acme-sec-engineering"
      capabilities: ["security.*"]
      maxDurationMinutes: 15
      approval: "second-human"
```

### 7.2 The three effects an entitlement may have — and only these three

1. **Requestability.** Whether `punarctl privilege request --capability X`
   from this uid is *considered at all*. Without an entitlement the request is
   refused with §73 text naming the policy that did not grant it.
2. **Duration ceiling.** The maximum `--duration`, itself clamped by M9's
   existing `[1, 60]` minute range. Org policy may only make the window
   *shorter* than Punar's ceiling, never longer.
3. **Approval routing.** Self-resolvable (the friction is the reason, the
   clock and the visible chip — M9 §7) or requiring a second human.

### 7.3 What an entitlement may never do

- Produce a **standing grant**. Every elevation still creates an approval
  record, still names a reason, still expires, still shows the `ELEVATED ·
  MM:SS REMAINING` chip, still audits (M9 §7).
- Add anyone to `wheel`, install a sudoers rule, or create any persistent
  local admin. §48 and §60 ("add persistent unrestricted root") both point
  here.
- Grant anything to an **AI agent**. M9's rule is unchanged and absolute: a
  grant is never issued to a peer attributed to an agent session. A directory
  group cannot launder an agent into a human.
- Skip the reason string, which travels verbatim into the audit event.
- Widen while offline (§4.3 R5).

### 7.4 The org that insists

An organization whose baseline says *"admins have standing root"* gets, at
most, `approval: "self"` with `maxDurationMinutes` at the ceiling: **"may
elevate without waiting", not "is elevated".** If their compliance framework
requires a literal standing local-admin group, Punar **refuses and reports the
refusal** — the compliance category renders `refused`, with the policy id and
the Punar rule that refused it, rather than silently reporting compliant. That
is §1.22 applied to a commercial conversation, and it is the difference
between a product with a position and a checkbox.

### 7.5 Revocation timing, stated honestly

Removing a person from a directory group takes effect within one reconcile
pass online (≤120 s) — and **not at all** while the device is offline, until
grace expires (§4.4). This is precisely why grants are minutes long and why
entitlements decay rather than persist. The exposure window is the grace
window, it is a number on the compliance surface, and nobody has to guess it.

---

## 8. The unmanaged-first rule: structurally inert, not hidden

Design language §8 and spec §3.2/§11 require the personal device to be the
default state of every surface. For an identity subsystem, *hidden* is not
good enough — an inert code path that still parses a config file, still opens
a socket, or still sits in the PAM stack is an attack surface and a bug source
on a machine that will never enroll. Six requirements, each mechanically
checkable:

1. **The provider is absent, not disabled.** `punar-idp-*` is a separate
   package that is **not in the personal image at all**. There is no daemon to
   disable, no unit to mask and no binary to exploit. This is the same posture
   `punar-mock-smplify` has toward production images, inverted.
2. **No userdb socket exists.** `punar-userdb.socket` has no `WantedBy`
   anywhere in `/usr/lib/systemd/system/*.wants/`. It is started **only** by
   the `identity.bind` capability's apply and stopped by its unbind. On a
   personal machine `/run/systemd/userdb/` contains no Punar socket, and
   `punard` opens no listener beyond the one it has today.
3. **The PAM stack is stock.** `pam_punar` is written into a drop-in by the
   capability and removed by unbind. A personal first boot touches **zero** PAM
   files. The whole authentication path of an unmanaged Punar is the same
   `pam_unix` path Arch ships, which is also the reason a bug in this design
   cannot brick a personal machine.
4. **No network client exists.** The only process that speaks to an IdP is not
   installed. There is no fallback, no built-in default issuer, no
   "unconfigured" HTTP client waiting for a config file.
5. **No upsell.** Beyond D-008's existing fork card — which is a card, not a
   gate — no surface mentions organizational sign-in. Absence is calm paper,
   never an "unenrolled" warning (design language §8).
6. **`punarctl identity status` on a personal device** prints
   `not configured · this device is personal`, exit **0**, and the
   `identity.account` capability observes `unconfigured` with reconcile making
   no change — the M5 unenrolled pattern verbatim.

**The inertness check** (offline, in-VM, the shape `m*-check.sh` already
uses): on an unenrolled image, assert (a) no `io.punar.*` socket in
`/run/systemd/userdb/`, (b) `/etc/pam.d/` matches the vendor tree exactly, (c)
no `punar-idp-*` binary on the filesystem, (d) `getent passwd` enumeration
equals the `/etc/passwd` enumeration, (e) `punarctl identity status` exits 0
with the personal text. Five assertions, no network, no hardware. Note (d)
also enforces §6 rule 10 for free.

---

## 9. Honest limits and blockers

### 9.1 What Apple gets from owning the hardware, which Punar cannot replicate

| Apple has | Punar has | Consequence |
|---|---|---|
| A Secure Enclave in **every** shipped machine, uniform attestation | A TPM that may be present, may be firmware-emulated, may be disabled in setup, with PCR behaviour that varies by vendor and moves on firmware update | The strong method is Apple's *default*; for Punar it is the *lucky case*. Every surface must therefore distinguish `TPM-SEALED` from `SOFTWARE ONLY`, and default to the honest one |
| A vendor-owned login window that can demand live IdP authentication [S1] | `greetd` plus a greeter Punar has **not built** (Plate D-002, deferred by M13 decision 7) | Login-window IdP authentication is not merely unbuilt, it is downstream of a surface that does not exist. §10 phases accordingly |
| FileVault unlock that can reach the IdP — and that **still cannot use passkeys** [S1] | LUKS2 unlock in the initrd, before userspace and before the network | Pre-boot IdP authentication is out of scope. Apple, owning everything, has the same limit for passkeys; we would have it for everything |
| One extension API that Microsoft, Okta, JumpCloud and others implement [S2] | No such contract, and no leverage to create one | Punar writes each provider itself, or vendors Himmelblau for Entra [S4]. **This is the recurring engineering cost of the feature and it does not go away** |
| MDM that ships the SSO payload as a first-class OS concept | A control plane that does not exist yet (user-blocked 4) | The `idp` block in `org.json` is designed here and mocked there |
| A platform authenticator | None on Linux in 2026 [S10][S11] | "Sign in with a passkey" is not available at any price in Phase 2 |

### 9.2 What Punar would be claiming vs. what it could prove

**Provable offline, in CI, with no tenant and no hardware** — by standing up a
fixture OIDC issuer inside the image exactly as `punar-mock-smplify` stands up
a fixture control plane, and labelling it a harness in the same words:

- the record model, `getent`/`userdbctl` resolution, and NSS integration;
- bind → verify → unbind with **uid, gid, home and shell byte-identical**
  before and after (the §6.1 acceptance property);
- the device-authorization-grant flow end to end against the fixture issuer,
  including the surface never receiving a secret;
- the freshness clock: fresh → stale → refused, with the §73 refusal text
  asserted verbatim, and R7's backwards-clock case;
- entitlement → `privilege request` → grant → expiry, and every §7.3 refusal;
- the five §8 inertness assertions;
- schema-version N-1 compatibility of the record file (ADR-003's rule).

**Not provable without user-blocked items**, and therefore not claimed:

| Claim | Blocked on |
|---|---|
| A real directory user, real group claims, real conditional access, real MFA | **Item 5** — IdP tenants |
| Hardware-bound credentials; anything called "phishing-resistant" or "hardware-backed"; any Secure Enclave analogue | **Item 2** — physical TPM hardware |
| The measured-boot policy the sealing binds to | **Item 1** — Secure Boot signing keys |
| The device↔user binding recorded server-side, and admin-side revocation | **Item 4** — the real control plane |

**Refusals, stated as rules:** no Punar surface may print *MFA enforced*,
*phishing-resistant*, *hardware-backed* or *verified identity* while
`credential` is `software`. The dashed `SOFTWARE ONLY` tag is mandatory in
that state, exactly as `SIMULATED · VM` is on D-008's attestation row today.

### 9.3 The blocker this design adds to the list

user-blocked item 5 currently reads *"test tenants for Google Workspace,
Microsoft Entra, or Okta — whichever Smplify supports first"*. This design
sharpens what is needed: a tenant with **an app registration permitting the
device authorization grant**, at least two test users, at least two groups,
and an administrator able to disable a user on demand — because R4, §7.5 and
§4.4 cannot be demonstrated with a single always-valid account.

---

## 10. Phasing

### 10.1 PSSO-1 — the minimum credible version

**One IdP.** Whichever Smplify sells first; Entra has by far the most mature
Linux prior art [S3][S4][S5]. Generic OIDC second, because Himmelblau 3.0
proves the shape [S5] and because it makes a fixture issuer possible in CI.

In scope:

- the `idp` block in `org.json`, and the device-authorization-grant step in the
  §49 chain — **at enrollment only**, on a networked first boot;
- the `io.punar.Identity` userdb provider and the bound record (§3.4);
- `identity.account` / `identity.bind` / `identity.unbind` typed capabilities,
  reconciled like any other, with the M9 approval kind;
- **local password remains the offline verifier**; `credential: "software"`,
  labelled;
- the freshness clock, the grace window, and the §73 refusal;
- entitlements → M9's existing JIT machinery (§7), with no new privilege
  primitive whatsoever;
- reversible bind/unbind with uid preserved (§6.1) — **the acceptance test**;
- the five inertness assertions (§8).

Explicitly **not** in PSSO-1: login-window IdP authentication; password sync
(Apple's Password method — it makes the IdP password the local password, which
is a step *down* in offline safety and a step *up* in blast radius, and it is
not worth taking first); hardware-bound credentials; pre-boot unlock;
smartcard; passkeys; shared multi-user devices; on-demand account creation at
the greeter.

**Depends on:** user-blocked 5 (tenant) and 4 (control plane) to be real; on a
greeter existing (D-002) only for the *later* phases, not for PSSO-1, because
PSSO-1 binds at enrollment rather than at the login window; and on §6's rules
having been respected by whatever ships account creation.

### 10.2 PSSO-2 — needs hardware

TPM-sealed credential plus a local PIN (the Himmelblau "Linux Hello" shape
[S3][S8]); freshness evaluated at the greeter; compliance-gated sign-in;
re-sealing integrated with the ADR-003 A/B update flow. **Depends on**
user-blocked 2 and 1. Only here may any surface stop saying `SOFTWARE ONLY`.

### 10.3 PSSO-3 / Phase 3

On-demand account creation at the login window (needs the D-002 greeter built
first); shared multi-user devices; per-user unlock; attestation-bound tokens.
Spec §78 already lists measured boot / remote attestation in Phase 3, which is
where the honest half of this belongs.

### 10.4 Spec phase placement

**Phase 2, §77** — it is the intersection of three §77 lines: *Google/Entra/
Okta*, *hardware-backed identity*, and *real Smplify cloud*. PSSO-1 is the
Google/Entra/Okta line; PSSO-2 is the hardware-backed identity line; neither
starts before the real control plane line. Nothing in §76's milestone plan
should attempt any of it, and M13 in particular must not: its §5.4 deferral of
account creation is the correct call, and this document exists partly to make
sure that deferral is *shaped* correctly rather than merely postponed.

---

## 11. Verification, when it is built

Everything below runs in the CI VM with **no network** and no TPM, in the
established `punar-mN-check.service` → `/run/punar/mN-report.txt` shape, and
none of it requires diffutils.

1. **Inertness (§8)** — the five assertions, on an unenrolled image.
2. **Bind/unbind identity** — capture `getent passwd alice`, `stat` of
   `/home/alice`, and the sha256 of the local authenticator record before bind
   and after unbind;
   assert equality with `cmp`-free shell comparison. This is the single most
   important test in the design.
3. **Fixture issuer** — an in-image OIDC fixture, dev/CI-only, never enabled,
   named a harness in its `--help` line, exercising the DAG flow.
4. **Freshness state machine** — fresh → stale → refused, driving the clock
   via the record rather than the system clock, plus the R7 backwards-clock
   case.
5. **Entitlement matrix** — every row of §7.2 and every refusal of §7.3,
   including the agent-attributed request being refused outright.
6. **Record schema N-1** — the previous release's record parses.
7. **Surface honesty** — grep the rendered surfaces for the forbidden strings
   of §9.2 while `credential` is `software`.

What an offline VM **cannot** prove is listed in §9.2 and must be listed again
wherever this ships, in those words.

---

## 12. What Punar must not claim

- **Not** that a disabled directory account cannot use a disconnected laptop.
  It can, until grace expires. The grace window is the exposure window and it
  is rendered as a number.
- **Not** that sign-in is "verified against the identity provider" when the
  device is offline. It is verified against a cached local credential inside a
  policy window — say that.
- **Not** phishing-resistant, hardware-backed, or MFA-enforced without a TPM
  path proven on real hardware.
- **Not** that Punar has Platform SSO "like macOS". It has a different, weaker
  thing built on different, weaker foundations, and §9.1 is the table that says
  which parts are weaker and why.
- **Not** that binding is required. A personal Punar has none of this, forever,
  and that is the product's first promise (§3.2, design language §8).

---

## 13. Sources

All retrieved 2026-08-26 unless stated.

- **[S1]** Apple, *Platform Single Sign-on for macOS*, Apple Platform
  Deployment. Page dated 2026-06-12.
  https://support.apple.com/guide/deployment/platform-sso-for-macos-dep7bbb05313/web
- **[S2]** Francis Augusto Medeiros-Logeay, *Platform Single Sign-on DIY*
  (2025), on `ASAuthorizationProviderExtension*`, `saveLoginConfiguration` and
  the OIDC endpoints an extension registers.
  https://francisaugusto.com/2025/Platform_single_sign_on_diy/
- **[S3]** *A Practical Introduction to Himmelblau*, Himmelblau documentation.
  https://himmelblau-idm.org/docs/introduction/
- **[S4]** *Linux cloud identity, built in the open* — Himmelblau project site
  and supported-distribution list. https://himmelblau-idm.org/about/
- **[S5]** heise online, *Entra ID for Linux: Himmelblau 3.0 extends
  enterprise features*, 2026-03-05 (version 3.0.0, GPLv3, David Mulder /
  SUSE).
  https://www.heise.de/en/news/Entra-ID-for-Linux-Himmelblau-3-0-extends-enterprise-features-11200189.html
- **[S6]** systemd, *User/Group Record Lookup API via Varlink*.
  https://systemd.io/USER_GROUP_API/
- **[S7]** systemd, *JSON User Records*. https://systemd.io/USER_RECORD/
- **[S8]** Himmelblau, *Configuring a Hardware TPM for Secure Key Storage*.
  https://himmelblau-idm.org/docs/advanced/Configuring-a-Hardware-TPM-for-Secure-Key-Storage/
- **[S9]** Microsoft Learn, *Deployment guide for Linux device management* /
  *Enroll a Linux device in Intune* (Ubuntu Desktop 24.04 & 26.04 LTS, GNOME,
  x86-64; 22.04 support ends August 2026).
  https://learn.microsoft.com/en-us/intune/fundamentals/platform-guide-linux
- **[S10]** FOSDEM 2026, *Credentials for Linux: Bringing Passkeys to the Linux
  desktop*. https://fosdem.org/2026/schedule/event/838A8N-credentials-for-linux-bringing-passkeys-to-linux/
- **[S11]** Credentials for Linux project (`libwebauthn`, `credentialsd`).
  https://github.com/linux-credentials
- **[S12]** Arch Linux package database: `systemd` 261.2-1 (`core`,
  2026-07-24); `sssd` 2.13.1-1 (`extra`, 2026-06-09); `ding-libs` 0.7.0-1
  (`core`, 2026-04-08); **no** `kanidm` and **no** `oddjob` in the official
  repositories. https://archlinux.org/packages/
- **[S13]** AUR packages `himmelblau` and `himmelblau-git`; package-page
  comments report build failures. **Not independently verified by building.**
  https://aur.archlinux.org/packages/himmelblau
- **[S14]** Microsoft Learn, *macOS Platform Single Sign-on (PSSO) overview*
  (Secure Enclave vs Password method semantics, Apple silicon requirement).
  https://learn.microsoft.com/en-us/entra/identity/devices/macos-psso
- **[S15]** Microsoft Learn, *Sign in to a Linux virtual machine in Azure by
  using Microsoft Entra ID and OpenSSH* (`aadsshlogin`; SSH only).
  https://learn.microsoft.com/en-us/entra/identity/devices/howto-vm-sign-in-azure-ad-linux
- **[S16]** SSSD offline-authentication behaviour and failure reports
  (SSSD/sssd issues #5846, #7499); Red Hat `cache_credentials` documentation;
  CVE-2025-11561 (AD integration, Kerberos local-authorization plugin not
  enabled by default). https://github.com/SSSD/sssd/issues/7499 ·
  https://explore.alas.aws.amazon.com/CVE-2025-11561.html
- **[S17]** Kanidm, *PAM and nsswitch* administration documentation and
  release notes (v1.8.x; `kanidm-unixd` caching, optional TPM-backed
  operations). https://kanidm.github.io/kanidm/stable/integrations/pam_and_nsswitch.html
- **[S18]** systemd-homed limitations: home directories not reachable over
  OpenSSH because PAM cannot activate them in that path; network-state
  interactions (systemd issue #22309). ArchWiki *systemd-homed*;
  https://github.com/systemd/systemd/issues/22309
- **[S19]** `pam_oauth2_device` and its forks — RFC 8628 device-authorization-
  grant PAM modules, multiple independent implementations.
  https://github.com/Nithe14/pam_oauth2_device
