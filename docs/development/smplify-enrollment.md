# Built-in Smplify enrollment — decision record and plan

> **Status (2026-09-23): DECIDED, slice 1 in progress.** The owner delegated
> the architecture decision with two constraints: security and privacy are
> not negotiable, and ease of use is primary. This document records the
> decision, the evidence it rests on, and the plan. It is staged into the
> image at `/usr/share/doc/punar/smplify-enrollment.md` because
> `punar-smplifyd.service` and `punar-smplifyd.socket` cite it.

## 1. Decision

Punar ships **`punar-smplifyd`**, a built-in Smplify device agent written in
Rust, in every image. It is *identity and transport only*: it generates the
device key, redeems the enrollment code for a certificate, and carries
punard's existing control-plane calls (`docs/api/ipc.md` §5.9–5.11 — the
nine-method NDJSON contract the dev/CI mock speaks) to Smplify's Linux device
API over mutually authenticated TLS. It reads five `os-release` keys and the
hostname, applies nothing, decides nothing, and answers only root on its own
socket.

**punard remains the single process that mutates the OS, the only caller (it
dials the agent, never the reverse), the owner of the enrollment state
machine, every report body, every audit event and every surface a person
sees.** Enrollment is by *entering a code* first (the organisation-issued
Smplify enrollment token, pasted into System Control or typed at a hidden
`punarctl` prompt); *signing in with credentials* follows on the Platform
SSO design (`docs/design/platform-sso.md` §412–430: an RFC 8628
device-authorization grant, never a credential typed into a Punar screen).

### Why not the Go `smplifyd`

The owner's instinct — reuse Smplify's system-level agent — was judged by a
three-design panel (adapter / stock run-loop / identity-and-transport) and
the identity-and-transport shape won on every lens. But that shape compiles
out everything the Go agent does except key, CSR, mTLS and HTTP, and what
remains is a few hundred lines. Doing those lines in Rust keeps one
toolchain, one CI, the hardening model `punar-pimd@.service` already proves,
and `rustls` with the verifier ADR-011 already pins — and it does not
inherit the agent's debt, which the read-only audit found to be material:

| # | In the Go agent today | Evidence (`Smplify-Linux/agent`) |
|---|---|---|
| 1 | Every 30 s status push ships serial, machine-id, FQDN, IPs, MACs, gateway, DNS, the full package list and `~/.local/bin` paths | `cmd/smplifyd/main.go:604-617`; `internal/systeminfo/systeminfo.go:549,987,1039-1068,1634-1660` |
| 2 | Tenant signing key overwritten from every check-in; TOFU from the manifest when empty | `main.go:383-388`; `internal/bundle/verify.go:82-86` |
| 3 | Only `manifest.json` is signed; `playbookSha256` is never checked | `verify.go:61-95` |
| 4 | `--insecure-skip-tls-verify` persisted to `config.yaml` forever | `main.go:127,174`; `internal/config/config.go:44` |
| 5 | Certificate-load failure falls back to an unauthenticated bearer client | `main.go:297-307` |
| 6 | Root unit with `NoNewPrivileges=false`, `ProtectSystem=false` | `packaging/systemd/smplifyd.service:35-51` |
| 7 | Reconciliation is `ansible-playbook` as root; Ansible leaks into config, reporter and packaging | `internal/reconciler/ansible.go:43-54` |
| 8 | Uncommitted 2 200-line working tree, no tag, no `vcs.revision` in any shipped binary | `git status`; `go version -m` |

Plus three feasibility costs the Rust choice removes: a Go toolchain in three
offline, snapshot-pinned image builders; CI credentials for a private
repository; and an unknown Go runtime under `MemoryDenyWriteExecute=yes`.

From the backend's point of view the difference is invisible: `punar-smplifyd`
performs the same `/os-identifiers/resolve` → `/enroll` (token + CSR) →
`/devices/{id}/checkin` sequence and speaks over the same device certificate.

## 2. The architecture

| Process | Runs as | May do | May not do | Transport | Hardening |
|---|---|---|---|---|---|
| **punard** | root | Enroll/unenroll, fetch and load policy through the M4 loader, reconcile, collect and build the compliance body (category states only) and the inventory body (the tier's device facts, §3.2), keep the record of what was sent (§3.3), check that the agent answers on every pass while enrolled (§3.4), write audit and `status.json` | Hold the device key; speak TCP; start, stop or enable a unit | Serves `/run/punard/punard.sock`; dials `/run/punar-smplifyd/api.sock` (compiled default, `PUNAR_CONTROL_PLANE_SOCKET` overrides) | unchanged; `Wants=` and `After=punar-smplifyd.socket` (and `After=` the service, so it stops first at shutdown), never `Requires` (SPEC §55: cached policy enforces with the agent down) |
| **punar-smplifyd** | `punar-smplifyd`, no capabilities | Generate key + CSR, redeem the code, hold cert/CA/pinned tenant key, translate the bodies punard hands it through a fixed allowlist (§3.3) and answer with exactly what it sent | Mutate the OS; call any punard method; act on a server command; gather anything; run on a device that never enrolled | Serves NDJSON on the listener `punar-smplifyd.socket` passes it (`/run/punar-smplifyd/api.sock`, root 0600 in a 0700 directory), `SO_PEERCRED` uid 0 only; outbound HTTPS with platform roots, TLS ≥ 1.2, client cert | `punar-pimd@`'s set: `CapabilityBoundingSet=`, `ProtectSystem=strict`, `StateDirectory` 0700, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service`; started by its socket, never enabled, resident only while it holds an identity, a manual stop refused (§3.4) |
| **punarctl** | the device's administrator (a `punar` group member), or root | `enroll start <domain> [--code-stdin] [--accept-non-removable] [--accept-organization-owned]` (asks for the code, then the person's password, relayed to `punar-authd` for a single-use ticket; the organization's terms — not removable, §3.1; owned by the organization, §3.2 — are shown together in one prompt and must be accepted), `enroll status`, `enroll stop` (the same password confirmation; refused for a non-removable enrollment, §3.1) | Put the code or the password on argv; decide authorization itself | punard socket; `punar-auth --admin` over a pipe | fixed argv |
| **System Control › Organization** (slice 2) | session | Domain, visibility panel, code entry, re-auth, then fixed-argv `punarctl … --code-stdin` | Be a second control plane | `status.json` over inotify | ticket path, like `policy.set` |

**Method mapping.** `org.discover {domain}` → root-owned pin
`/etc/punar/smplify/<domain>.json`, else
`https://<domain>/.well-known/smplify-management.json`; the document keeps
the mock's `org.json` shape and adds `enrollment.server`, and may carry the
organization's removal term `enrollment.removable` (§3.1) and its ownership
term `enrollment.ownership` (§3.2), which the agent passes to punard
untouched.
`enroll.register {device_id, bootstrap, code}` → resolve (five keys) →
`POST /enroll` (`Bearer <code>`, CSR `CN=device-pending`, no SAN,
`machineId` = Punar `device-id`) → identity stored 0600 → answers
`{device_token, attestation: "none", organization}`; the device token is
random, and only its SHA-256 is kept. The first check-in, which pins
`tenantPublicKeyX509Base64`, is the first compliance report's.
`policy.fetch` → `GET /devices/{id}/bundle`: 204 answers `{policies: [],
assignment: "none"}`, the one answer that lets punard withdraw an
organization's policy; a bundle without a Punar payload answers
`{policies: [], assignment: "unusable"}`, which punard holds, keeping the
policy it enforces (docs/api/ipc.md §5.6, §5.9). The two must never look
alike: one unreadable bundle would otherwise wipe the organization's policy
on its next refresh. punard now asks on every reconcile pass while enrolled,
so this is one `GET` per device every two minutes, the rate of the
compliance POST. Slice 2 adds the signed `punar-policy` payload, and with it
the rule that a payload which fails its signature check is an **error**
(punard records `refused` and keeps its policy), never an empty list. `compliance.report` / `inventory.report` → `POST
/devices/{id}/status`: the compliance states as `facts`, and the inventory
translated key by key into `systemInfo` (§3.3) — nothing else. Both answer
punard `{sent: <the body posted>}`. `queries.*` → empty until the backend has
`punar-query`. `recovery.*` → `out_of_scope`. `enroll.unregister` → wipes the
identity locally (it asks Smplify nothing, so it works offline) and the agent
goes dormant; with `any_identity: true`, which punard sends only while it
holds no enrollment and under its enrollment guard, whatever is held goes,
the token's identity or not. `enroll.stop` never waits on it, and punard
keeps its release record and the device token until the agent confirms the
wipe, asking again on every pass (§3.4).
`identity.status` → local as well: punard's liveness call on every pass while
enrolled (§3.4).

**Error mapping.** 401/403 on `/enroll` → `unauthorized` ("the enrollment
code was not accepted"); 409 → `denied`; 404 on a device path →
`not_found`; transport and 5xx → `internal` with the server's own message.
The agent's HTTP budget is 4 s inside punard's 5 s per call, and it is the
budget of the whole call, however many requests it makes: an answer that
reaches punard late reads as "unreachable" even when Smplify kept the
report, and the inventory would be uploaded again on every pass.
`enroll.register` has its own: resolve and `/enroll` share one 12 s
deadline (resolve may spend a third), and punard waits 14 s for it. A
registration punard gave up on would be worse than a resent report:
Smplify keeps the record `/enroll` created and refuses a second active
record for the same machine, so the device could not enroll again until an
administrator removed the stale one. The budgets are
`crates/punar-smplifyd/src/budget.rs`, and punard's tests hold each of its
timeouts (`call_timeout`) a second above them. So
`inventory.report` makes one request. The check-in that pins the tenant
key rides only `compliance.report` (sent first on every pass), with a 4 s
budget of its own, since three round trips over a satellite or poor
cellular link need that much, and the status POST keeps its 4 s; punard
waits 9 s for a compliance report. A check-in that fails is not tried again
for a minute, then two, doubling to 30 minutes, so one that cannot succeed
does not cost every pass; once a status POST gets through after one that
did not, the link is back and the next report tries it at once. The status
POST gets its 4 s or what is left of the call's whole budget, measured from
the call's start, whichever is less, and a name lookup is given up on at the
request's budget, so a slow check-in never pushes a stored report past
punard's wait. Every read and
write, the TLS handshake's included, waits only for the time left, so a
server that never answers costs one budget. Nothing long-polls inside a
call.

## 3. Conditions that are not negotiable

- **What leaves is decided on the device, and fixed** (SPEC §24/§54). punard
  builds both bodies (`compliance_report_body`, `inventory_body`): the
  compliance report carries category states only, the inventory the device
  facts its tier allows (§3.2). The agent gathers nothing. It translates
  the inventory through a fixed allowlist (§3.3), adding only a heartbeat,
  `supportedActions: []` and its own build constants, and punard keeps the
  body that left so the person can see it.
- **No localhost TCP control surface** (SPEC §61, milestone-5 §4.2): both
  sockets are UDS; the agent's HTTP is outbound only.
- **Explicit, audited enrollment**: nothing at first boot; `enroll.start`
  stays root-or-ticket, all-or-nothing, audited; no automatic `enroll.stop`.
  A person is never root on a Punar device, so the ticket is the path: the
  code, then the person's own password, as a Mac asks for an administrator's
  (ipc.md §5.9). AI agents are refused at any uid, before the ticket is spent.
  Unenrolling takes the same confirmation, so a person who enrolled can also
  leave — unless the organization enrolled the device as not removable, with
  that person's explicit yes (§3.1), the Punar analogue of a non-removable
  MDM profile.
- **The code never touches argv, audit, logs or a result**: punarctl reads
  it from stdin or a terminal with echo off; punard carries it as `Redacted`
  for the one register call.
- **Remote commands**: none honoured in slice 1. Backend device commands are
  unsigned, so a remote `unenroll` is refused until it carries a signature
  by the pinned tenant key.
- **Shipping preconditions on the Smplify side** (Phase 0 below): Punar is
  not enrolled into a deployment that does not verify device identity in
  the application layer.

### 3.1 Who may unenroll — decided 2026-09-24

A person is never root on a Punar device (onboarding.md §1.6), so once
`enroll.stop` accepts a person's password confirmation, the local
administrator can unenroll. Opening that path was only acceptable with a
rule the organization controls. The first version (5a66f48) let an
organization keep its device by turning local policy editing off
(`spec.security.localAdmin.policyEditing: denied`). It was replaced the same
day, for four reasons:

- It tied two decisions to one switch.
- It arrived with the policy fetch, so a tenant that had assigned nothing yet
  could not keep its device.
- Any later fetch could make a person's device non-removable without their
  consent. Nothing proves the organization owns the hardware, and that
  breaks the privacy rule.
- It exempted root.

**Decision.** The organization decides, at enrollment, whether the
enrollment can be undone from the device. If it can, the device's
administrator undoes it with their password. If it cannot, nobody on the
device can, and the person enrolling had to say yes to that first.

1. **The term.** The organization document carries
   `enrollment.removable` (boolean). punard reads it once, in `enroll.start`
   after `org.discover` and before `enroll.register`, and fixes it in
   `enrollment.json` beside `remote_query_scopes`. It is never re-read from
   a policy fetch, and the live policy refresh never calls `org.discover`:
   it writes only the policy fields of `enrollment.json`, through one
   function that has no way to name a term. Policy arrives after enrollment
   and may legitimately be empty, so a term carried there would be absent
   in exactly the window it matters, and would move with every fetch. Fixed
   at enrollment, an organization cannot tighten it after the person
   agreed, and a confused control plane cannot loosen it. `punar-smplifyd` passes the document
   through untouched.
2. **Absent means removable.** An organization that states no term has no
   opinion, and the device's owner administers the device; an ordinary
   enrollment asks nothing more. That is the reading
   `spec.security.localAdmin` gets, and Apple's default for
   `is_mdm_removable`. A value that is present but not a boolean refuses
   enrollment (`invalid_params`). An organization that tried to state a term
   this device cannot read never gets the permissive reading.
3. **Removable: the administrator unenrolls with their password.**
   `enroll.stop` takes the same single-use `punar-authd` ticket as
   `enroll.start` and `policy.set`. Root needs none. AI agents are refused at
   any uid, and their ticket is left unspent. The control plane is asked to
   forget the device (`enroll.unregister`, best effort). The unenroll is
   audited to the person who confirmed it.
4. **Non-removable: the person's explicit yes, then nobody.** Punar has no
   Automated Device Enrollment: no reseller or Apple Business Manager vouches
   that an organization owns this hardware. So an organization cannot make a
   device non-removable on its own word. The enrolling person must accept the
   term: `accept_non_removable` on the wire, `--accept-non-removable` in a
   script, or `accept` typed at punarctl's prompt, which shows the term. It
   is checked after discovery and before register, so the organization never
   hears of a device whose user said no. Once enrolled, `enroll.stop` refuses
   **every** local caller, root included. The refusal comes before the ticket
   is asked for, so nobody types a password only to be told no.

**Why the consent follows the first password.** The term lives in the
organization's document. punard fetches nothing for a caller who has not
confirmed who they are: the ticket is spent before any control-plane call.
Asking before the first password would take a pre-flight discovery on
behalf of an unconfirmed caller, which is the thing that ordering exists to
prevent. So a person meets a non-removable organization as: code, password,
the term, `accept`, password again. The first password pays for the lookup,
and nothing is registered until the second. Scripts pass the flag and see
the term only in the refusal that asks for it.

**What this does not hold:**

- **It is not a boundary against someone who is already root by another
  route.** Such a caller can delete `enrollment.json`. Punar gives no person
  root, so the term binds every account on the device, but it is not
  tamper-proofing.
- **A release that predates the term cannot enforce it.** `/var` is shared
  across releases and never rolled back, and a person can boot the one
  release retained on the ESP (`update rollback`, decision 24, or the boot
  menu). If that release predates the term, it applies its own unenroll rule.
  Every released Punar before this one lets only root unenroll, and no person
  is root, so no released build ends a non-removable enrollment either. The
  term also survives such a boot. An older punard rewrites `enrollment.json`
  without the field on its next sync, but the term is kept in
  `enrollment-terms.json` as well, bound to the enrollment by organization
  and enrollment time. Older builds never rewrite that file, and this build
  folds it back in on load; it can only take removability away. The
  organization's control over which releases a device runs is the channel's
  minimum-version admission. That keeps a pre-term release from being
  *installed*, but cannot stop the single retained previous release from
  booting.
- **Erasing and reinstalling ends any enrollment.** Nothing binds the
  hardware to the organization across a disk wipe; there is no Activation
  Lock equivalent. An organization that needs that needs firmware-level
  binding, and Punar does not claim it.
- **An organization cannot yet release a non-removable device remotely.**
  Backend device commands are unsigned, and slice 1 honours none (above).
  Until a remote `unenroll` carries a signature by the pinned tenant key,
  erasing and reinstalling is the only exit. The refusal says so.
- **A local unenroll is local.** Offline, the organization sees the device
  go silent rather than a release. What it already received is not
  retracted.
- **System Control › Organization (slice 2) must show the terms before the
  password** — this one and ownership (§3.2), together. It shows the "what
  your organisation can see" panel, and it can pay for one lookup with the
  confirmation it already asks for. That is a condition of shipping slice 2.

**What an enterprise reviewer can verify.**

- The organization document it publishes.
- On the device: `enroll.status.removable`, and every refused unenroll in
  the audit trail (`action: "enroll.stop"`, `decision: "deny"`,
  `details.reason: "enrollment_not_removable"`).
- The tests in `crates/punard/tests/enroll.rs`:
  - A person unenrolls a removable enrollment only with their own fresh
    ticket, spent once.
  - A non-removable one needs the person's yes before register, and then
    refuses person and root alike, across a restart.
  - An unreadable term refuses enrollment before register.
  - An agent is refused at any uid without burning the ticket.

### 3.2 Who owns the device, and what the organization receives — decided 2026-09-24

Nothing proves that an organization owns the hardware it enrolls (§3.1
item 4). So how much a device reports is a second enrollment term, and the
enrolling person accepts it the way they accept the removal term.

**What punard's inventory carries** (exact keys: milestone-5.md §6):

- **Every managed device**, with no further consent. The release (`os`:
  id, name, version, `IMAGE_ID`, `IMAGE_VERSION`, architecture; the kernel
  release). Security posture as states: Secure Boot, UEFI, TPM presence and
  version, whether it is virtual, disk encryption, firewall, patch status,
  reboot required. Hardware facts: manufacturer, model, BIOS version, CPU
  model, vendor, cores and threads, memory, capacity rounded to whole GB,
  root filesystem type, whether a battery is present. And the applications
  built into the image: Punar's first-party apps at `IMAGE_VERSION` and the
  image's browser at its package version. Those are identical on every
  device of a release, so they say nothing about the person.
- **An organization-owned device**, additionally. Its serial number (SMBIOS
  `product_serial`, or the device tree's `serial-number`), and every
  application installed for all users: the system Flatpaks and the catalog
  vendor apps.
- **Never, in any tier.** Anything under `/home` or belonging to one
  person: files, per-user apps, browser data. The AI registry, access
  ledger and detections. Addresses of any kind (IP, MAC, gateway, DNS),
  network names, Bluetooth, USB history, timezone or location. User names,
  UIDs, logins and sessions. Uptime, boot time, battery level and usage
  samples. `/etc/machine-id`, the base OS packages, audit contents,
  processes and command lines, and secrets. On a personal enrollment, the
  applications the person chose are never sent.

punard's body carries neither the hostname nor any capability's value:
the resend gate hashes the body, so a value that is never sent must not be
in it, or changing it would send an inventory at the moment it changed. The
milestone-5 `capabilities` list names each capability and whether it is
supported, and nothing else. punar-smplifyd translates the body through a
fixed allowlist and gathers nothing itself (§2): it sends the hostname
once, at `/enroll`, and no capability value at all. The exact keys Smplify
receives per tier are §3.3.

**Decision.**

1. **The term.** The organization document carries `enrollment.ownership`:
   `"personal"` or `"organization"`. punard reads it once, with the removal
   term, after `org.discover` and before `enroll.register`, and fixes it in
   `enrollment.json` as `organization_owned`. It is never re-read from a
   policy fetch, so an organization cannot claim a device after its user
   agreed to a personal enrollment.
2. **Absent means personal.** An organization that states no term gets the
   narrower tier, and an ordinary enrollment asks nothing more. The value
   must be exactly `"personal"` or `"organization"`; anything else refuses
   enrollment (`invalid_params`). Guessing personal would enroll a device
   its organization cannot manage as it said. Guessing organization would
   report more than anyone agreed to.
3. **Organization: the person's explicit yes.** The person accepts with
   `accept_organization_owned` on the wire, `--accept-organization-owned`
   in a script, or `accept` typed at punarctl's prompt. The prompt says
   plainly that the organization will also receive the device's serial
   number and the list of every app installed for all users. The
   organization chooses its own name, so punard cleans it once, where it
   reads the document: control and invisible format characters (direction
   overrides, zero-width characters) dropped, every kind of whitespace,
   line separators included, one space, and at most 64 characters, the cut
   shown. The prompt shows it quoted on a line of its own; each term's
   meaning, and every row that states a term, is fixed text that never
   contains it; and a terminal replaces anything that could still steer it
   with U+FFFD. The name it chose cannot conceal, reorder or argue with the
   term beside it. The check
   comes before register, so the organization never hears of a device whose
   user said no, and nothing about it is sent.
4. **Both terms, one question.** When an organization sets both terms, one
   refusal names both (`details.terms`, docs/api/ipc.md §5.9 step 6), and
   punarctl asks about both in one prompt that says what each means. A
   person answers once and types their password once more; a script passes
   both flags. The removal term alone is refused exactly as before.
5. **No second record.** The removal term is also kept in
   `enrollment-terms.json`, because an older punard that dropped it would
   read the device as removable. Ownership fails the other way: an older
   punard that rewrites `enrollment.json` without `organization_owned`
   reads it as `false`, the narrower tier. A lost record can only send
   less, so the field alone is enough.

**What this does not hold:**

- **It is a claim the person accepted, not proof.** A person who accepts on
  a device they bought themselves gives the organization its serial number
  and app list. The prompt says so; it cannot know who paid for the
  hardware.
- **The organization keeps what it received.** Unenrolling stops future
  reports. It does not retract a serial number or an app list already sent,
  and Smplify keeps the last values it stored.
- **Ownership is fixed for the life of the enrollment.** Neither side can
  change it later. Changing it means unenrolling and enrolling again, and a
  non-removable enrollment cannot be unenrolled from the device (§3.1).

**What an enterprise reviewer can verify.**

- On the device: `enroll.status.organization_owned`, and the Ownership row
  of `punarctl enroll status` and of the enrollment receipt.
- The tests in `crates/punard/tests/enroll.rs`:
  - An organization's claim without the person's yes is refused after
    discovery and before register, and nothing is sent.
  - With it, the inventory adds `identifiers.serial_number` and the
    system-wide applications, and nothing else.
  - `"personal"`, or no term, sends no identifiers and only the image's own
    applications.
  - An unreadable term refuses enrollment before register.
  - Both terms are named in one refusal, and each flag accepts only its own
    term.

### 3.3 The visibility manifest — what Smplify receives, decided 2026-09-24

Everything below is `POST /api/v1/linux/mdm/devices/{id}/status`. It is
composed in one place, `crates/punar-smplifyd/src/status.rs`, from punard's
inventory and compliance report; a key not named there never leaves.

**Compliance** (every sync pass): `facts.punar_compliance_overall` and one
`facts.punar_compliance_<capability>` per registered capability, each a
state word. Never a value.

**Inventory** (at enrollment, when it changes, and at least once a day):

| Smplify key | From punard | Tier |
|---|---|---|
| `systemInfo.os.name` | "Punar OS" on a Punar image, else `PRETTY_NAME` | every |
| `systemInfo.os.version` | `IMAGE_VERSION`, else `VERSION_ID` | every |
| `systemInfo.os.kernelRelease` | the kernel release | every |
| `systemInfo.os.arch` | the package architecture | every |
| `systemInfo.hardware.secureBoot`, `uefi`, `tpmPresent`, `tpmVersion`, `isVirtual`, `virtualization` | posture | every |
| `systemInfo.hardware.manufacturer`, `modelName`, `biosVersion`, `cpuModel`, `cpuVendor`, `cpuCores`, `cpuThreads`, `memoryTotalBytes`, `deviceCapacityBytes` (whole GB), `rootFilesystemType`, `batteryPresent` | hardware | every |
| `systemInfo.security.diskEncryptionEnabled`, `firewallEnabled`, `firewall` (`"nftables"`), `osPatchStatus`, `rebootRequired` | posture | every |
| `systemInfo.software.smplifydVersion`, `smplifydRevision`, `smplifydBuildDate` | the agent's own build, not the device | every |
| `systemInfo.software.installedPackages` (`{name, displayName, version, source, managed}` rows), `installedPackagesHash`, `installedPackagesCount` | applications: the image's own (`source: "punar-image"`) | every |
| the same list, adding `source: "flatpak"` and `"punar-vendor"` rows | every system-wide application | organization-owned |
| `systemInfo.hardware.serialNumber` | `identifiers.serial_number` | organization-owned |
| `supportedActions: []` | slice 1 honours no remote command | every |

**Patch posture is device state — decided 2026-09-24.** `osPatchStatus` and
`rebootRequired` come from the device's staged update and nothing else
(`patch_posture` in `crates/punard/src/inventory.rs`). A release staged and
waiting for a restart reads `"updates-available"` with a reboot required;
otherwise the status is `"unknown"` and no reboot is required. Today only a
person stages a release (`punarctl update apply`); nothing updates on its own
schedule. The inventory changes when a release is staged and again when the
device restarts into it, and each change is sent within one pass. So the
organization sees, to within two minutes, when an update was staged and when
the device began running it.

The owner accepts that as posture an organization may see, as every MDM
reports pending updates and a required reboot. It is not a privacy leak:
it reflects the device's update state (whether the device runs the release
it has installed), not what the person does with the device. A person's own
check changes nothing: nothing from `punarctl update check` feeds the
status, so it stays `"unknown"` whether or not anyone looked. Only a change
to the device itself moves it. Whether and when anyone checked for updates,
and what a channel check found, never leave.

**Never, in any tier:** a `network` or `identity` section; the hostname
(sent once, at `/enroll`); any capability's value (the hostname string, the
timezone); timezone, uptime, boot time or `machineId`; addresses of any
kind, network names, Bluetooth or USB history; user names, UIDs, logins and
sessions; anything under `/home` or belonging to one person, per-user and
browser data, the AI registry, ledger and detections; battery level and
usage samples; base OS packages; audit contents, processes and command
lines; secrets. On a personal enrollment, an application the person chose.

**How the translation holds that line:**

- **Types.** Smplify reads a typed column only from a JSON boolean or
  number; `"true"` is dropped. Booleans and counts are coerced (the exact
  strings `"true"`/`"false"` and digit strings), and anything else is
  `null`. Counts past the receiving column (`int` for cores and threads,
  `bigint` for bytes) are `null`.
- **Every value fits its column.** Smplify writes the typed columns inside
  the transaction that stores the whole report, so one value too long fails
  the entire write. `modelName`, `os.version` and `kernelRelease` are cut to
  100 characters, `os.name` to 128, other text to 255.
- **Unknown is `null`.** `null` keeps what Smplify stored; a placeholder
  would overwrite it. The substrate's `"unknown"` is therefore `null`,
  except for `osPatchStatus`, where `"unknown"` is the console's own word
  and replaces a verdict whose evidence expired. `firewall`, `tpmVersion`
  and `osPatchStatus` are closed vocabularies; architecture, filesystem and
  hypervisor names must be plain tokens; a serial number must be printable
  ASCII and is never repaired into a different one.
- **The application list is a complete snapshot.** Smplify deletes every
  row it does not see, and one malformed row discards the whole list. So
  every row is checked (a name, a text version, a known source, a boolean
  `managed`), names and display names are cut to 255 characters and
  versions to 100, and any bad row, more than 2,000 rows, or a body over
  512 KiB sends the list, its hash and its count as `null` ("no change").
  The list is never cut. punard applies the same caps first and audits the
  withholding (`enroll.inventory`); the agent does not rely on it.
- **Only the allowlist.** A key punard's inventory carries that this file
  does not name is not copied, including an unknown key inside a row.

**What the person sees.** The agent answers `inventory.report` with
`{sent: <the body posted>}`, and punard stores that body in
`/var/lib/punar/organization-view.json` (0640 root:`punar`, bound to the
enrollment, written only after a send succeeds, removed on unenroll).
`enroll.status.organization_view` lists its categories and the field names
that carried a value, and when it was sent (docs/api/ipc.md §5.10);
`punarctl enroll status` renders them under "Your organization can see". It
is read from what left, not from this table, so it cannot show less than
was sent. Against the development mock, which returns no `sent`, the record
is the inventory the mock received (punard's body, which holds no hostname
and no capability value), and the person is shown exactly that.

**What an enterprise reviewer can verify.**

- `enroll.status.organization_view` and `organization-view.json` on the
  device.
- The tests in `crates/punar-smplifyd/src/status.rs`: exact key sets per
  section, nothing outside the allowlist, the serial only with
  `identifiers`, coercion, clamping, and a withheld (never shorter) list.
- `crates/punard/src/enroll.rs` and `crates/punard/tests/enroll.rs`:
  punard's real inventory through the agent's real translation, per tier,
  as exact key sets; the caps; the record of what was sent holds exactly
  the body Smplify received, and the summary exactly its non-null fields.

### 3.4 Dormant until enrolled — decided 2026-09-24

Punar is independent of Smplify: a personal device that never enrolls runs
no Smplify code. An enrolled device's agent is hard to stop, and every way
root can stop it is noticed and audited. Design and its adversarial review:
option D of the activation design, with the review's corrections.

**Lifecycle.**

- **Never enrolled.** systemd holds `punar-smplifyd.socket` (root 0600 in a
  0700 directory, `Accept=no`, `FileDescriptorName=api`, a manual stop
  refused, no `[Install]`); `punard.service` `Wants=` it. No agent process
  exists: punard calls the agent only for `enroll.start` and while enrolled.
  The CI image proves it at stabilized idle: `PUNAR_SMPLIFYD_PROCS=0` with
  the socket active is a release gate (`tests/performance/check-budgets.sh`).
- **`enroll.start`.** Its first call starts the agent through the socket. An
  enrollment that fails or is declined leaves nothing of an identity, and the
  agent exits with status 75 (`DORMANT_EXIT_STATUS`) after 30 s without a
  call. The unit treats 75 as a clean exit it does not restart
  (`SuccessExitStatus=`, `RestartPreventExitStatus=`), and the socket starts
  the agent again on the next call. A call queued while it exits is answered
  by the next instance.
- **Enrolled.** The agent stays resident while anything of an identity is in
  its state directory (the record, the key, a certificate, a file a crash left
  half written). It waits for calls with no timeout of its own, so it adds no
  wakeup. On an enrolled boot, punard's boot reconcile makes the first call.
- **Crash or kill.** `Restart=always` and `StartLimitIntervalSec=0`:
  restarted forever. `RestartSec=100ms`, doubling over `RestartSteps=5` to
  `RestartMaxDelaySec=5s`, because a new call does not bring a killed agent
  back any sooner: while a restart is pending systemd counts the service as
  starting and queues no earlier start, so the call waits out the delay. A
  killed agent therefore answers well inside punard's 10 s liveness wait, and
  an agent that cannot start at all (a missing or crashing binary) is
  restarted every 5 s at most, forever, which punard reads as
  `not_answering`. The socket's `TriggerLimitIntervalSec=10s`,
  `TriggerLimitBurst=20` bound only an agent that exits cleanly at once with
  calls queued; the socket then fails, punard reads `connection_refused` or
  `socket_missing`, and asks systemd to start the socket again on every pass
  (a masked socket stays stopped).
- **Unenroll.** `enroll.stop` first writes punard's release record
  (`identity-release.json`, durably), then asks the agent to wipe the
  identity (`enroll.unregister`, local, works offline); the agent answers and
  exits 75 at once. Unenrollment never waits on it, and never forgets the
  identity either: until the agent confirms the wipe, punard keeps the record
  and the device token, `enroll.status` and `status.json` say
  `identity_release: pending`, and every pass asks again; the confirmation is
  audited as `enroll.release` `success` (docs/api/ipc.md §5.11). An episode
  still open when the enrollment ends is closed with `enroll.agent` `ended`.
- **A registration that does not commit, or whose answer is lost.**
  `enroll.start` writes the same record, cause `registration`, before it
  calls `enroll.register`, because the agent keeps the identity Smplify
  issued before it answers: punard killed, the machine off or a connection
  broken during registration leaves an identity with the agent and nothing
  with punard but this record, and the next pass asks the agent to wipe
  whatever it holds. A registration that commits removes the record.
- **Only a record releases.** A device token found with no enrollment and no
  release record (someone deleted `enrollment.json`) is not an unenrollment
  waiting to finish: nothing ended the enrollment. punard keeps the identity,
  never asks the agent to wipe it (and so never starts the agent for it),
  audits `enroll.release` `kept` once (resource
  `agent.enrollment_record_missing`), and shows `identity_release: kept` in
  `enroll.status`, `status.json`, `punarctl enroll status` and the shell's
  Enrollment pane. A new enrollment replaces it.

**Who can stop it, and how each path is noticed.** No person is root and
nobody holds a manage-units grant (onboarding.md §1.6; the Punar polkit rules
grant only power actions), and an AI agent is refused by punard at any uid.
What is left is another root process:

| Path (as root) | What happens | What punard sees on its next pass |
|---|---|---|
| `systemctl stop` or `restart` of the service or the socket, `disable --now` | refused (`RefuseManualStop=yes`); nothing is enabled to disable | nothing: the agent keeps running |
| `kill -TERM`, `kill -KILL`, `systemctl kill` | restarted after 100 ms (backing off to 5 s when it keeps failing) | a call in flight: `connection_reset` or `closed_without_answer`; the next call waits for the restart and is answered |
| `kill -STOP`, `systemctl freeze` | stays `active`, never answers | `not_answering` (the liveness call gets no answer in 10 s) |
| `mask`, then `stop`; a runtime drop-in lifting `RefuseManualStop=` | stopped | `socket_missing`, `connection_refused` or `connection_reset`, and punard asks systemd to start the socket again; once anything answers, `unit_modified` while the mask or drop-in stays |
| any drop-in or override in `/etc` or `/run` on the agent's units, punard's or the reconcile timer's and service's (`systemctl edit`, `set-property`, an `ExecStart=` replaced, an `Environment=` pointing punard elsewhere, a moved state directory) | whatever it does | `unit_modified`: every pass while enrolled compares systemd's loaded units with the image's (fragment in `/usr/lib/systemd/system`, no drop-in outside it, not masked, the socket listening where punard dials, the agent's process running `/usr/bin/punar-smplifyd`); `enroll.start` refuses to send anything through such units |
| `PUNAR_CONTROL_PLANE_SOCKET` or `--control-plane-socket` for punard, by any means | refused on every image without the development control plane: punard dials the agent anyway | `enroll.agent` `denied` (resource `agent.control_plane_override`) at punard's start; a drop-in that sets it is also `unit_modified` |
| another program binding its own socket at the agent's path | it answers whatever it answers | `unexpected_listener` before anything is sent: the listener's credentials must name PID 1, as every socket-unit listener does |
| a target with `Conflicts=` on it | stopped until the next call starts it again | the agent back, or `socket_missing` if the socket went too |
| delete `device.json` and leave the key | the agent keeps running | `identity_missing` |
| delete every identity file | the agent goes dormant 30 s later | `identity_missing`: the next call starts it, and it holds none |
| an identity punard did not register | the agent answers for it | `identity_mismatch` |
| delete punard's `device-token` and restart punard | punard cannot ask about or report on this device | `token_missing` (nothing is sent) |
| delete `enrollment.json` (and its terms) and restart punard | punard no longer enforces or reports for the enrollment; the organization's policy files stay in `policy.d` as foreign files | the identity is kept, not released: `enroll.release` `kept` once, `identity_release: kept` everywhere the enrollment is shown |
| another program answering on the agent's socket with anything but this device's identity | whatever it says | `unexpected_answer` (the liveness call fails closed) |
| an agent that cannot start (a missing or broken binary) | restarted every 5 s at most, forever | `not_answering` |
| `systemctl stop` or `restart` of punard, or of the reconcile timer | refused (`RefuseManualStop=yes` on both) | nothing: passes go on |
| kill punard | restarted after 1 s (backing off to 30 s), no start limit | the gap, if any, when passes resume |
| mask the timer or punard and stop them, `systemctl isolate rescue.target`, a target that stops them | no passes run, so nothing is checked meanwhile | when passes resume, on this boot or at the next one after a clean shutdown: `enroll.gap` (passes further apart than three timer periods and a minute, suspend excluded); a mask or drop-in still in place is `unit_modified` |

**How it is noticed.** Every reconcile pass while enrolled first calls
`identity.status`, before the policy fetch, and the agent answers it from
one file read. The check fails closed: the only answer that means the agent
is there and is this device's is `enrolled: true` with `token_matches: true`.
Any failure of the agent's own socket (a connect error of any kind, a reset,
a connection closed before the answer, no answer in 10 s to a call that
needs no network) is `AgentUnavailable`, never the network, and so is an
agent that answers that it holds no identity, or not this device's, an
answer the agent never gives (`unexpected_answer`), and a device token
punard no longer holds (`token_missing`). While it lasts nothing more is
sent that pass, the policy is not fetched and the reports stay pending; a
report or fetch the agent's socket fails later in the same pass starts the
episode just the same. None of it is recorded as a network outage: no
`enroll.sync` `unreachable`, no `enroll.policy` `unreachable`, and
`last_sync` keeps the last sync that was attempted. One `enroll.agent` audit event
with result `agent_unavailable` and resource `agent.<reason>` starts an
episode and one `success` event ends it; the episode is kept in
`enrollment.json`, so a restart neither repeats nor loses it. `status.json`
says `management: "interrupted"`, `enroll.status.management` gives the reason
and since when, `punarctl enroll status` prints "Management: Interrupted",
and the shell's Enrollment pane shows the same line. Refused stops leave no
journal line of their own (measured); what is audited is their effect.

**What it is not.** Tamper-evident against root, not tamper-proof: root can
still stop the agent and punard, and every way above is noticed and audited
when punard next runs a pass. What no process on the device can vouch for is
the operating system image itself: root that rewrites `/usr` (punard's own
binary, the vendor units, the agent's binary) or punard's state files can
make punard report whatever it likes, and so can a program that copies the
agent's key, runs as a systemd socket unit of its own on the agent's path
after the vendor socket's node is removed, and answers as the agent. The
organization's backstop for those is the device ceasing to check in, and
the audit log's history (an `enroll.start` with no `enroll.stop`); no alert
for missed check-ins exists on the Smplify side yet (§6).

**Measured, and not.** In a systemd 261 container with a stand-in and the
real unit: stops refused as root, kills restarted, `mask` then `stop`
succeeds, a frozen agent produces only timeouts, and a `RuntimeDirectory=` on
the service deletes the socket node when it stops (hence none). That a call
made while a restart is pending waits out `RestartSec=` is read from
systemd's source (a service in auto-restart counts as starting, and the
socket queues no start for it), not measured; neither is the kill-to-answer
time with the new delay. The agent's
resident cost while enrolled, and its activation latency under real socket
activation on the release image, are **unmeasured** until measured on an
enrolled device; the container's figures (about 1 MiB PSS idle, about 46 ms
from start to answer, measured outside socket activation) are not budget
numbers. `tests/images/smplifyd-activation-contract-test.sh` holds the units
to all of the above.

## 4. Smplify backend — Phase 0 (gating) and later

Verified by reading `manager-smp-1214/multi-module-mdm-project`. B0 and B3
landed on 2026-09-23 in the checkout the local Tilt backend is built from
(`com.smplify.mdm.manager`, branch `smp-1405-punar-phase0`, 8/8 tests) and
the local backend resolves `IMAGE_ID=punar-desktop` to `punar`; B1 and B4
remain the shipping gates.

| # | Change | Why | Est. |
|---|---|---|---|
| B0 | `EnrollmentCertificateAuthority` must verify the PKCS#10 self-signature before signing (today it signs `csr.getSubject()`/SPKI without `isSignatureValid`) | proof of possession | 0.5 d |
| B1 | In-app `LinuxDeviceClientCertFilter`: the presented certificate's SHA-256 must equal `LinuxDevice.clientCertFingerprint` on `/devices/{id}/**`; fail closed; the edge must forward the client certificate for `/api/v1/linux/**` (today the fingerprint is written at `/enroll` and never compared; Linux device paths are `permitAll`) | device identity | 3 d + edge |
| B2 | Local TLS edge for Linux device paths with `auth-tls-verify-client: on` | local proof | 1.5 d |
| B3 | Registry row for Punar: `{IMAGE_ID: punar-desktop}` (multi-key match is ANDed; the agent already forwards `IMAGE_ID`); can be added at runtime via `PUT /os-identifiers/{id}` | resolve | 0.5 d |
| B4 | Applicability gate at assignment and render: family `punar` accepts only `punar-policy` — a registry row alone gates nothing today | keep Ansible away from Punar | 2 d |
| B5 | `/enroll` 201 body gains `tenantId`, `tenantDisplayName`, signing key | pin at enrollment | 1 d |
| B9 | `punar-policy` payload kind: opaque signed envelope for punard, removal semantics, cross-signed key rotation on check-in, per-category compliance in the UI | real policy | 11 d |
| B10 | Short human code (`smp_<code>`, ≤ 24 h, single use, per-IP limited) | ease of use | 3 d |
| B11 | RFC 8628 device-authorization endpoints; `/enroll` accepts a user assertion; `enrolled_by` | credentials | 8 d |

**Inventory gaps (open, found 2026-09-24).** Found reading the backend
while mapping §3.3; none blocks Punar sending the manifest, but each limits
what the organization sees or can clear. Nothing here is verified against a
running backend except where it says so.

| # | Change | Why |
|---|---|---|
| B-A1 | An empty `installedPackages` must clear the device's Linux applications (`LinuxDeviceIndexerImpl` returns early on an empty list, contradicting the ingest's "an explicitly empty array replaces the prior inventory") | a device with nothing listed keeps its old rows |
| B-A2 | Honour `displayName` and `managed`: display name from `displayName`, key still from `name`; `managed` read instead of hardcoded `false` | the console shows ids, never a managed flag |
| B-A3 | Make `GET /devices/{id}/applications` (and so `smplify device apps`) see Linux applications, by indexing them into Elasticsearch as the Apple path does or reading the installed-apps table | the CLI stays empty however complete the list is; the console tab reads Postgres and fills |
| B-A4 | Isolate the application reconcile from the status write (its own transaction, or clamp lengths server-side) | a column overflow inside the `@Transactional` ingest plausibly aborts the whole status write (not verified) |
| B-P1 | A way to clear withdrawn data: typed columns use `COALESCE` and the JSON merge strips nulls, so a value is never cleared by a later report | a category a device stops sending, or an unenrollment, leaves the old values forever |
| B-U1 | Console: add `Manufacturer` and `ModelName` to `NAMED_KEYS` (they render twice today); show the `punar_compliance_*` facts, which are stored but have no reader (overlaps B9) | presentation |

## 5. Phases

- **Slice 1 (this branch):** `punar-smplifyd` crate, unit, service user,
  staging in all three lanes, enabled-units manifests, PSS unit list, dev
  drop-in keeping the mock as the CI oracle; punard `code` parameter and
  best-effort `enroll.unregister`; `punarctl enroll start … [--code-stdin]`
  with a hidden prompt; a lab (`tools/prepare-smplify-lab.sh`) that derives
  a disposable image trusting one local CA and pins the organisation
  document, so a VM on this Mac enrolls into the local Smplify over TLS.
  Owner test: paste a code, `punarctl enroll status` says enrolled, the
  device row appears in the manager with OS, kernel, last-seen and
  `punar_compliance_overall`; the bar shows the organisation.
- **Slice 2:** System Control › Organization page with the "what your
  organisation can see" panel, rendered from `enroll.status.organization_view`
  (the body that left, §3.3); the
  signed `punar-policy` payload end to end; certificate expiry in
  `enroll status`; in-VM CI stub (TLS over a Unix socket) and `m14-check`.
- **Slice 3:** short code; credentials (device-authorization); `punar-query`
  for remote queries; certificate renewal; recovery escrow through Smplify.

## 6. What the code could not answer

1. How `device_facts` surfaces in the manager UI (whether slice-1 compliance
   is visible or only stored).
2. The staleness sweep: whether a 120-s sync keeps a device `ENROLLED`.
3. Whether the production ALB forwards client certificates for
   `/api/v1/linux/**`, and which client-key algorithms it accepts (the
   agent uses P-256; RSA-2048 is the known-good path).
4. The exact rendered `/etc/os-release` of each lane (whether `VERSION_ID`
   is present on Arch and sid).
5. Whether Smplify alerts an administrator when a device stops checking in:
   the organization's only signal that root stopped the agent on a device
   (§3.4).
