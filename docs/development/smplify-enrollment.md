# Built-in Smplify enrollment — decision record and plan

> **Status (2026-09-23): DECIDED, slice 1 in progress.** The owner delegated
> the architecture decision with two constraints: security and privacy are
> not negotiable, and ease of use is primary. This document records the
> decision, the evidence it rests on, and the plan. It is staged into the
> image at `/usr/share/doc/punar/smplify-enrollment.md` because
> `punar-smplifyd.service` cites it.

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
| **punard** | root | Enroll/unenroll, fetch and load policy through the M4 loader, reconcile, collect and build the compliance body (category states only) and the inventory body (the tier's device facts, §3.2), keep the record of what was sent (§3.3), write audit and `status.json` | Hold the device key; speak TCP | Serves `/run/punard/punard.sock`; dials `/run/punar-smplifyd/api.sock` (compiled default, `PUNAR_CONTROL_PLANE_SOCKET` overrides) | unchanged; `After=punar-smplifyd.service`, never `Requires` (SPEC §55: cached policy enforces with the agent down) |
| **punar-smplifyd** | `punar-smplifyd`, no capabilities | Generate key + CSR, redeem the code, hold cert/CA/pinned tenant key, translate the bodies punard hands it through a fixed allowlist (§3.3) and answer with exactly what it sent | Mutate the OS; call any punard method; act on a server command; gather anything | Serves NDJSON on `/run/punar-smplifyd/api.sock` 0600, `SO_PEERCRED` uid 0 only; outbound HTTPS with platform roots, TLS ≥ 1.2, client cert | `punar-pimd@`'s set: `CapabilityBoundingSet=`, `ProtectSystem=strict`, `StateDirectory` 0700, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service` |
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
`policy.fetch` → `GET /devices/{id}/bundle`: 204 and any bundle without a
Punar payload both answer `{policies: []}` (slice 2 adds the signed
`punar-policy` payload). `compliance.report` / `inventory.report` → `POST
/devices/{id}/status`: the compliance states as `facts`, and the inventory
translated key by key into `systemInfo` (§3.3) — nothing else. Both answer
punard `{sent: <the body posted>}`. `queries.*` → empty until the backend has
`punar-query`. `recovery.*` → `out_of_scope`. `enroll.unregister` → wipes the
identity; punard's `enroll.stop` calls it best-effort and continues offline.

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
`inventory.report` makes one request; the check-in that retries pinning the
tenant key rides only `compliance.report` (sent first on every pass) with a
quarter of the budget, and its status POST gets what is left. Every read and
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
   a policy fetch. Policy arrives after enrollment and may legitimately be
   empty, so a term carried there would be absent in exactly the window it
   matters, and would move with every fetch. Fixed at enrollment, an
   organization cannot tighten it after the person agreed, and a confused
   control plane cannot loosen it. `punar-smplifyd` passes the document
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
