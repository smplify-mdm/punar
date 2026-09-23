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
| **punard** | root | Enroll/unenroll, fetch and load policy through the M4 loader, reconcile, build the category-states-only compliance and inventory bodies, write audit and `status.json` | Hold the device key; speak TCP | Serves `/run/punard/punard.sock`; dials `/run/punar-smplifyd/api.sock` (compiled default, `PUNAR_CONTROL_PLANE_SOCKET` overrides) | unchanged; `After=punar-smplifyd.service`, never `Requires` (SPEC §55: cached policy enforces with the agent down) |
| **punar-smplifyd** | `punar-smplifyd`, no capabilities | Generate key + CSR, redeem the code, hold cert/CA/pinned tenant key, forward exactly the bodies punard hands it | Mutate the OS; call any punard method; act on a server command; gather anything | Serves NDJSON on `/run/punar-smplifyd/api.sock` 0600, `SO_PEERCRED` uid 0 only; outbound HTTPS with platform roots, TLS ≥ 1.2, client cert | `punar-pimd@`'s set: `CapabilityBoundingSet=`, `ProtectSystem=strict`, `StateDirectory` 0700, `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service` |
| **punarctl** | root | `enroll start <domain> [--code-stdin]`, `enroll status`, `enroll stop` | Put the code on argv | punard socket | fixed argv |
| **System Control › Organization** (slice 2) | session | Domain, visibility panel, code entry, re-auth, then fixed-argv `punarctl … --code-stdin` | Be a second control plane | `status.json` over inotify | ticket path, like `policy.set` |

**Method mapping.** `org.discover {domain}` → root-owned pin
`/etc/punar/smplify/<domain>.json`, else
`https://<domain>/.well-known/smplify-management.json`; the document keeps
the mock's `org.json` shape and adds `enrollment.server`.
`enroll.register {device_id, bootstrap, code}` → resolve (five keys) →
`POST /enroll` (`Bearer <code>`, CSR `CN=device-pending`, no SAN,
`machineId` = Punar `device-id`) → identity stored 0600 → first check-in pins
`tenantPublicKeyX509Base64` → answers `{device_token, attestation: "none",
organization}`; the device token is random, and only its SHA-256 is kept.
`policy.fetch` → `GET /devices/{id}/bundle`: 204 and any bundle without a
Punar payload both answer `{policies: []}` (slice 2 adds the signed
`punar-policy` payload). `compliance.report` / `inventory.report` → `POST
/devices/{id}/status` carrying the states as `facts` and the OS triple as
`systemInfo.os` — nothing else. `queries.*` → empty until the backend has
`punar-query`. `recovery.*` → `out_of_scope`. `enroll.unregister` → wipes the
identity; punard's `enroll.stop` calls it best-effort and continues offline.

**Error mapping.** 401/403 on `/enroll` → `unauthorized` ("the enrollment
code was not accepted"); 409 → `denied`; 404 on a device path →
`not_found`; transport and 5xx → `internal` with the server's own message.
The agent's HTTP budget is 4 s inside punard's 5 s per call; nothing
long-polls inside a call.

## 3. Conditions that are not negotiable

- **Category states only** (SPEC §24/§54): the bodies are built only by
  punard's `compliance_report_body` / `inventory_body`; the agent adds the
  OS triple already in the inventory and a heartbeat, nothing more.
- **No localhost TCP control surface** (SPEC §61, milestone-5 §4.2): both
  sockets are UDS; the agent's HTTP is outbound only.
- **Explicit, audited enrollment**: nothing at first boot; `enroll.start`
  stays root-or-ticket, all-or-nothing, audited; no automatic `enroll.stop`.
- **The code never touches argv, audit, logs or a result**: punarctl reads
  it from stdin or a terminal with echo off; punard carries it as `Redacted`
  for the one register call.
- **Remote commands**: none honoured in slice 1. Backend device commands are
  unsigned, so a remote `unenroll` is refused until it carries a signature
  by the pinned tenant key.
- **Shipping preconditions on the Smplify side** (Phase 0 below): Punar is
  not enrolled into a deployment that does not verify device identity in
  the application layer.

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
  organisation can see" panel generated from the transport manifest; the
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
