# Punar Execution Trust — design

**Status:** Design (proposed) · 2026-08-25 · **Owner:** `punard`
**Spec authority:** §45 (security through native OS primitives), §46
(application policy), §23 (shadow AI — *suspected, never certain*), §28
(approval gates), §60 (hard safety constraints), §61 (local IPC security),
§59.3/§59.6 (malicious local process, supply chain), §73 (every restriction
explains itself), §1.14 (no broad tracing where a scoped kernel primitive
suffices), §1.22 (honesty), §1.24/§1.25 (no deep forks, prefer upstream),
§6.2/§6.3/§6.4 (budgets), §74.4 (security tests).
**Binding prior contracts:** `docs/api/ipc.md` §1–§20 (M11 proposes §21–§23;
**this document proposes three new sections, numbered at merge time — see the
allocation note in §10.1**), `schemas/audit/approval.json`,
`schemas/audit/audit-event.json`, `schemas/desired-state/desired-state.json`,
`docs/development/milestone-7.md` (classification, cgroup attribution),
`milestone-9.md` (the approval engine, human-only resolution, the envelope
law), `milestone-10.md` (detection identity, the anti-nag rule, the alert),
`milestone-11.md` (`browser.policy`, the Chromium integration layer),
`docs/design/app-catalog.md` (**the shared `trustTier` / `containment`
vocabulary — §4 below and app-catalog §1.5 are one enum with two readers**),
`docs/design/DESIGN_LANGUAGE.md` (§2 colour semantics, §7 stroke and coverage
semantics, §8 unmanaged-first).

> **A machine that will run anything you were tricked into downloading is not
> a secure machine, and a machine that interrogates you about the compiler
> output you produced thirty seconds ago is not a usable one. Execution trust
> is the line between those two failures, and it is drawn at *foreign
> origin*, not at *unfamiliarity*.**

This document is a security design. It states what is enforced by the kernel,
what is advisory, what is simulated, and what Punar refuses to claim. Per
DESIGN_LANGUAGE §7, coverage is always `FULL` / `PARTIAL` / `UNSUPPORTED`
with a reason — silence is not support — and any mechanism outside the
operating production path is drawn **dashed**.

---

## 0. Claim register (spec §1.22 · design language §7)

**Nothing in this document is implemented.** The stroke rule applies to prose:
a solid claim is an operating path, a dashed claim is designed and unshipped.
This register exists so no sentence below can be read as a description of the
running system.

| # | Mechanism | Stroke | Where it stands (2026-08-25) |
|---|---|---|---|
| 01 | `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` in the pinned kernel | **solid** | Verified: Arch `linux` 7.1.10-arch1 `config.x86_64`. The primitive exists on the substrate Punar pins. |
| 02 | The M9 approval engine, human-only resolution, cgroup attestation | **solid** | Shipped by M9/M7 and reused unchanged; this design adds a fourth approval kind and no new authority. |
| 03 | The exec gate itself (`fanotify` thread inside `punard`) | *dashed* | §3. No code. `TO VERIFY` item V2 in §3.5 is the spike that can invalidate the design. |
| 04 | ADR-003's separate `/home` and `/var`, on which the mark set depends | *dashed* | Planned, unbuilt. The image is one root filesystem today. Hard prerequisite (§3.3, V3). |
| 05 | `packaged.db`, the ALPM hook, and the `system`/`curated` tiers as *gate verdicts* | *dashed*, and **descoped** | §4.1: under the shipped mark set they are almost never gate verdicts. They serve `trust check` and the surfaces. |
| 06 | Browser-written download provenance (`user.xdg.origin.url`) | **never** | Falsified 2026-08-25 (§5.1): Chromium's Linux `QuarantineFile()` is a no-op. Punar reads the xattr if some other tool wrote it and depends on it nowhere. |
| 07 | The `containment` axis in practice (Flatpak) | *dashed* | Arrives with [`app-catalog.md`](app-catalog.md); not in the MVP image. |
| 08 | IMA/EVM as a kernel-enforced `system` tier | **never**, on this kernel | `# CONFIG_IMA is not set`. Reaching it means owning a kernel build (§2, §14). |
| 09 | Protection against malware, a notary, or a local root | **never** | §12. Refusals, not roadmap. |

---

## 1. What macOS actually does, mechanism by mechanism

**Gatekeeper is not an antivirus; it is a consent gate on files of foreign
origin.** Everything Punar can honestly copy follows from understanding that
sentence precisely.

| macOS mechanism | What it actually enforces | Where the trust comes from |
|---|---|---|
| **Quarantine** (`com.apple.quarantine` xattr) | Nothing by itself. It is a *mark*, written by the downloading application through the Quarantine API, that makes Gatekeeper evaluate the file at first launch. Removable by the file's owner with `xattr -d`. | The cooperating application (browser, mail client, Archive Utility). Advisory data, not a kernel property. |
| **Gatekeeper** (`syspolicyd`) | Blocks first execution of a *quarantined* file until it passes signature + notarization checks or the human explicitly allows it. Since macOS 15 Sequoia the Control-click shortcut is gone; the human must go to System Settings → Privacy & Security and click **Open Anyway**, then open again. | Apple's code-signing PKI plus the notarization ticket. |
| **Notarization** | Nothing at runtime. It is a service: the developer uploads the build, Apple scans it for known malware, and issues a ticket that Gatekeeper checks. Apple states plainly this is a malware scan, **not** a security review, and Apple can revoke a ticket later. | An Apple-operated notary service. There is no local equivalent. |
| **XProtect / XProtect Remediator** | Signature-based detection and removal of *known* malware families, at app launch, on file change, and on signature update. | An Apple-maintained signature feed. |
| **TCC** (Transparency, Consent, Control) | Per-app consent for camera, microphone, contacts, screen recording, full disk access. Enforced in the platform sandbox policy. | A system database + the user's own prompts. |
| **SIP** | Puts system paths, Mach bootstrap names and IOKit access beyond the reach of **root**. | A boot-time kernel policy the running system cannot switch off. |
| **App Sandbox / entitlements** | Per-app filesystem, network and IPC restriction, declared as entitlements and enforced by the kernel sandbox. Mandatory only for App Store apps. | Code-signed entitlements. |

Two conclusions that shape the whole design:

1. **Gatekeeper only ever looks at quarantined files.** A binary fetched with
   `curl` on macOS is not quarantined and runs with no prompt at all. The
   property macOS actually ships is *"software of foreign origin gets one
   deliberate human decision"* — not *"unfamiliar software is blocked."*
   Punar can honestly ship the same property.
2. **Notarization, XProtect, TCC and SIP have no honest Linux equivalent that
   Punar can ship.** Notarization requires an operated notary service; Punar
   would have to *be* one. XProtect requires a malware signature feed and a
   team maintaining it. TCC requires every application to run inside a
   platform sandbox. SIP requires a boot-anchored kernel policy that survives
   local root — which on Linux needs measured boot plus a locked-down kernel,
   and Punar's Secure Boot/TPM state is **simulated in VMs** (§1.22). §12
   states these as refusals, not as roadmap.

---

## 2. The Linux primitive survey

**Assertion: exactly one shipping Linux primitive can refuse an `execve` on
behalf of a policy engine that was not itself the process being executed —
`fanotify` permission events. Everything else in the list either confines a
process that already consented, or verifies something at install time, or is
not available on Arch.**

Verified 2026-08-25 against the Arch official repositories
(`archlinux.org/packages/search/json`) and upstream documentation.

| Primitive | What it actually enforces | Maturity on Arch | Cost | Failure modes |
|---|---|---|---|---|
| **`fanotify` `FAN_OPEN_EXEC_PERM`** | Kernel suspends `execve(2)`/`execveat(2)`/`uselib(2)` and waits for a userspace `FAN_ALLOW`/`FAN_DENY`. This is a *gate*, not a report. Needs `CONFIG_FANOTIFY_ACCESS_PERMISSIONS` and `CAP_SYS_ADMIN`; `FAN_OPEN_EXEC` landed in Linux 5.1. | **In the mainline kernel Arch already ships.** No package, no module, no AUR dependency. | Zero when nothing execs — a blocking `read(2)` on an fd, no timer, no polling. One decision per `execve`. | **Fail-open**: `fanotify(7)` states "upon `close(2)`, outstanding permission events will be set to allowed", so a dead listener means execution proceeds. Does not see `mmap`-based execution, in-memory `memfd` execution, or a script read as data by an interpreter. Queue can overflow (`FAN_Q_OVERFLOW`). No events from network filesystems. |
| **fapolicyd** | The same primitive, wrapped in a rule language (allow/deny by `path`, `dir`, `exe`, `ftype`, `trust`, `uid`, SHA-256), with an LMDB trust database populated from the **RPM database** or a manual file list. | **Not packaged in Arch's official repositories** (`fapolicyd` search: zero results, 2026-08-25). Its first-class trust backend is `rpmdb`; a Debian backend exists; no ALPM backend. `aur.archlinux.org` could not be reached for automated verification (bot protection) — the claim above is about the official repositories only. | Subject/object caches, 79–95 % hit ratio; per-decision rule iteration. | Undefined behaviour if the daemon dies mid-decision. Cannot gate script *content*, only the interpreter it invokes. Root can stop it. **No callout mechanism: its decisions are static, so it cannot ask a human anything.** |
| **IMA / EVM appraisal** | Kernel-enforced signature or hash appraisal of every file before read/execute, via `security.ima` xattrs, with `ima_appraise=enforce` blocking the operation. The strongest primitive in the list. | **Not available on stock Arch at all.** The pinned kernel's own configuration settles it before the userland question arises: Arch `linux` 7.1.10-arch1 `config.x86_64` contains `# CONFIG_IMA is not set` and `# CONFIG_EVM is not set` (verified 2026-08-25). `CONFIG_LSM="landlock,lockdown,yama,integrity,bpf"` lists `integrity`, which is the *framework*, not IMA. So this is not "needs a policy and a keyring" — **the subsystem is not compiled in**, and adopting it means shipping a custom kernel, which is a distribution-level commitment, not a feature. `ima-evm-utils` is also absent from the official repositories (zero results, 2026-08-25), but that is now the second reason, not the first. | Hash/verify per first access; label every file at image build. | Meaningful only when the keyring is anchored by measured boot — which Punar simulates in VMs. **Breaks the developer instantly**: a freshly compiled binary has no `security.ima` signature, so an enforcing policy refuses it. |
| **Landlock** | *Self*-restriction. A process (or its parent) drops its own filesystem/network rights, inherited by descendants. `LANDLOCK_ACCESS_FS_EXECUTE` restricts what *that* domain may execute. | In the stock Arch kernel and in `CONFIG_LSM` by default. | Negligible. | **Cannot express system-wide policy.** Kernel documentation is explicit that Landlock is enabled by the process itself or its parents, not by a system policy, and cannot restrict processes that did not opt in. Useless as a gatekeeper; excellent as *post-approval confinement*. |
| **AppArmor** | Path-based MAC; a confined profile can deny `x` on a path. | `apparmor` is in `extra` (4.1.7-1; 5.0.2-1 in `extra-testing`), but **it is not active on Arch by default** — the kernel's `CONFIG_LSM` omits it, so it needs an `lsm=…,apparmor,…` boot parameter and an initramfs/bootloader change, plus a profile set to ship and maintain. | Per-syscall profile evaluation for confined tasks. | Unconfined processes are unconfined. Profile-per-program, not a global allowlist; a new unknown binary has no profile and is therefore *unrestricted*, which is the exact opposite of the property wanted here. |
| **SELinux** | Label-based MAC, capable of `execute` denials fleet-wide. | **Effectively unavailable on Arch**: the official repositories contain no SELinux userland (search returns only `python-selinux`); a working system needs core packages rebuilt from AUR. Adopting it means owning a distribution-wide rebuild. | Policy load + per-access vector cache. | Same structural problem as AppArmor for *new* files: a mislabeled binary usually inherits a permissive type. |
| **Flatpak + bubblewrap + portals** | Real confinement: `bubblewrap` (in `extra`, 0.11.2-1) mount/user namespaces, a declared permission set, and `xdg-desktop-portal` (already in the Punar image) mediating file, screenshot and device access. | `flatpak` is in `extra` (1:1.18.1-1); portals already installed. | Per-app runtime + storage. | Confines only applications that ship as Flatpaks. Says nothing about a loose ELF binary in `~/Downloads`. Portals mediate only portal-using apps — an ordinary Wayland app has no consent layer at all. |
| **systemd exec sandboxing** | Confines *Punar's own services* (`ProtectSystem`, `NoNewPrivileges`, `CapabilityBoundingSet`, …). Already used. | Native. | Free. | Applies to units, not to user-launched binaries. |
| **`noexec` mounts** | Genuinely blocks `execve` on a mount. Free, kernel-enforced, no daemon. | Native. | Free. | All-or-nothing: it cannot be lifted for one approved file, so it is incompatible with a consent flow. Blunt on `/tmp`, which is where builds live. |
| **pacman signature verification** | Verifies package signatures against the pacman keyring web of trust **at install time**. Already the substrate's trust root (ADR-001: vendor-pinned snapshot repos, Punar's own signing key). | Native, mature. | Free at runtime. | Says nothing about the bytes on disk *after* install; provides no exec-time check on its own. |

### 2.1 The rejections, stated

- **fapolicyd is rejected as a dependency, and adopted as a design ancestor.**
  It is the right architecture and it proved the primitive at RHEL scale. But
  it is not packaged for Arch, its trust database is built for `rpmdb`, and —
  decisively — **it has no way to ask a human a question**. Punar's whole
  first-run model is an M9 approval; a static rule engine cannot produce one.
  Vendoring it would mean a second policy engine, a second rule language, a
  second audit trail, and a second daemon against the §6.2 RSS gate, to obtain
  a fanotify loop that is a few hundred lines. Credit where due: the
  trust-database-populated-by-the-package-manager pattern in §4.1 is
  fapolicyd's, ported from ALPM instead of RPM.
- **IMA appraisal is rejected for now and named as the upgrade path.** It is
  the only primitive that makes the `system` tier a *kernel* claim rather than
  a *daemon* claim, and §14 draws it dashed. It is **not compiled into the
  kernel Punar pins** (`# CONFIG_IMA is not set`), so reaching it means owning
  a kernel build; and it is hostile to compilation, which is fatal for a
  developer OS. Both reasons are independently sufficient, and the §14 dashed
  line must be read as *"needs a custom kernel"*, not *"needs configuration"*.
- **Landlock, AppArmor, SELinux, Flatpak, systemd sandboxing and `noexec` are
  not rejected — they are simply not the gate.** §11 assigns each the job it
  can actually do.

---

## 3. The enforcement mechanism

**Decision: Punar gates execution with `fanotify` `FAN_OPEN_EXEC_PERM`,
marked on the mounts where non-package files can live, evaluated by a
dedicated subsystem inside `punard`. No new daemon, no new socket, no new
package dependency.**

### 3.1 Why this primitive

| Requirement | How `FAN_OPEN_EXEC_PERM` meets it |
|---|---|
| **It must actually stop execution, not report it.** | The kernel suspends the `execve` and will not proceed until the listener writes `FAN_ALLOW` or `FAN_DENY`. This is the difference between M10's detector, which "blocks nothing, kills nothing, quarantines nothing" (M10 law 4), and a gate. |
| **It must cost approximately nothing at idle.** | It is an event source, not a loop. Zero wakeups, zero timers, zero CPU while no process calls `execve` — precisely the "event-driven observation" §6.3 demands and the opposite of the polling it prohibits. |
| **It must not be broad tracing (§1.14).** | It is a *scoped kernel primitive*: one bounded event class (`execve`/`execveat`/`uselib`), delivered only for the mounts Punar marks, producing a decision rather than a trace. It is not eBPF-wide, not `ptrace`, not a filesystem firehose. §1.14 asks for exactly this instead of tracing. M10 §3.2 deferred "exec-time notification" on the grounds that a *detection* mechanism at exec time would be tracing; a *permission gate* at exec time is a different object with a different cost, and it is why this document exists separately from M10. |
| **It must survive a determined user only as far as it honestly can.** | It does not survive local root, and §12 says so in those words. It does survive an ordinary user account, a script, a downloaded binary, and an AI agent running as that user. |
| **No fork, no vendored dependency (§1.24, §1.25).** | A `fanotify_init(2)` + `fanotify_mark(2)` + `read`/`write` loop against the mainline API. |

### 3.2 Why inside `punard` and not a new daemon

`punard` already owns the capability registry, the layered policy merge (§39),
the reconcile loop (§42), the audit path (§53), **and the M9 approval engine**.
The gate needs all five. M9 §3.2 settled the governing principle when it
placed the approval engine in `punard`: *adding a second approval authority is
not additive.* An exec gate in its own daemon would need to call `punard` for
policy, call `punard` for approvals, and duplicate the audit writer — while
adding a fourth resident process to the §6.2 sum that already counts
`punard` + `punar-agentd` + `punar-secrets`.

**Cost, stated:** the gate runs as a dedicated thread with its own `epoll`
loop, so it never contends with the IPC contract's 10 s per-method processing
bound or its sequential per-connection handling (ipc.md §2). `punard`'s unit
must retain `CAP_SYS_ADMIN` in its `CapabilityBoundingSet` for
`fanotify_init`. That is a real widening of `punard`'s privilege surface —
`CAP_SYS_ADMIN` is close to root — and it is recorded here rather than
discovered later. `punard` already runs as uid 0 to apply capabilities, so the
delta is the bounding set, not the effective identity.

**Rejected alternative:** `punar-execd`. Rejected for the reasons above, and
because a gate whose liveness is independent of the daemon holding the policy
can disagree with it — which is worse than the fail-open it was meant to fix.

### 3.3 What is marked, and what is not

`FAN_MARK_MOUNT | FAN_OPEN_EXEC_PERM` on **user-writable mounts only**:
`/home`, `/tmp`, `/var/tmp`, `/run/user`, and any removable-media mount as it
appears. `/usr`, `/opt` and the image's read-only trees are **not marked** —
which means the overwhelmingly common execution (`ls`, `cargo`, `chromium`,
every shell builtin's helper) never generates an event at all. This is the
single biggest reason the design costs nothing: for *system* execution the
fast path is *no kernel event*, not *a fast decision*.

**This is true of the system's execution and false of the developer's**, and
§8.1 traces it: `cargo`'s output lives on `/home`, which is marked, so every
locally built binary *does* generate an event and is answered in microseconds
by two `fgetxattr` calls. The honest sentence is that the fast path is free for
everything the image ships and cheap for everything the user builds — and
§13 assertion 16 is the measurement that decides whether "cheap" is true.

Consequence, stated honestly: a file placed under `/usr` is never seen by the
gate. Placing a file under `/usr` requires root, and §12 already concedes root.

`/dev/shm` **must be** mounted `noexec` — free, kernel-enforced, and no
legitimate Punar workload executes from it. Stated as a requirement, not a
fact: the image does not mount it `noexec` today (no such option appears
anywhere under `os/images/`), so this is one line the adopting milestone
adds, and until it does, §12 item 6 covers the gap.

**The mark set assumes a partition layout that does not exist yet.**
`FAN_MARK_MOUNT` marks the *mount* containing the given path. On the image as
built today there is a single root filesystem and no separate `/home` or
`/var`, so marking `/home` would mark `/` — and with it `/usr`, destroying the
"the common case generates no kernel event" property that the whole cost
argument rests on. The design therefore **requires** ADR-003's layout
(separate, shared `/var` and `/home`), which is planned and unbuilt
(`docs/development/image-pipeline.md`). This is a hard prerequisite, recorded
in §3.5, not a detail.

Two consequences of that layout that the mark set must answer explicitly:

- **`/var/tmp` lives on the `/var` mount, and so does `/var/lib/flatpak`.**
  A mount mark placed for `/var/tmp` marks all of `/var`, which means every
  Flatpak application launch becomes a permission event. That is not fatal —
  the verdict is a cache hit after the first launch — but it is the opposite
  of "no event on the common path", and it is what makes the `curated` /
  `community` tiers reachable at the gate at all. The adopting milestone
  chooses one of: mark `/var` and accept the events; give `/var/tmp` its own
  mount; or drop `/var/tmp` from the mark set (it is not an origin zone, and
  §5.3's argument against `/tmp` applies to it verbatim). **The third option
  is the recommended one** and it is the cheapest.
- **Mounts that appear after `punard` starts must be marked when they
  appear** — `/run/user/<uid>` at first login, removable media at plug time.
  This needs no polling: `poll(2)` on `/proc/self/mountinfo` returns `POLLPRI`
  on every mount-table change, which is an event source in exactly the §6.3
  sense. It is one more fd on the gate thread's `epoll` set, and the design
  owes it a line rather than an assumption.

### 3.4 The decision path, and its latency

```text
execve(~/Downloads/foo)
  │
  ├─ 1. mount not marked ──────────────────────────────► kernel proceeds, no event
  │
  └─ 2. FAN_OPEN_EXEC_PERM event → punard exec-gate thread
         │
         ├─ 2a. inode cache hit (dev, ino, mtime_ns, size) → verdict ─► FAN_ALLOW  (~µs)
         │
         ├─ 2b. tier resolution (§4): packaged.db lookup by realpath ─► FAN_ALLOW  (~µs)
         │
         ├─ 2c. provenance test (§5): 2 × fgetxattr + prefix test
         │       no foreign origin ─────────────────────────────────► FAN_ALLOW  (~µs)
         │
         └─ 2d. tier = unknown → sha256 → decisions.db
                 ├─ allow  ──────────────────────────────────────────► FAN_ALLOW
                 ├─ deny   ──────────────────────────────────────────► FAN_DENY + §73 surface
                 └─ absent ─► M9 approval (§7) + hold ≤ 20 s ─────────► FAN_ALLOW | FAN_DENY
```

**The hold window is 20 s and then the syscall is refused.** A permission event
held open for the full 300 s approval TTL would pin a blocked process, burn a
kernel event slot, and invite a queue overflow; and a machine where an
`execve` can hang for five minutes is a machine with a new denial-of-service
primitive. Twenty seconds is long enough that a human who is *at the machine*
presses `A` and the program they just launched simply starts. Past that, the
gate answers `FAN_DENY`, the approval stays live for its full M9 TTL, and the
card says *"approve, then run it again"* — which is exactly the shape macOS
Sequoia settled on: refuse, decide deliberately, open again.

`FAN_DENY` surfaces to the caller as `EPERM`. `FAN_DENY_ERRNO` (Linux ≥ 6.13,
`FAN_CLASS_PRE_CONTENT` groups) could choose the errno; the design does not
depend on it. §10 covers the §73 problem that `EPERM` is literally the spec's
example of an unacceptable message.

**Concurrency bound:** at most **4** execution events may be held awaiting a
human at any moment, device-wide. Beyond that the gate answers `FAN_DENY`
immediately and, if a decision record does not already exist, folds the
refusal into the flood path (§6.4). Everything else — cache hits, tier
resolution, denied-and-remembered — is answered on the gate thread without
blocking.

---

### 3.5 `TO VERIFY` — what must be measured before this design is believed

Marked here so the register cannot be lost in prose. Each is a build- or
boot-time check, not an opinion.

| # | Claim | Status |
|---|---|---|
| V1 | The pinned kernel enables permission events. | **VERIFIED** — Arch `linux` 7.1.10-arch1 `config.x86_64` sets `CONFIG_FANOTIFY=y` and `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`. Checked 2026-08-25. |
| V2 | `FAN_MARK_MOUNT` + `FAN_CLASS_CONTENT` + `FAN_OPEN_EXEC_PERM` deliver and gate on the pinned kernel, in the CI VM. | **TO VERIFY** — a 200-line spike, and it should run *before* the milestone is scheduled. This is the one experiment that can invalidate the document. |
| V3 | ADR-003's separate `/home` and `/var` exist. | **TO VERIFY** — not built. Hard prerequisite (§3.3). |
| V4 | `punard` marking mounts does not deadlock on its own `execve`s. | **TO VERIFY** — `punard` execs `nft`, `pacman`, `flatpak`, `hyprctl`, all from unmarked `/usr`, so the exposure is believed nil; the gate must still self-exclude by pid to be safe, and the spike must prove it. |
| V5 | Rootless `podman` / `punar-env` execs generate no events. | **TO VERIFY** — the reasoning (container rootfs is a distinct mount object, so a `/home` mount mark does not match) is sound for `overlay`; the `vfs` fallback and `fuse-overlayfs` must be exercised too. |
| V6 | An `execve`-heavy build measures under the §13 2 % wall-clock gate. | **TO VERIFY** — assertion 16. Note this is a *marked-mount* measurement: a developer's build output lives on `/home`, so it is gated, and the fast path for a developer is "an event with a microsecond verdict", not "no event". |
| V7 | Chromium writes download provenance xattrs. | **FALSIFIED** — see §5.1. |
| V8 | `packaged.db` stays single-digit megabytes and non-resident. | **TO VERIFY** — §4.1. |

---

## 4. The trust tiers

**Assertion: a tier names what was verified. It never names a hope, a
reputation, or a vendor — and it never names *containment*, which is a
different sentence on a different axis.**

Punar has exactly **one** trust vocabulary. It is shared verbatim with
[`app-catalog.md`](app-catalog.md) §1.5 and defined once, in a schema both
consume (`schemas/common/trust.json`, proposed — one file, two readers):

```text
punar.trustTier   = system | curated | community | user | unknown   (who vouches, and who read it)
punar.containment = sandboxed | sandbox-bypassed | none             (what it can reach)
```

The two axes are independent, and **no surface may print one word for both.**
A `community` + `sandboxed` Flatpak is a *weaker provenance* claim and a
*stronger containment* claim than a `system` + `none` package; a design with a
single ladder cannot say that sentence. This is app-catalog law 4, adopted
here without amendment.

Tiers are resolved first-match-wins.

| Tier | What was **verified** | What was **not** verified | Seen by the gate? |
|---|---|---|---|
| `system` | The file's realpath is recorded in `packaged.db` as owned by a package that **pacman verified against the Punar/Arch keyring at install time**, from the pinned base repository; and its `(size, mtime_ns)` are unchanged since that transaction. | That the bytes are cryptographically intact at *this* execution (that is IMA, §14). That the upstream package is free of malware — nobody checked. | **Rarely.** Packaged files live under `/usr`, which §3.3 deliberately leaves unmarked. This tier is mostly a `punarctl trust check` answer, not a gate verdict. |
| `curated` | Either the owning package came from **Punar's vendor repository**, signed by Punar's repo key (ADR-001); or the bytes are a Flatpak deployment whose **OSTree commit signature verified against a catalog-pinned remote key** and whose catalog entry carries a current `review` (app-catalog §1.5). | Anything about the software's behaviour. "Curated" means *someone chose to carry it and read its permission set*, not *someone audited it*. | Only where Flatpak deployments sit on a marked mount — see the `/var` question in §3.3. |
| `community` | Identical pin and signature verification, but the catalog entry is **not reviewed**: its summary and permission set come from the application's own AppStream metadata. Punar vouches for the pin, not for the app. | That anyone at Punar has read what it asks for. | As `curated`. |
| `user` | Nothing about the file's origin — and that is the point: **no evidence of foreign origin exists** (no quarantine mark, no `user.xdg.*` provenance xattr, not inside an origin zone). | Everything. This is the tier of *your own machine's output*: compiler artefacts, scripts you wrote, binaries you built. | **Constantly.** This is the developer's normal path and the reason §8 exists. |
| `unknown` | The file **carries evidence that it came from somewhere else** — a Punar quarantine mark or residence inside a configured origin zone — and Punar can verify no signature over it. | Whether it is safe. Punar has no opinion. It only knows the human has not yet said yes to *these bytes*. | Yes. This is the only tier that can raise an approval. |

Notes that keep the vocabulary honest:

- **There is no `trusted` tier, no `verified publisher` tier, and — deliberately
  — no `sandboxed` tier.** The first two would imply a notary Punar does not
  operate (§12). The third would place *reach* on the *provenance* ladder,
  which is the exact collapse app-catalog law 4 forbids. Whether a Flatpak's
  declared permissions actually confine it is `containment`, computed from the
  exact ref against `catalog/containment-bypass.json`, and printed as a
  sentence — *"this app can read and write every file in your home
  directory"* — never as a reassuring adjective.
- **`user` and `unknown` are the two runtime-only halves.** A catalog entry is
  never `user`; the catalog describes bytes somebody published. `unknown` spans
  both surfaces with one meaning — *nothing vouches for this* — which at the
  gate means foreign bytes awaiting a decision and in `punarctl app doctor`
  means an installed application with no catalog entry.
- **`user` is not a compliment.** A binary someone emailed you and you saved
  outside the download folder lands in `user` and runs silently. §12 names
  this hole, and it is the same hole macOS has.
- **`unknown` is not an accusation.** The card never says malware, virus,
  threat, or suspicious. It says *unknown origin*, and per §23's discipline
  the only stronger word it may use is **suspected**, and only about AI-agent
  classification (§9).
- **Tiers are computed, never stored on the file.** The only thing stored on
  the file is the quarantine mark (§5.2); the authority is always the
  root-owned store.

### 4.1 `packaged.db` — the trust database, populated by ALPM

An **ALPM hook** (`/usr/share/libalpm/hooks/90-punar-exec-trust.hook`,
`Operation = Install|Upgrade|Remove`, `Type = Package`, `Target = *`) runs
`punarctl trust reindex --alpm` after every pacman transaction, writing
`/var/lib/punar/exec-trust/packaged.db` (`0600 root:root`): `realpath →
{sha256, size, mtime_ns, pkgname, repo, tier}`. `tier` is `system` for the
pinned base repositories and `curated` for the Punar vendor repository — a
repository-name mapping shipped as reviewable data
(`exec-trust/repo-tiers.json`), in the same style as M7's `suspected.json` and
M11's `policy-allowlist.json`.

This is a supported upstream extension point, not a fork. It is also the only
write path to `packaged.db`: there is no IPC method that adds an entry.

**Scope, and the honest consequence of §3.3.** `packaged.db` records
**executable-mode files only** — not every packaged file. Two reasons, one
budget and one correctness. The budget: a full desktop image carries on the
order of 10^5 package files, and a row per file at ~150 bytes is tens of
megabytes, which against a §6.2 gate whose *entire current sum is ~4 MB* is
not a rounding error but a multiple. Restricted to executables the store is
single-digit megabytes on disk, and it is queried by an indexed on-disk
lookup — **never held resident**. The correctness reason is sharper:

> **Under §3.3's mark set, no packaged file is ever on a marked mount, so the
> `system` and `curated` tiers are almost never gate verdicts.** `/usr` and
> `/opt` are unmarked by design. `packaged.db` therefore serves
> `punarctl trust check`, the surfaces that print a tier, and the *future*
> case where the root slot is marked — not the hot path in §3.4 step 2b.

This is recorded rather than glossed because it changes what the MVP owes:
the ALPM hook, `repo-tiers.json` and `systemIntegrity` are **not on the
critical path for the gate**, and a milestone that ships the gate without
them still ships the property in §1. See the `TO VERIFY` register in §3.5.

**Integrity policy, and its honest limit.** `execution.systemIntegrity` takes
`mtime` (default) or `hash`. `mtime` compares `(size, mtime_ns)` against the
transaction record — cheap, and it catches accidental modification and lazy
tampering, **but a local root can rewrite a system binary and restore its
mtime**. `hash` re-hashes on first execution after each change and caches by
inode — correct, and it costs one full read of, e.g., a 200 MB Chromium
binary on the first launch after an update. Neither is a substitute for IMA;
both say so in `punarctl trust explain`.

---

## 5. The quarantine problem

**Assertion: Punar's provenance inputs are advisory; Punar's verdict is
enforced. Confusing the two is how a security product starts lying.**

macOS's model depends on cooperating applications writing a mark. On Linux
nothing writes a mark by default — but that is not the same as *no provenance
exists*. The honest answer to the task's question is **both**: Punar uses the
provenance that already exists, adds a mark of its own where it can, and the
model still functions with no provenance at all.

### 5.1 The three provenance signals, and their real coverage

| Signal | Written by | Coverage | Enforceability |
|---|---|---|---|
| `user.xdg.origin.url`, `user.xdg.referrer.url` | **Nothing in the image, as of the Chromium Punar ships.** See the correction below. | `UNSUPPORTED` on the shipped browser. `FULL` only for third-party tools a user opts into (`curl --xattr`, `wget --xattr`, some file managers). | Advisory input in every case. The owner may `setfattr -x` it, exactly as a macOS user may `xattr -d`. |
| `user.punar.quarantine` | **`punard` itself**, when the gate refuses an execution (§5.2), and `punarctl trust mark`. | `FULL` for anything Punar has already refused once. | Enforced input in the sense that it is *created* by the gate; still user-removable, and removal is a user's right on their own machine. |
| Origin zones | Nobody — it is a *location* rule, not a mark. Default: the XDG download directory (`XDG_DOWNLOAD_DIR`, ordinarily `~/Downloads`), extensible by policy. | `FULL` for every file in the download folder regardless of how it arrived — `scp`, a tarball, a file manager, a browser that writes nothing. | Fully enforced: it needs no cooperation from anyone. |

#### Correction (2026-08-25): Chromium on Linux writes no provenance xattr

An earlier draft of this document claimed that Chromium already writes
`user.xdg.origin.url`, citing
`content/common/quarantine/quarantine_linux.cc`. That citation was read at
revision **62.0.3178.1 — a 2017 tree**. It does not describe the browser in
the image. Verified against Chromium `main` on 2026-08-25:

- `components/services/quarantine/` (the file's modern home) contains
  `quarantine_win.cc`, `quarantine_mac.mm` and `quarantine_chromeos.cc`.
  **There is no `quarantine_linux.cc`**, and `BUILD.gn` adds a
  platform source only for `is_win`, `is_mac` and `is_chromeos`.
- `quarantine.cc` compiles, for every other platform, a `QuarantineFile()`
  whose entire body is `std::move(callback).Run(QuarantineFileResult::OK);`.
  On Linux, quarantining a download is **a no-op that reports success**.

crbug 40088105 was not an open proposal to remove the Linux implementation;
the removal has happened. The image ships `chromium` 151, so:

> **Punar's `user.xdg.*` provenance signal has coverage `UNSUPPORTED`, not
> `FULL`.** For an ordinary browser download, the *only* provenance signal is
> the origin zone.

**The design survives this, which is the point of having built it this way.**
§5.1's third row was written to work with no provenance at all, and the
default origin zone — the XDG download directory — is where a browser puts
its downloads. Everything in §6, §7 and §8 is unchanged. What changes is
three sentences of coverage and one piece of scope:

- **`user.xdg.*` becomes an input Punar *reads if present* and never
  *expects*.** It is read because `curl --xattr`, `wget --xattr` and some file
  managers do write it; it is never a required link in any chain.
- **M11 still does not need to change, and still must not fork Chromium.**
  §1.24 forbids the fork, and a fork would buy a hint the origin-zone rule
  already provides for the same files. What M11 *may* add is a
  `browser.policy` key restricting download types (spec §62 lists download
  restrictions as a policy family) — that is M11's decision, not this
  document's.
- **The "manual acceptance step" in §13.2 is deleted, not deferred.** There is
  nothing to accept manually: the browser writes nothing, and asserting that
  offline CI cannot prove it would now be dressing an absent feature as an
  untested one.

**CLI downloads are `UNSUPPORTED` by default, deliberately.** `curl --xattr`
and `wget`'s `xattr = on` would extend provenance to `curl` and `wget`, and
Punar does **not** enable them by default: both write the *full URL* into file
metadata readable by any local process, which leaks credentials embedded in
URLs — the precise defect of CVE-2018-20483, which is why wget made it
opt-in. Punar will not create a local secret-leak to gain a provenance hint.
`execution.provenance.cliDownloads: true` turns it on (writing `xattr` to
`/etc/skel/.curlrc` and `xattr = on` to `/etc/wgetrc`), the privacy panel
(§64) states exactly what that records, and the audit trail stores only the
**scheme and host** of an origin URL, never the path or query.

### 5.2 The mark that Punar does write

**On refusal, the gate writes `user.punar.quarantine`** on the refused file:
a small JSON value carrying the refusal timestamp, the sha256 it refused, and
the `apr_` id if an approval was raised. Two consequences, both intended:

- **Quarantine becomes sticky.** Moving the file out of `~/Downloads` no
  longer launders it, because the mark travels with the inode.
- **On approval, `punard` removes the mark.** The file's tier becomes `user`,
  and it behaves like anything else you own. On `punarctl trust revoke`, the
  mark is written back.

Honest limits, in the same breath: `cp` without `--preserve=xattr` drops the
mark; so does a rename-over by an updater; so does `setfattr -x`. The
authoritative record is always `decisions.db`, keyed on content hash — the
xattr is a *travelling hint*, never the authority. **Punar never trusts a
`user.*` xattr as evidence of permission**, only as evidence of suspicion,
because the `user.*` namespace is writable by the file's owner and a
trust-granting xattr would be a forgery primitive.

### 5.3 Why `/tmp` is not an origin zone

M10 §3.5 lists `~/Downloads/`, `/tmp/` and `~/.local/bin/` as unmanaged path
prefixes — for **detection**, where a false positive costs a line in a list.
For **enforcement** the calculus inverts, and this design narrows the set to
the download directory alone:

- `/tmp` is where builds, `./configure` probes, test binaries and installer
  scripts execute. Gating it would prompt during ordinary compilation, which
  §8 forbids outright.
- `~/.local/bin` is where users deliberately put their *own* tools. Its
  purpose is the opposite of a download folder's.
- The download directory is the one path on the machine whose entire purpose
  is receiving files from elsewhere.

`execution.originZones[]` lets policy add paths. It is a policy knob, not a
default, and the reason it is not a default is written above.

---

## 6. The default policy

**Assertion: the defensible line is `unknown` — one deliberate decision per
set of foreign bytes, on both a personal and a managed device. Everything
else runs silently.**

### 6.1 The table

| Tier | Personal (`personal-defaults`) | Managed (org baseline) |
|---|---|---|
| `system` | run silently | run silently |
| `curated` | run silently | run silently |
| `community` | run silently; the containment sentence is shown at install, not at launch | run silently; containment governed by policy |
| `user` | run silently | run silently, **unless** `applications.allowUserInstall: false`, in which case refuse with the §73 explain naming the policy and the org |
| `unknown` | **first execution of these bytes raises one approval**; approved bytes run silently forever after; denied bytes are refused silently forever after | `approval_required` by default, routed to the user with the org citation; `deny` available, and then **no approval is offered at all** — the card explains that the organisation, not Punar, refused |
| explicitly `denied` by `applications.denied[]` | refuse | refuse |

`execution.unknown` therefore takes `allow | approval_required | deny`, and
`execution.enforcement` takes `enforce | observe | off`:

- `observe` writes the audit event and the card and answers `FAN_ALLOW` —
  the honest way to roll this out to a fleet, and the honest way to answer
  *"what would this have blocked?"* It is labelled **OBSERVE ONLY** on every
  surface, because §1.22 forbids a red card that did not act.
- `off` unmarks every mount and the thread sleeps on nothing. `punarctl
  status` prints `EXECUTION TRUST · OFF` — an absent security control is
  always visible, never silently absent.

### 6.2 Why not stricter — the defence of `user` running silently

An allowlist that refuses everything unsigned is the enterprise-correct
answer and the wrong answer for this product. Punar is a developer OS whose
first success criterion (§1.26, Test A) is a developer being productive on it.
A developer's machine produces new, unsigned executables continuously —
`cargo build` alone emits dozens per session. Gating them would either
prompt hundreds of times a day or force a "developer exception" so broad it
would be the policy. §8 states the resulting invariant as a testable
property.

### 6.3 Why not looser — the defence of prompting on `unknown`

*"A downloaded unsigned binary executing silently is exactly the hole macOS
closed."* Correct, and Punar closes it on the same terms macOS does: the
prompt is bound to **evidence of foreign origin**, not to unfamiliarity. The
expected steady-state prompt rate for a working developer is a handful per
month — a downloaded release binary, an AppImage, a vendor installer — and
zero per build. Compare with M10's anti-nag discipline: one alert per
`signature_id` per day; here it is **one approval per content hash, ever**.

### 6.4 The anti-nag rules, enumerated

1. **One approval per sha256, ever** — until revoked. Re-running an approved
   binary produces no card, no prompt, and no audit event.
2. **A denial is remembered too.** Re-running refused bytes is refused
   immediately, with the §73 explain and *no new approval*. `punarctl trust
   forget <sha256>` clears the memory when the human changes their mind.
3. **A pending approval is reused, never duplicated.** While `apr_x` is
   pending for a hash, further executions of that hash are refused
   immediately without raising anything.
4. **The M9 flood bounds apply unchanged** — 8 pending device-wide, 2 per
   requester session.
5. **The archive case gets one question, not fifty.** Extracting a downloaded
   SDK inside the download folder puts dozens of executables in an origin
   zone. When the flood bound trips, `punard` replaces the queue with a single
   aggregate card:

   ```text
   EXECUTION TRUST · 12 REFUSED · 14:31
   ──────────────────────────────────────────────────────────────────
   12 executables under ~/Downloads/acme-sdk-3.2 were refused.

   Why · they are inside your download folder, so Punar treats them as
         being of unknown origin.

   Next · move the folder into a project directory, or run
          punarctl trust allow-tree ~/Downloads/acme-sdk-3.2
          — one approval, and Punar records every hash it trusted.
   ```

   `trust allow-tree` enumerates the tree **once, at approval time**, prints
   the file count and a manifest hash in the contract block, caps at **512
   executables**, and on resolve writes one decision record per hash. It is
   not path-scoped trust: it is a bulk grant over an enumerated, printed,
   revocable set. `punarctl trust list --tree <apr_id>` prints exactly what
   was granted.

### 6.5 Where the policy block lives — zero schema bytes change

`schemas/desired-state/desired-state.json` is **shipped**, and the M8
Decision-0 law (restated by M9 and M10) says the design conforms to the
schema, not the reverse. It does, without an edit:

- `spec.applications` is a **closed** object (`additionalProperties: false`) —
  so nothing here goes there. Spec §46's `required` / `denied` /
  `allowUserInstall` are consumed as-is: `denied[]` is an execution-trust
  input, and `allowUserInstall: false` is what makes the `user` tier prompt on
  a managed device (§6.1).
- `spec.security` is an **open** object (`additionalProperties: true`) — it is
  where §44's baseline lives, and execution trust is a security baseline
  control. The block is therefore `spec.security.execution`:

```yaml
security:
  execution:
    enforcement: enforce          # enforce | observe | off
    unknown: approval_required    # allow | approval_required | deny
    unknownAgents: approval_required
    systemIntegrity: mtime        # mtime | hash
    originZones: []               # additive; the XDG download dir is implicit
    terminalNotice: true
    provenance:
      cliDownloads: false         # §5.1 — off by default, and why
    gateSharedLibraries: false    # dashed (§14); false is the only shipped value
```

It merges through the §39 ladder like every other block, appears in
`policy.effective` / `policy.explain` with no new method, and joins the §42
reconcile loop: hand-unmarking a mount is drift, and reconcile re-marks it
within one period — the firewall demo's shape, applied to a kernel mark.

---

## 7. First-run consent is an M9 approval

**Assertion: this needs no new consent mechanism, and inventing one would be
a security regression. The approval engine M9 shipped is already the
human-only, TTL-bounded, audited, overlay-backed gate this feature needs.**

Everything is reused: the typed approval object, the human-only resolution
rule enforced by reading the peer's cgroup, the 300 s TTL, the flood bounds,
the audit path, and the Plate D-003 overlay.

### 7.1 The approval record

Per M9's envelope law, `schemas/audit/approval.json` is **not extended**. The
`approval` member validates unchanged; everything else is a sibling.

```json
{"v": 1,
 "approval": {
   "approval_id": "apr_3b81f0c2",
   "requester": {"type": "human", "id": "punar"},
   "user": "punar",
   "capability": "execution.trust",
   "resource": "/home/punar/Downloads/acme-cli",
   "reason": "first execution of a file of unknown origin",
   "risk": "medium",
   "status": "pending",
   "expires_at": "2026-08-25T14:36:00Z"
 },
 "kind": "execution_request",
 "created_at": "2026-08-25T14:31:00Z",
 "request": {"method": "(none — raised by the exec gate)"},
 "requester_peer": {"uid": 1000, "agent_session_id": null},
 "policy_ids": ["personal-defaults"],
 "execution_subject": {
   "sha256": "9f2c4d…",
   "size": 8421376,
   "mtime": "2026-08-25T14:29:41Z",
   "tier": "unknown",
   "provenance": {"origin_zone": "~/Downloads",
                  "xdg_origin_host": "github.com",
                  "punar_quarantine": false},
   "launched_by": {"pid": 4471, "exe": "/usr/bin/foot", "comm": "foot"},
   "agent_suspicion": null,
   "setuid": false
 },
 "resolved_at": null, "resolved_by": null,
 "consumed_at": null,
 "execution": null}
```

Contract notes:

- `capability: "execution.trust"` matches the `capability_id` pattern and is a
  typed **method-shaped** id, exactly as M9 §2.4 permits for
  `credential.request` and `privilege.request`. The capability *registry*
  still holds `security.firewall`, `system.hostname`, `time.timezone` and
  M11's `browser.policy`. Nothing is faked to make this fit.
- `resource` is the realpath, because M9 §2.4 defines `resource` as *the
  concrete argument of the typed call* so that `capability(resource)` reads
  as the contract block: `TrustExecution(~/Downloads/acme-cli)`. The **hash**
  is the key of the decision and lives in the sibling, where the contract
  block prints it.
- `requester.type` is `human` for an ordinary launch and **`ai_agent` when the
  execing process is attributed to a `punar-agent-<id>.scope`** (§9).
- `risk` is `medium` by default; `high` when the file is setuid/setgid, when
  the M10 agent signature matches, or when the requester is an AI agent.
- `execution.audit_event_id` is filled on resolve, and the
  `approval.resolve` audit event carries `resource: "apr_3b81f0c2"` — M9's
  bidirectional link, unchanged.

### 7.2 What the human is told

Plate D-003's grammar, unchanged. Six facts, in this order, because this is
the whole security value of the feature:

```text
APPROVAL · APR_3B81F0C2 · EXPIRES 04:59                        [MEDIUM]
──────────────────────────────────────────────────────────────────────
Run a program of unknown origin?

  Program    ~/Downloads/acme-cli
  Identity   sha256 9f2c4d21 8e07b3aa … (8.0 MB)
  Origin     downloaded with Chromium from github.com · in ~/Downloads
  Launched   by foot (your terminal)
  Rights     if you approve, it runs as you — your files, your network,
             your credentials. Punar does not sandbox it.
  Memory     this decision covers these exact bytes. Replace or update
             the file and Punar asks again.

Policy: personal defaults · unknown origin requires your approval
                                          [A] APPROVE      [D] DENY
```

- **"Rights" is the sentence macOS does not print, and it is the honest one.**
  Punar has no App Sandbox and no TCC; approving means granting the program
  everything the user has. Saying so is §1.22 and §73 in one line.
- **"Memory" states the key before the decision, not after.**
- When Chromium recorded no origin and the file is merely in the zone, the
  Origin line reads `in ~/Downloads · Punar does not know where it came
  from` — absence of evidence is printed as absence, never inferred.
- Managed devices append the org citation and a `MANAGED` pill as *additive
  chrome* (DESIGN_LANGUAGE §8). Personal devices cite `PERSONAL DEFAULTS`.

### 7.3 How the decision is remembered

**Keyed on `sha256` of the file contents. Only.**

- **Not the path.** A path is a name, not an identity; keying on it would mean
  approving `~/Downloads/acme-cli` also approves whatever is written there
  tomorrow. That is a laundering hole, not a convenience.
- **Not path + hash.** Then moving an approved binary into `~/bin` would
  re-prompt for bytes the human already approved, which is nagging without a
  security gain.
- The record *stores* the realpath at approval time for display, audit and
  `punarctl trust list` — as data, never as key.

Store: `/var/lib/punar/exec-trust/decisions.db`, `0600 root:root`, one record
per hash: `{sha256, decision, approval_id, user, path_at_decision, tier,
provenance_summary, decided_at, size}`. Atomic write per transition (temp +
`fsync` + `rename`), the M9 discipline, and batched per §6.4 of the spec.
Retention is unbounded by design — a record is a *permission*, and permissions
do not evaporate — capped at 4096 entries with the oldest **denied** records
evicted first and a §73 message when the cap is reached.

The **inode cache** — `(dev, ino, mtime_ns, size) → verdict`, in memory,
bounded at 4096 entries LRU — exists only so a hot binary is not re-hashed. It
is invalidated by any change to the tuple, is never persisted, and is cold
after reboot, which is exactly what the reboot test in §13 exercises.

**When the binary changes**, its hash changes, so the decision does not apply
and the next execution raises a fresh approval — *if the new bytes still show
foreign origin*. If a self-updating tool replaces itself by rename outside an
origin zone, the new file has no provenance and is tier `user`, and it runs
silently. That is a real gap, it is the same gap macOS has, and §12 names it.

### 7.4 Revocation

```text
punarctl trust list                 # decisions for your uid (root sees all)
punarctl trust show <sha256|path>   # the record, the tier, the evidence
punarctl trust revoke <sha256|path> # delete the decision, re-mark the file
punarctl trust forget <sha256>      # clear a *denial*, so it can be asked again
punarctl trust check <path>         # what would happen — no execution, no record
punarctl trust why                  # §73 explain for your most recent refusal
```

`revoke` is authorised for **the user the decision was made by, or root**. It
deletes the decision record, rewrites `user.punar.quarantine` on the file if
it is still present, invalidates the inode cache, and audits
`action: "execution.trust", decision: "deny", result: "revoked"`.

**There is deliberately no `trust.allow` method.** Execution trust can be
granted in exactly one way: a human resolving an approval. A daemon method
that granted it would be a way to obtain execution trust without a human, and
M9 Law 2 exists to prevent precisely that. Root can change *policy*; root
cannot mint a decision record through the IPC surface.

---

## 8. The developer invariant

**Assertion: Punar does not try to recognise build output. It recognises
foreign origin, and the absence of foreign origin is the developer's
silence.** This is the difference between a rule that works and a heuristic
that eventually guesses wrong about someone's `Makefile`.

> **Invariant D.** A file that (1) carries no `user.punar.quarantine`, (2)
> carries no `user.xdg.origin.url` / `user.xdg.referrer.url`, and (3) does not
> resolve inside a configured origin zone, is tier `user`. It executes with no
> hold, no approval, no card, and no audit event.

Every artefact of a local build satisfies all three **by construction**:

| Producer | Writes provenance xattrs? | Writes into the download folder? |
|---|---|---|
| `cc`, `ld`, `cargo`, `go build`, `zig`, `ghc` | no | no |
| `npm`/`pnpm` postinstall binaries, `.venv/bin`, `node_modules/.bin` | no | no |
| `make install` into `~/.local` | no | no |
| a shell script you wrote in an editor, `chmod +x` | no | no |
| `podman build` / `punar-env` container layers | no (and the exec happens in the container's mount namespace) | no |
| `git clone` of a repository containing a checked-in binary | no | no — and §12 names this as an accepted gap |

### 8.1 The four workflows, walked concretely

**Assertion: the design is only worth shipping if a working day produces zero
prompts. It does — and two of the four cases produce zero prompts for reasons
that are also the design's largest holes, which is why they are traced here
rather than asserted in a table.**

| # | What the developer does | Events | Prompts |
|---|---|---|---|
| 1 | `cargo build && ./target/debug/thing` | one per `execve` on `/home` | **0** |
| 2 | Download an AppImage, `chmod +x`, run it | 1 | **1**, once per version |
| 3 | `curl https://sh.rustup.rs \| sh` | 1–2 | **0** — and §12.5 is why |
| 4 | `git clone`, `./scripts/build.sh`, `npm ci` | one per script/binary | **0** |

**1 — `cargo build`, then `./target/debug/thing`.** `rustc`, `cc`, `ld` and
`ar` all live on unmarked `/usr`, so the compiler itself is invisible to the
gate. `build.rs` binaries and the final artefact live under `~/src/...` on
`/home`, which **is** marked, so each one *does* generate a permission event.
The verdict costs two `fgetxattr` calls and a prefix test, resolves to `user`
by Invariant D, and answers `FAN_ALLOW` in microseconds. Rebuilding changes
`mtime_ns`, so the inode cache misses and the two `fgetxattr` calls run again;
that is the whole cost. **Zero prompts, zero audit events, zero cards.**

  This corrects a sentence in §3.3: "the fast path is *no kernel event*" is
  true for the *system's* execution and false for the *developer's*. A
  developer's fast path is an event with a microsecond verdict. That is what
  §13 assertion 16's 2 % wall-clock gate over 2000 `execve`s actually measures,
  and it is the number that decides whether this design is shippable.

**2 — a downloaded AppImage.** It lands in `~/Downloads`, which is the origin
zone, so it is tier `unknown` and raises **one** approval. Approve, run again,
and it runs forever. A new release is new bytes and therefore one more
approval — roughly one per application update, which is exactly Gatekeeper's
rate and is the property being bought.

  The storm case is `--appimage-extract`, which drops hundreds of files
  *inside the origin zone*. §6.4's aggregate card and `punarctl trust
  allow-tree` exist for it, and the adopting milestone must prove that path
  with a real extracted archive (a new assertion 18), not only with the flood
  bound. The AppImage's own FUSE mount is a distinct mount object and is
  therefore not covered by the `/tmp` mark; the inner binary runs unexamined
  once the outer one is approved, which is the correct behaviour under §12.4
  and is worth knowing.

**3 — `curl https://sh.rustup.rs | sh`.** Trace it honestly:

  - `sh` reads the installer **from a pipe**. There is no file, so there is no
    `execve` of a script and no event.
  - The installer downloads `rustup-init` into `$TMPDIR`. `/tmp` is marked but
    is deliberately **not an origin zone** (§5.3), and with `cliDownloads:
    false` `curl` writes no xattr, so the binary is tier `user`.
  - `rustup-init` runs silently, installs toolchains into `~/.cargo`, and every
    one of those runs silently thereafter.

  **The most dangerous install idiom on Linux produces zero prompts.** This is
  stated here, in the feature section, and not only in §12.5, because a
  security design that buries its widest gap in the limits section is doing the
  thing this document was written to avoid. Two honest observations:
  `execution.provenance.cliDownloads: true` *would* convert this case into one
  approval — the installer's own `curl` would tag `rustup-init` with
  `user.xdg.origin.url` — at the cost of writing full URLs, credentials
  included, into file metadata (CVE-2018-20483). The default stays `false` and
  the trade is the user's to make. And macOS is no better: `curl | sh` sets no
  quarantine bit there either.

**4 — a cloned project's build script, and `npm ci`.** `git clone` writes no
xattrs and does not write into the download folder, so `./scripts/build.sh` is
tier `user` and executes silently. So does a binary checked into the
repository, and so does every `node_modules/.bin` entry and every `postinstall`
script `npm` runs. **`npm ci` is the second uncovered case and it belongs
beside `curl | sh`**: it is the highest-volume unsigned-code execution path in
modern development, and this gate does not touch it. Gating it would mean
gating an entire package ecosystem's normal operation, which §6.2 already
refused for `cargo`. `UNSUPPORTED`, with the reason.

**Verdict: no prompt storm, in any of the four.** The design passes its own
audience test. The price is written above in full: it buys exactly one
property — *nothing of foreign origin runs without your decision*, where
"foreign origin" means the download folder or a mark Punar itself wrote — and
it buys nothing at all against a pipe, a package manager, or a `git clone`.

### 8.2 Two corollaries

Two corollaries worth stating because they are the ones a reviewer will
probe:

- **The gate covers `./script.sh` but not `bash script.sh`.** Executing a
  shebang script is an `execve` of the script file, so it generates the event.
  Passing it to an interpreter opens it as *data*, and no `execve` of the
  script occurs. This is fapolicyd's documented limitation and it is
  structural, not an oversight: gating interpreter input means gating file
  *opens*, which is a different and far more expensive primitive.
  **`UNSUPPORTED`, with the reason.**
- **Shared libraries are not gated.** `dlopen` and the loader use ordinary
  opens, not `FAN_OPEN_EXEC_PERM`. Gating them means `FAN_OPEN_PERM` on every
  library load, which is where fapolicyd's cost lives and where the §6.3 idle
  and §6.4 I/O budgets would go. **`UNSUPPORTED` in MVP**, a policy option
  (`execution.gateSharedLibraries`) drawn dashed in §14.

---

## 9. AI agents — closing M10's open verb

**Assertion: an AI agent about to run a binary of unknown origin is the exact
case this design was built for, and it needs no new authority — it needs
`requester.type: "ai_agent"` and M9 Law 2.**

M10 ships a detector that is deliberately **not armed**: it "blocks nothing,
kills nothing, quarantines nothing", and it names the missing piece as *a
policy verb*. This is that verb, and it arrives at exec time rather than at
scan time.

### 9.1 The three interactions, precisely

1. **The agent is the one execing.** The gate reads the peer's
   `/proc/<pid>/cgroup` — the same kernel-attested attribution M7/M8/M9 use.
   If the path contains a `punar-agent-` segment, the approval's
   `requester.type` becomes `ai_agent`, `requester.id` becomes the `agt_`
   session id, and `risk` becomes `high`. **The agent cannot answer it**:
   M9's `approvals.resolve` refuses any peer attributed to an agent session
   *before any other check*, and a self-approval attempt is audited as
   `policy_bypass_attempt`. The card reads:

   ```text
   APPROVAL · APR_5C02A9E1 · EXPIRES 04:52                          [HIGH]
   ─────────────────────────────────────────────────────────────────────
   Claude Code wants to run a program of unknown origin.

     Program    ~/Downloads/foo-agent
     Identity   sha256 41ba9c07 …
     Requester  Claude Code · agt_4f21c09ab3e1
     Origin     in ~/Downloads · Punar does not know where it came from
     Rights     if you approve, it runs as you, from inside the agent's
                session. Punar does not sandbox it.

   Policy: personal defaults · only a person at this device can answer
                                           [A] APPROVE      [D] DENY
   ```

2. **The binary is *suspected* to be an AI agent.** The gate evaluates M7/M10's
   `signatures/suspected.json` — the same reviewable data file, no second rule
   set — and when the `unmanaged-path-agentlike` rule matches (unmanaged path
   prefix **and** agent-like name token, `require: "both"`), the contract
   block gains one line and one line only:

   ```text
     Suspected  this looks like an AI agent · signature
                unmanaged-path-agentlike · suspected, not certain
   ```

   §23's vocabulary is preserved verbatim. The gate never upgrades a
   suspicion to a classification: classification remains `punar-agentd`'s job
   and `punar-agentd`'s alone.

3. **The policy that blocks.** `execution.unknownAgents: allow |
   approval_required | deny`, merged through the §39 ladder like any other
   policy.
   - **Personal default: `approval_required`.** A personal device never
     silently refuses its owner's own choices — DESIGN_LANGUAGE §8, and
     "unmanaged-first" means the human is the authority.
   - **Managed: `deny` is available**, and when it fires the gate answers
     `FAN_DENY`, raises **no approval** (there is nothing to ask), writes the
     audit event with `decision: "deny"`, and the M10-shaped card changes one
     word — the line that today reads *"nothing was blocked"* reads
     **"execution was refused"**. That single word is the whole difference
     between M10's honest detector and an armed control, and it may only
     appear when the `FAN_DENY` actually happened.

### 9.2 Wiring, without touching M10's contracts

`punard` owns this event, so `punard` publishes it: **`/run/punard/exec-trust.json`**,
`0640 root:punar`, atomic write on change only, watched by a Quickshell
`FileView` (`Services/ExecTrust.qml`). Root-owned for M9's stated reason — a
forged *"execution refused"* card is a phishing primitive, and `/run/punar` is
user-writable. M10's `/run/punar-agentd/alerts.json` is **not modified**; the
shell watches both files and the two cards are visually siblings.

`punard` additionally fires M10's immediate-trigger path (proposed as a
fourth trigger in M10 §3.3) after an **allowed** unknown execution, because
that is precisely the moment the process landscape changed. After a **refused**
execution there is no process to scan, so the audit event and the card are the
entire record — and that is stated on the card, because an admin reading a
fleet answer must not conclude that a refused agent was ever "seen running".

---

## 10. Surfaces, and the `EPERM` problem

Spec §73 uses `EPERM` as its canonical example of an unacceptable message,
and `FAN_DENY` produces exactly `EPERM`. The refusal therefore has three
surfaces and the raw errno is never the whole story:

1. **The graphical card** (`/run/punard/exec-trust.json` → `FileView`), in
   the Plate D-009 grammar, colour `bad` for a refusal and `warn` for a
   pending approval — §2's promise that green/amber/red map 1:1 to
   allow/approval_required/deny, kept.
2. **`punarctl trust why`**, which prints the full §73 block for the most
   recent refusal belonging to the caller's uid: what happened, why, which
   policy, whether it can be changed, and the next step.
3. **The controlling terminal.** The gate knows the refused process's
   `tty_nr`; with `execution.terminalNotice: true` (default) `punard` writes
   the §73 block to that tty, so a refusal in a shell explains itself where
   the human is looking. Honest caveat, recorded: a message written to a tty
   is not distinguishable by the terminal from program output, so any program
   can print a lookalike. The card and `punarctl trust why` are the
   authoritative surfaces; the tty notice is a courtesy.

`punarctl status` gains one line — `EXECUTION TRUST · ENFORCE · 3 DECISIONS`
or `· OFF` — because an absent control must be visible.

### 10.1 Proposed contract text for `ipc.md` — three additive sections

Additive, still **`v: 1`**. No existing method, error code or side contract
changes. **This document does not edit `ipc.md`** — the implementing milestone
lands the text.

> **Section numbers are allocated at merge time, in merge order, and no design
> document may hard-code them.** `ipc.md` ends at §20 (M10). Four unmerged
> designs now queue behind it — M11 (`webapps.*`, `browser.policy`), M12
> (network additions), M13 (`update.*`), [`app-catalog.md`](app-catalog.md)
> (`apps.*`), and this one (`trust.*`) — and three of them had independently
> written "§24" into their own text. Whoever merges first takes the next free
> number; every other document says *the next free section* and cites the
> method names, which are the part that actually has to be unique. The
> provisional order, recorded so a reader has something to hold: M11 §21–§23,
> app-catalog §24, execution-trust §25–§27, M12 and M13 after them.

The three sections this design contributes are, in order: **`trust.*` methods**,
**the `execution_request` approval kind**, and **the
`/run/punard/exec-trust.json` side contract.**

**`trust.*` — `punard` additions** (all on the existing
`/run/punard/punard.sock`; admission unchanged — root or group `punar`):

| Method | AuthZ | Mutating | Audited | Notes |
|---|---|---|---|---|
| `trust.check` | any connected peer | no | no | `{path}` → `{tier, decision, evidence{}, sha256?, would_prompt}`. Side-effect free; does not execute, does not record, does not hash unless the tier resolves to `unknown`. |
| `trust.list` | any connected peer | no | no | Scoped to the caller's uid; root sees all. Paths of other users are never returned to a non-root peer. |
| `trust.get` | any connected peer | no | no | `{sha256}` → the decision record, uid-scoped as above. |
| `trust.revoke` | decision owner **or** root | yes | always | Deletes the record, rewrites `user.punar.quarantine`, invalidates the cache. |
| `trust.forget` | decision owner **or** root | yes | always | Clears a **denial** only. Refuses on an `allow` record — that is `revoke`. |
| `trust.reindex` | **root only (uid 0)** | yes | always | The ALPM hook's entry point; rebuilds `packaged.db`. |

**There is no `trust.allow`, `trust.grant`, `exec.run` or `execution.allow`
method, and there never will be** — for the same reason ipc.md §8 has no
generic execution method. Execution trust is minted by exactly one act: a
human resolving an approval through `approvals.resolve` (§14.5, unchanged).
The §74.4 probe asserts `unknown_method` for all four names.

**The `execution_request` approval kind.** M9's §2.4 table gains one more row
(a sibling of [`app-catalog.md`](app-catalog.md)'s `application_install`;
whichever merges second is not "the fourth", and neither document may say so): `capability = execution.trust`, `resource =` the executable's
realpath, rendering as `TrustExecution(<path>)`; the identity that is
remembered travels in the `execution_subject` **sibling** (§7.1), never inside
the `approval` document. Envelope law unchanged.

**Side contract: `/run/punard/exec-trust.json`.** `0640 root:punar`,
atomic write on change only, no timer. Shape:
`{v, updated_at, enforcement, pending[], recent_refusals[], counts{}}` where
each entry carries `{path, sha256_short, tier, provenance_summary,
approval_id?, agent{suspected, signature_id}?, at}`. Root-owned for M9's
stated reason. The shell watches it with a `FileView`; it is **not** a
socket client and there is no polling.

---

## 11. What the other primitives are for

Assigning each surveyed primitive the job it can actually hold (§45 asks for
native primitives, not for one primitive):

| Primitive | Job in Punar | Status |
|---|---|---|
| pacman signatures + pinned repos | the trust root for `system` and repo-delivered `curated`; the source of `packaged.db` | shipped (ADR-001) |
| `fanotify FAN_OPEN_EXEC_PERM` | the gate | **this design** |
| systemd exec sandboxing | confinement of Punar's own daemons | shipped |
| `noexec` on `/dev/shm` | free removal of one execution surface | this design |
| bubblewrap / Flatpak / portals | the `containment` axis's enforcement, owned by Flatpak, not by Punar — and the reason there is no `sandboxed` *tier* | **dashed** — Flatpak arrives with [`app-catalog.md`](app-catalog.md); it is not in the MVP image |
| Landlock | post-approval confinement of an approved-but-unknown binary, and of `punar-env` / agent sessions | **dashed** — Phase 2 |
| AppArmor | targeted profiles for `punard`, `punar-agentd`, Chromium | **dashed** — needs an `lsm=` boot parameter and a profile set to maintain |
| IMA/EVM appraisal | turning the `system` tier from a daemon claim into a kernel claim | **dashed** — needs a custom kernel, a signing key in the build pipeline, and a measured-boot anchor Punar currently simulates |
| SELinux | not adopted | rejected: no usable userland in Arch's official repositories |

---

## 12. What Punar must not claim

**This section is written with more care than the feature sections, because
every line in it is a sentence somebody will otherwise be tempted to say in
marketing.**

1. **There is no malware scanner.** Punar ships no signature database, no
   heuristic engine, no behavioural analysis, and no XProtect equivalent.
   Punar cannot tell you whether a program is malicious. It can only tell you
   that *you have not yet decided about these bytes*. No surface may use the
   words malware, virus, threat, infected, or clean.
2. **There is no notary, and there will not be one by accident.**
   Notarization is a *service*: a vendor scans a submitted build and issues a
   revocable ticket. Punar operates no such service. "Signed by Punar" means
   only *built and signed by Punar's repository key* — a statement about
   provenance in a build pipeline, not a safety verdict. The `curated` tier
   says "curated", and curated means *someone chose to carry it*.
3. **A local root user defeats local policy.** Root can stop `punard`
   (`FAN_DENY` never arrives, the pending events fail **open** by design —
   `fanotify(7)`: "upon `close(2)`, outstanding permission events will be set
   to allowed"), edit `decisions.db`, unmark files, unmount the marks, or boot
   another kernel. Nothing here is a defence against the administrator of the
   machine, and no honest Linux mechanism is, short of measured boot plus
   kernel lockdown — which Punar simulates in VMs (§1.22) and does not claim.
4. **This is a first-execution gate, not a sandbox.** An approved program runs
   with all of the invoking user's rights: their files, their SSH keys, their
   network, their session. Punar has no TCC and no App Sandbox equivalent for
   ordinary applications; portals mediate only portal-using applications. An
   approved program can also write new executables, and those will be tier
   `user` and will run silently.
5. **Provenance is advisory, in both directions.** A user may remove any
   `user.*` xattr. A downloader may write none. A binary that arrives by
   `scp`, `git clone`, a USB stick, or `curl -o ~/bin/x` and never touches the
   download folder is tier `user` and runs with no prompt. **macOS has the
   identical hole**; naming it is the difference between describing the
   mechanism and overselling it.
6. **Interpreted code, `mmap`ed code and in-memory execution are outside the
   gate.** `bash script.sh`, `python -c`, a `memfd_create` + `fexecve` on an
   anonymous fd, and library loading all bypass `FAN_OPEN_EXEC_PERM`. Stated,
   not engineered around.
7. **The `system` tier is an integrity claim about install-time state, not a
   cryptographic claim about this execution** — unless `systemIntegrity:
   hash`, and even then the hash comes from `packaged.db`, which root can
   rewrite. Only IMA moves this claim into the kernel.
8. **Signature verification is not safety.** A signed package from a
   compromised upstream is signed. Execution trust does nothing about §59.6
   supply-chain compromise, and must never be cited as though it does.
9. **Nothing here is proof of absence.** Per §23's rule, the product language
   is *"nothing runs from an unknown origin without your decision"* — never
   *"no malicious code can run on this machine."*

---

## 13. Verification

### 13.1 What an in-VM check proves, offline

`tools/boot-test.sh` gains an exec-trust phase; `exec-trust-check` runs
inside the guest with **no network**, which every assertion below respects.

| # | Assertion | Method |
|---|---|---|
| 1 | A crafted unsigned binary in the origin zone is **refused**. | `cc` a fixture at build time into `/usr/share/punar/fixtures/exec-trust/`, copy it to `~/Downloads/`, run it. Expect exit status from `EPERM`, an `apr_` approval created, `execution_subject.tier == "unknown"`. |
| 2 | The **same bytes outside** the origin zone with a quarantine mark are still refused. | Move it to `~/bin/`; assert `user.punar.quarantine` survived the move and the verdict is unchanged. |
| 3 | An **approved** binary runs. | `punarctl approvals resolve <apr> --decision approved` as the console user; re-exec; expect success, `execution.audit_event_id` populated, `user.punar.quarantine` removed. |
| 4 | A developer's **freshly compiled** binary is not prompted. | `cc -o ~/src/hello/hello hello.c && ~/src/hello/hello`; assert the approval count is **unchanged**, no `exec-trust.json` write, no audit event. This is Invariant D and it is the check that fails loudest if the design drifts. |
| 5 | The decision **survives a reboot**. | Reboot phase; re-exec the approved binary; assert silent success and that the inode cache was cold (the record came from `decisions.db`). |
| 6 | Changing the binary **re-prompts**. | `printf x >> ~/bin/fixture`; re-exec; assert a *new* `apr_` with a different `execution_subject.sha256`. |
| 7 | **Revocation** works. | `punarctl trust revoke <sha256>`; re-exec; assert refusal, mark rewritten, audit `result: "revoked"`. |
| 8 | A **denial is remembered** and does not nag. | Deny; re-exec three times; assert exactly one approval ever existed and three refusals were audited. |
| 9 | The **audit trail is complete and bidirectional**. | For each of the above, assert an `audit-event.json`-valid event exists, that `approval.resolve` carries `resource: "apr_…"`, and that the approval's `execution.audit_event_id` names an existing `evt_`. |
| 10 | An **AI agent cannot approve its own execution**. | Launch the fixture from inside a `punar-agent-*.scope`; assert `requester.type == "ai_agent"`, then attempt `approvals.resolve` from that scope; expect `denied` / `self_approval_refused` and a `policy_bypass_attempt` ledger row. |
| 11 | `unknownAgents: deny` **actually refuses**. | Agent-named fixture (`foo-agent`) in the origin zone with policy `deny`; assert `FAN_DENY`, **zero** approvals created, and that the card text contains "execution was refused" and not "nothing was blocked". |
| 12 | **`observe` mode allows and still records.** | Flip to `observe`; assert the binary runs and the card is labelled `OBSERVE ONLY`. |
| 13 | **The gate fails open when `punard` is stopped**, and the check asserts it. | `systemctl stop punard`; exec the refused fixture; assert it **succeeds**. This test exists to make the limit unforgettable: a green suite must never imply a guarantee the mechanism does not give. |
| 14 | **No generic execution method exists.** | `punarctl debug rpc exec.run`, `execution.allow`, `trust.allow` → `unknown_method` (ipc.md §4/§8, spec §60). |
| 15 | **`trust check` is side-effect free.** | `punarctl trust check ~/Downloads/fixture` prints the tier and predicted decision; assert no approval, no record, no execution. |
| 16 | **Budgets hold.** | Idle CPU sample over the existing 300 s window unchanged at ≈0 (no timer was added); services PSS sum still under the §6.2 gate; and a `make`-shaped workload of 2000 `execve`s measures added wall-clock, gated at **< 2 %**. |
| 17 | **Schemas are unextended.** | `jq .approval` of every new fixture validates against the shipped `approval.json`; a fixture with `"status": "trusted"` is asserted **invalid**. |
| 18 | **A real extracted archive produces one card, not fifty.** | Stage a fixture tarball containing 40 executables, extract it inside `~/Downloads`, and run a script that execs all 40. Assert **exactly one** aggregate card, that `punarctl trust allow-tree` grants and lists all 40 hashes, and that the 512 cap refuses a 600-entry fixture with the count printed. §6.4 is the anti-nag rule most likely to be wrong in practice, and until this assertion exists it is an intention. |
| 19 | **No packaged file is ever a gate verdict under the shipped mark set.** | Exec a `/usr/bin` binary and assert **zero** fanotify events; exec a `/home` binary and assert exactly one. This is the check that keeps §3.3's cost claim and §4.1's scoping honest with each other. |

### 13.2 What cannot be proven without real-world malware or hardware

Stated on the surface, not only here:

- **That the gate stops malware.** It stops *unapproved execution of files of
  foreign origin*. Proving the former needs samples Punar has no engine to
  recognise and no business shipping.
- **That provenance exists in the wild.** It largely does not, and §5.1 now
  says so: the shipped Chromium writes no xattr on a Linux download. The check
  can write `user.xdg.origin.url` by hand to prove the *reader* works; there is
  no browser behaviour left to accept manually. The property the gate actually
  ships for browser downloads rests on the origin zone, which needs no
  cooperation from anyone and **is** provable offline (assertion 1).
- **That a determined attacker cannot escape.** Assertion 13 proves the
  opposite for the root case, deliberately. `memfd`/interpreter bypasses are
  documented in §12, not tested as though they were defended.
- **Anything anchored in hardware.** Secure Boot and TPM state are simulated
  in VMs (§1.22); an IMA-backed `system` tier cannot be demonstrated on the
  stock kernel at all.
- **Fleet behaviour.** One VM cannot show that a managed `deny` policy is
  survivable across an organisation's developer population; that is a rollout
  question, which is why `observe` exists.

---

### 13.3 Budget arithmetic — this design, and the three read together

The §6.2 gate sums **every Punar daemon** and is currently at **~4 MB against a
100 MB target**. That headroom is the reason these three designs can be
considered at all, and it is also the reason the one number below that is
*unsized* matters more than it looks.

| Design | New daemon | New unit or timer | Resident delta | Disk |
|---|---|---|---|---|
| [`theme-system.md`](theme-system.md) | none | none | two `FileView`s and ~1.5 KB of parsed JSON in `punar-shell` — **< 1 MB** | 7 theme documents, ~14 KB |
| [`app-catalog.md`](app-catalog.md) | none | none — verified: Arch `flatpak` 1.18.1 ships `flatpak-system-helper.service` (D-Bus activated) and **no `.timer`** | the catalog must be read on demand and **not held resident**; 160 entries parsed is ~1–2 MB if someone caches it, which nobody should | ≈ 90 MB preinstall + ≤ 3 GB of Flatpak runtimes on shared `/var` + a < 16 MiB fixture repo |
| this design | none | none | one thread, one `epoll` set, a bounded inode cache — **and `packaged.db`, which is the risk** | `packaged.db` + `decisions.db` on `/var` |
| **combined** | **0** | **0** | **< 4 MB if `packaged.db` is scoped per §4.1; 20–40 MB if it is not** | ≈ 3.1 GB, dominated by Flatpak runtimes |

Two conclusions, plainly:

1. **Nothing here adds a resident process, an enabled unit, or a timer.** The
   §6.2 sum and the §6.3 idle-CPU rule survive all three designs intact. That
   is not luck — it is the same decision made three times (`punard` owns the
   gate; the shell owns the theme; `punard` drives `flatpak` with a fixed
   argv and no updater).
2. **One number can break the gate, and it is `packaged.db`.** An unscoped
   index over every packaged file on a desktop image is tens of megabytes; held
   resident it would take the services sum from 4 MB to 30–45 MB — still inside
   100 MB, but a **tenfold** increase in the number the project quotes, spent
   on a tier that §4.1 has just shown the gate almost never evaluates. §4.1
   scopes it to executable-mode files with an on-disk indexed lookup, and V8
   in §3.5 makes it a measurement rather than a promise.

**Disk, restated against ADR-003 rather than against a guess.** ADR-003 fixes
17 GiB of the §5.1 minimum 128 GB (119.2 GiB) disk as ESP + two 8 GiB root
slots, leaving **≈ 102 GiB shared between `/var` and `/home`** — not the
110 GiB an earlier draft of app-catalog assumed, and the `/var`:`/home` split
is itself unspecified. Three Flatpak runtimes at ≈ 3 GB is therefore **2.5 % of
the minimum disk** and an unknown but larger fraction of `/var` alone. It is
affordable; the honest sentence is "2.5 % of the disk", not "2.7 % of `/var`",
until the partition layout exists to divide by.

---

## 14. Trajectory (dashed — outside the production claim)

Per DESIGN_LANGUAGE §7, a dashed line marks a mechanism outside the current
production claim. These are dashed:

- **IMA/EVM appraisal** for the `system` and `curated` tiers, anchored by
  real Secure Boot — turns "the daemon believes this file is packaged" into
  "the kernel refuses to execute anything it cannot verify."
- **Landlock confinement of approved-unknown binaries** — approve *and*
  restrict, which is the one place Punar could exceed Gatekeeper.
- **The `containment` axis in practice** — Flatpak, and therefore any
  `curated` or `community` Flatpak deployment, arrives with
  [`app-catalog.md`](app-catalog.md) and is not in the MVP image.
- **Shared-library gating** (`execution.gateSharedLibraries`).
- **Fleet reporting of execution-trust decisions** through M10's existing
  scoped, audited, user-readable query path — never a new channel.
- **`browser.policy` download restrictions** (spec §62) narrowing what can
  reach an origin zone at all.

Nothing above may be described in any user-facing surface as existing.

---

## 15. Sources

Verified 2026-08-25.

- Apple, *Protecting against malware in macOS* — the three layers, and that
  notarization is a malware scan, not a security review:
  https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web
- MacRumors, *macOS Sequoia Makes It Harder to Override Gatekeeper Security*
  (2024-08-06) — removal of the Control-click override:
  https://www.macrumors.com/2024/08/06/macos-sequoia-gatekeeper-security-change/
- HackTricks, *macOS Gatekeeper / Quarantine / XProtect* — `syspolicyd`, the
  `com.apple.quarantine` attribute, and its removability:
  https://hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-gatekeeper.html
- HackTricks, *macOS TCC* and *macOS SIP*:
  https://hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-tcc/index.html ·
  https://hacktricks.wiki/en/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-sip.html
- `fanotify(7)` — permission events, `FAN_OPEN_EXEC_PERM`, fail-open on
  `close(2)`, queue overflow, `mmap`/network-filesystem limits:
  https://man7.org/linux/man-pages/man7/fanotify.7.html
- LWN, *fanotify: introduce FAN_OPEN_EXEC and FAN_OPEN_EXEC_PERM* (v7 series):
  https://lwn.net/Articles/771160/
- fapolicyd — the primitive, rule attributes, RPM trust backend, caches, and
  its documented limitations (scripts, deferred execution, root):
  https://github.com/linux-application-whitelisting/fapolicyd ·
  Red Hat, *Blocking and allowing applications by using fapolicyd* (RHEL 10):
  https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/security_hardening/blocking-and-allowing-applications-by-using-fapolicyd
- Linux kernel documentation, *Landlock: unprivileged access control* — self
  restriction, inheritance, and the absence of system-wide policy:
  https://docs.kernel.org/userspace-api/landlock.html ·
  https://docs.kernel.org/admin-guide/LSM/landlock.html
- IMA documentation — `ima_appraise=` modes, appraisal policy, key
  requirements: https://ima-doc.readthedocs.io/en/latest/ima-configuration.html
- Chromium quarantine, **re-verified against `main` on 2026-08-25 and found to
  contradict the earlier citation** (§5.1). `components/services/quarantine/`
  builds a platform source only for `is_win` / `is_mac` / `is_chromeos`
  (`BUILD.gn`), and `quarantine.cc`'s `#if !IS_WIN && !IS_APPLE && !IS_CHROMEOS`
  body is `std::move(callback).Run(QuarantineFileResult::OK);` — a no-op:
  https://chromium.googlesource.com/chromium/src/+/refs/heads/main/components/services/quarantine/ ·
  the 2017 revision the earlier draft cited, which no longer describes the
  browser:
  https://chromium.googlesource.com/chromium/src.git/+/62.0.3178.1/content/common/quarantine/quarantine_linux.cc ·
  the removal issue: https://issues.chromium.org/issues/40088105
- everything.curl.dev, *Storing metadata in file system* (`--xattr` writes
  `xdg.origin.url` and `mime_type`):
  https://everything.curl.dev/usingcurl/downloads/metadata-fs.html
- CVE-2018-20483 — wget writing credential-bearing URLs into xattrs, and the
  resulting opt-in change: https://bugzilla.redhat.com/show_bug.cgi?id=1662705
- Arch official package searches (2026-08-25): `apparmor` 4.1.7-1 (`extra`),
  `bubblewrap` 0.11.2-1 (`extra`), `flatpak` 1:1.18.1-1 (`extra`);
  `fapolicyd` — **no results**; `ima-evm-utils` — **no results**; `selinux` —
  only `python-selinux`. `aur.archlinux.org` was unreachable for automated
  verification (bot protection), so no AUR claim is made.
- Arch stock kernel configuration, read directly from the packaging repository
  on 2026-08-25 (`linux` 7.1.10-arch1, `config.x86_64`):
  https://gitlab.archlinux.org/archlinux/packaging/packages/linux/-/raw/main/config.x86_64
  — `CONFIG_FANOTIFY=y`, `CONFIG_FANOTIFY_ACCESS_PERMISSIONS=y`,
  `CONFIG_LSM="landlock,lockdown,yama,integrity,bpf"` (AppArmor compiled in but
  not enabled without an `lsm=` parameter), `# CONFIG_IMA is not set`,
  `# CONFIG_EVM is not set`. The kernel config is the authority for every
  primitive claim in §2 and it is checked, not cited second-hand.
- Arch Linux Archive snapshot pinned by `os/images/snapshot.env`
  (2026/08/20), confirmed present 2026-08-25:
  https://archive.archlinux.org/repos/2026/08/20/
