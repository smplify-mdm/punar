# Milestone 3 — `punard` + `punarctl`: architecture plan

Deliverable per spec section 76 M3: **daemon, typed IPC, capability registry,
CLI, audit.** Spec authorities: sections 10, 11, 41, 53, 60, 61, 73, 74.4.
The wire contract lives in `docs/api/ipc.md` (binding); this document holds
the implementation, image-integration, and verification decisions.

Everything M3 ships runs in **personal mode** (design language section 8):
no org, no enrollment; policy citations are `personal-defaults` / "os
default" only.

---

## 1. Scope

In: `punard` daemon (UDS NDJSON server, capability registry with three real
capabilities, audit writer, boot-time reconcile), `punarctl` real
implementations of `status`, `capabilities [get|set]`, `audit tail`,
`reconcile` (+ global `--json`), image integration (packages, units,
tmpfiles, hermetic binary build), `m3-check` VM exercise, services-RSS budget
wiring.

Out (each with its landing milestone): desired-state schemas + policy merge +
drift *remediation* (M4), enrollment/compliance (M5), agent methods (M7+),
approvals/JIT elevation (M9), audit rotation (M5 follow-up, documented in
ipc.md section 6), `punarctl update status` (stays stubbed; the M0 skeleton
labeled it M3 — retarget its stub text to the update-architecture milestone
when touched).

## 2. Decision summary

| # | Decision |
|---|----------|
| 1 | NDJSON over UDS at **`/run/punard/punard.sock`** — deliberate variation from `/run/punar/…` because `/run/punar` is the M1 punar-writable artifact dir (0755 `punar:punar`); a socket in a peer-writable dir can be unlinked and squatted. Justification and full contract: ipc.md section 1. |
| 2 | Envelope `{v:1, id, method, params}` / `{v:1, id, result|error{code,message,details}}`; version field `v` required; strict params; errors in section-73 voice. |
| 3 | Methods (closed set): `status`, `capabilities.list`, `capabilities.get`, `capabilities.set`, `audit.tail`, `reconcile`. **No exec/shell method, ever** (spec sections 10, 60). |
| 4 | AuthZ: admission via socket FS perms (`/run/punard` 0750 root:punar, socket 0660 root:punar) + `SO_PEERCRED`; reads any connected peer; **mutations root-only** (`personal-defaults` rule) until M9 JIT. Non-root `capabilities set` gets the section-73 denial and a `decision:"deny"` audit event — that IS the test path. |
| 5 | Capabilities: `security.firewall` (nftables, table `inet punar-base`, inbound-drop/outbound-accept), `system.hostname` (`/etc/hostname` + `/proc/sys/kernel/hostname`, no hostnamectl/D-Bus), `time.timezone` (`/etc/localtime` symlink). All with real observe/apply/verify and schema-conformant descriptors. |
| 6 | Audit: `/var/log/punar/audit.jsonl`, dir 0750 root:punar, file 0640 root:punar, writes only by punard; every mutation + every denial; schema-conformant with documented sentinels (`agt_none`, `project_id:"system"`); rotation OUT. |
| 7 | Build strategy **(a) hermetic in-container build**: `rust 1:1.97.1-1` from the pinned snapshot added to the builder container; `container-build.sh` compiles `--release --locked` and stages binaries into the desktop extra tree before mkosi. `PUNAR_BUILD_MODE=summary` skips compilation. |
| 8 | `m3-check` runs as root via `punar-m3-check.service` (the service manager IS the root path), started by `idle-ram.sh` after `punar-m2-check`, before export; host gate parses `PUNAR_M3_OK`. |
| 9 | `PUNAR_SERVICES_RSS_MB` = summed **PSS** of `punard.service` cgroup pids (PERFORMANCE_BUDGETS.md §2.3 canonical metric), sampled at end of the idle window, exported through ram-report.txt; check-budgets gate warn > 100 / fail > 150 (KVM only). |

## 3. Daemon architecture

- **No async runtime.** `punard` at M3 serves one low-rate local socket;
  std `TcpListener`-style accept loop over `UnixListener`, thread per
  connection, hard cap 16 concurrent (excess connections get served as slots
  free; the listener simply doesn't accept). Budgets section 6.2 / 1.2 makes
  frugality a gate — a tokio dependency tree is unjustifiable for this load
  profile. Measured RSS is now gated (section 9), so the claim is checked,
  not asserted.
- **Startup order:** read/create device-id → open audit file → load
  `/var/lib/punar/desired.json` (create with defaults on first boot: firewall
  `enabled` [os default], hostname/timezone seeded from first observation
  [os default]) → **boot reconcile** (observe+verify, apply only
  `security.firewall` if the table is absent — the one boot-time apply,
  because the firewall's desired default is a fixed os default, audited
  `source:"service"` — errata: originally planned `"os"`, which is not a
  `principal_kind` enum value; see §12) → bind socket, perms, listen.
- **State:** registry is static (3 capability implementations behind one
  trait: `observe() / apply(desired) / verify(desired) / descriptor()`);
  desired.json is the only mutable store (root 0600); every
  `capabilities.list`/`get` observes live.
- **New workspace dependency: `rustix` (feature `net`)** — for
  `SO_PEERCRED`. Justification: `std`'s `UnixStream::peer_cred` is unstable;
  the alternatives are `libc` + an `unsafe` block (breaks the workspace-wide
  `#![forbid(unsafe_code)]` discipline) or `nix` (larger). `rustix` is
  memory-safe at the call site, widely audited, small feature-gated tree.
  Supply chain: one new crate + `bitflags`/`linux-raw-sys` transitives,
  pinned by the committed `Cargo.lock`.
- **No time crate.** RFC 3339 UTC timestamps via a small
  `utc_now_rfc3339()` in `punar-common` (civil-from-days algorithm, unit
  tested against known values). `chrono`/`time`/`jiff` rejected: one
  function does not justify a dependency tree (budget + supply chain).
  Event ids: `evt_` + unix-millis + per-process counter (schema pattern
  `^evt_[A-Za-z0-9]+$`).
- **Redaction:** no M3 method carries a secret; the existing
  `punar_common::Redacted` (53 tests green) is the required type for any
  future secret-bearing field, keeping section 53's never-log rule
  structural.
- `punard.service` (desktop extra tree, versioned): `Type=simple`,
  `ExecStart=/usr/bin/punard run` (new `run` subcommand replaces the M0
  stub-error path; `check-config` stays a stub), `Restart=on-failure`,
  minimal hardening now (`NoNewPrivileges=yes`, `PrivateTmp=yes`,
  `ProtectHome=yes` — NOT `ProtectSystem`, it writes `/etc/hostname` and
  `/etc/localtime`; the full sandbox profile is later-milestone work).
  **Enablement is a vendor-level symlink**
  `usr/lib/systemd/system/multi-user.target.wants/punard.service` in the
  desktop `mkosi.extra` — never postinst `systemctl`, never `/etc` (the
  twice-verified M1 preset lesson). tmpfiles `usr/lib/tmpfiles.d/punard.conf`
  per ipc.md section 1.1.

## 4. Capability set — backends and descriptors (spec section 41)

All three have real observe + apply + verify; descriptors serialize exactly
per `schemas/capability/capability-descriptor.json` (the
`security-firewall.json` example is the shape reference). Common fields:
`supported: true`, `mutable: true`, `requires_reboot: false`,
`managed_by: "local"` (personal mode; becomes `"smplify"` only after
enrollment), `privilege_required: "root"`, `approval_requirement: "allow"`
(no approval gates until M9 — root-only-ness is authz, not approval).

### 4.1 `security.firewall`

- **Package fact (verified 2026-08-25 against ALA snapshot 2026/08/20):**
  `nftables 1:1.1.6-3` is in the snapshot's `extra` repo and is **not** in
  the image today — `base`'s dependency chain (checked in the snapshot's
  `core.db`: base → iproute2/systemd/…) pulls neither `nftables` nor
  `iptables`. **Action: add `nftables` to the desktop profile package list**
  (`os/images/mkosi.profiles/desktop/mkosi.conf`). Do **not** enable
  `nftables.service` (it would load `/etc/nftables.conf` and make two owners
  of the ruleset); `punard` owns firewall state, applied at boot reconcile.
- **States:** `enabled` | `disabled` (`allowed_desired_states`), desired
  default `enabled` (os default; spec section 44.4 default-deny inbound).
- **Ruleset** (vendored at `/usr/share/punar/nftables/punar-base.nft`,
  versioned in the desktop extra tree): minimal inbound-drop /
  outbound-accept —

  ```text
  destroy table inet punar-base
  table inet punar-base {
    chain input {
      type filter hook input priority filter; policy drop;
      ct state established,related accept
      ct state invalid drop
      iif "lo" accept
      ip protocol icmp accept
      meta l4proto ipv6-icmp accept
    }
    chain forward { type filter hook forward priority filter; policy drop; }
    chain output  { type filter hook output  priority filter; policy accept; }
  }
  ```

  `destroy` (delete-if-exists, in nftables since 1.0.8, snapshot has 1.1.6)
  makes `nft -f` idempotent. icmpv6 accept is required or IPv6 neighbor
  discovery dies; the CI VM is `-nic none` so nothing at runtime needs the
  net, but the ruleset must be correct for real hardware.
- **Backend:** spawn `nft` with **fixed argv, no shell** (typed capability →
  privileged implementation, spec section 10): observe/verify =
  `nft -j list table inet punar-base` (exit nonzero → `disabled`; JSON parsed
  and matched against expected chains/policies → `enabled`, anything else →
  `disabled` + detail in reconcile output); apply enabled = `nft -f <file>`;
  apply disabled = `nft destroy table inet punar-base`.
- Descriptor: `risk: "high"`, `verification: "nftables"`,
  `audit_category: "security"`, `state_schema: {"enum": ["enabled","disabled"]}`.

### 4.2 `system.hostname`

- **Backend: direct, no `hostnamectl`.** Observe: read
  `/proc/sys/kernel/hostname` (canonical `current_state`) and
  `/etc/hostname`; a mismatch is reported as drift detail. Apply: write
  `/etc/hostname` atomically (temp + rename) then write
  `/proc/sys/kernel/hostname`. Verify: re-read both, must equal desired.
  Rationale: pure `std::fs`, no D-Bus/hostnamed dependency, no CLI output
  parsing, works identically in the netless CI VM.
- **Validation** (`invalid_params` otherwise): RFC 1123 label,
  `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`.
- Descriptor: `risk: "low"`, `verification: "kernel+file"`,
  `audit_category: "system"`,
  `state_schema: {"type":"string","pattern": …}`; no
  `allowed_desired_states` (open value space — the schema allows omission).

### 4.3 `time.timezone`

- **Package fact (verified 2026-08-25):** `tzdata 2026c-1` is in the
  snapshot `core` repo and is a hard dependency of `glibc` — `/usr/share/zoneinfo`
  is already in the image; no package change needed.
- **Backend:** observe = `readlink("/etc/localtime")`, normalize by
  stripping the `/usr/share/zoneinfo/` prefix (relative or absolute link
  forms); a non-symlink or out-of-tree target → `current_state: "unknown"`.
  Apply: create symlink at a temp name in `/etc`, `rename(2)` over
  `/etc/localtime` (atomic). Verify: re-observe equals desired.
- **Validation:** segments `[A-Za-z0-9_+-]+` joined by `/`, no `..`, no
  leading `/`, and the target must exist under `/usr/share/zoneinfo`
  (path-traversal guard before any filesystem write).
- Descriptor: `risk: "low"`, `verification: "symlink"`,
  `audit_category: "system"`. Desired default: seeded from observation
  (image ships `UTC` per `mkosi.conf Timezone=UTC`).

## 5. Audit implementation

Contract in ipc.md section 6 (file, modes, sentinels, event population,
rotation-out). Implementation notes: open `O_APPEND|O_CREAT` at startup with
explicit `fchmod 0640` / `fchown root:punar`; serialize
`punar_common::AuditEvent`; write line + flush (no per-line fsync — budget;
crash-loss of the last events is an accepted M3 tradeoff, documented).
Because the schema requires all 12 fields but the Rust `AuditEvent` marks
agent/user/project/resource optional, **punard constructs every event with
all fields `Some(...)`** (sentinels per ipc.md) — and `m3-check` validates
the emitted lines against the schema shape with `jq`, so a regression here
fails CI, not review.

## 6. `punarctl` (D-014 output contract)

- Surface changes: `capabilities` becomes a group — bare
  `punarctl capabilities` = list (preserves the section 11.2 spelling),
  plus `capabilities get <id>`, `capabilities set <id> <state>`; `audit tail
  [-n N]`; `status`; `reconcile`; global `--json`; hidden `debug rpc
  <method>` (test probe, ipc.md section 7). Everything else stays a stub
  with its milestone notice.
- Human output per Plate D-014 (`docs/design/mockups/cli-grammar.html`):
  one formatter module (masthead/rule/row/status-word) — no command formats
  itself; masthead `PUNAR · STATUS` + `<hostname> · Personal`; middle-dot
  separators; labels tracked-uppercase bright-black; status words on ANSI
  semantic slots (lime ok, peach pending, red denied/unknown);
  `DEVICE · PERSONAL` uncolored; **no org/compliance rows in personal
  mode**; firewall row reads `Firewall  Enabled   inbound deny by default ·
  nftables verified <time>`. Non-TTY or `NO_COLOR` → no ANSI, columns keep.
- `--json` prints the IPC `result` verbatim (registry field names
  unchanged) — human table and JSON are two renderers over one struct.
- Exit codes: 0 ok · 1 daemon/runtime error · 2 usage · 3 denied · 4
  approval_required (reserved) · 5 daemon unreachable. The denial path
  prints the server's section-73 `error.message` verbatim to stderr.

## 7. Image integration and build strategy

**Decision: (a) hermetic in-container build.** The builder container gains
the snapshot's own Rust; `container-build.sh` compiles and stages binaries
into the desktop extra tree before mkosi runs.

- **Toolchain pin (verified 2026-08-25):** `rust 1:1.97.1-1` in ALA snapshot
  2026/08/20 `extra` (satisfies workspace `rust-version = "1.85"`;
  includes cargo). Add `rust` to the `pacman -S` list in
  `os/images/builder/Containerfile` — same pinned mirror as everything else
  (ADR-001), no rustup, no second toolchain provenance.
- **`container-build.sh`:** new `stage_punar_binaries()` — run only when
  `MODE=build` and desktop is in `PUNAR_IMAGES`:

  ```sh
  CARGO_HOME=/work/os/images/cache/cargo \
  CARGO_TARGET_DIR=/work/os/images/cache/cargo-target \
    cargo build --release --locked -p punard -p punarctl
  install -m 0755 .../release/punard .../release/punarctl \
    mkosi.profiles/desktop/mkosi.extra/usr/bin/
  ```

  Staged binaries are gitignored (extend `os/images/.gitignore` with
  `mkosi.profiles/desktop/mkosi.extra/usr/bin/`), same pattern as the staged
  desktop assets. Putting cargo's home/target under `os/images/cache` rides
  the existing CI cache key alongside the mkosi package cache.
- **`PUNAR_BUILD_MODE=summary` skips compilation entirely** (the staging
  function is gated on `MODE=build`), so the cheap local config-validation
  path stays cheap. `mkosi summary` does not require extra-tree contents.
- **Honest hermeticity limit:** crates.io is fetched at image-build time for
  `serde`/`serde_json`/`thiserror`/`clap`/`rustix` — the one build input not
  served from the Arch snapshot. It is pinned by the committed `Cargo.lock`
  (`--locked` refuses drift) and checksummed by cargo; the CI cache makes it
  a warm no-op. `cargo vendor` (fully offline) was considered and rejected
  for repo bloat; revisit if the supply-chain bar rises. The **runtime** VM
  needs no network — binaries are dynamically linked against the snapshot's
  glibc inside the image, nothing fetches at boot (hard CI constraint:
  `-nic none`).
- **Local-dev implications (honest):** on the arm64 Mac the desktop image
  build now also compiles two release binaries under amd64 emulation —
  expect roughly +10–30 min cold, much less warm (cargo cache persists in
  `os/images/cache`). The dev loop is unchanged: host-side
  `docker run rust:1 … cargo test` for code, `PUNAR_BUILD_MODE=summary` for
  image config; full local builds remain non-authoritative (spec 1.22
  labeling), CI x86_64 is canonical.
- **Rejected (b) CI artifact handoff:** the rust job builds on
  `ubuntu-24.04` with a rustup toolchain — a second, differently-pinned
  toolchain and glibc lineage (violates the spirit of ADR-001's
  single-snapshot inputs), plus an inter-job artifact-name contract and
  download failure mode, purely to save compile minutes that the cargo
  cache already saves. No hard blocker exists for (a), so per the decision
  rule, (a) it is.

New image content summary (all in the desktop profile): package `nftables`;
versioned extra-tree files `usr/bin/` (staged binaries), `punard.service` +
`multi-user.target.wants/` symlink, `usr/lib/tmpfiles.d/punard.conf`,
`/usr/share/punar/nftables/punar-base.nft`, `usr/lib/punar/m3-check.sh`,
`punar-m3-check.service`.

## 8. In-VM exercise plan — `m3-check`

Mechanics mirror M2: `punar-m3-check.service` (root, `Type=oneshot`,
`TimeoutStartSec=10min`, not enabled) runs `/usr/lib/punar/m3-check.sh`,
which always exits 0 and writes `/run/punar/m3-report.txt` with per-assertion
`ok`/`FAIL` lines and a final `PUNAR_M3_OK` / `PUNAR_M3_FAIL` verdict.
`idle-ram.sh` starts it synchronously **after** `punar-m2-check.service` and
**before** the artifact export, so the report ships in the same tar and the
mutations (hostname!) never pollute the idle window. `tools/boot-test.sh`
gains a phase that copies `m3-report.txt` from the export and hard-fails on
`PUNAR_M3_FAIL` or a missing report (same as the M2 gate).

**How the check gets root for the allowed path:** the service manager —
`punar-m3-check.service` has no `User=`, so the script runs as root; that is
the decided root path (no sudo, no helper binaries). Unprivileged paths use
`runuser -u punar --` / `runuser -u nobody --` (util-linux, in base).

Assertions (all via `--json` + `jq` where output is machine-checked):

1. `systemctl is-active punard.service` — daemon up from boot (vendor
   enablement worked).
2. Socket perms: `stat -c '%U:%G %a'` → `/run/punard` = `root:punar 750`,
   `/run/punard/punard.sock` = `root:punar 660` and is a socket.
3. `punarctl --json status` (root): exit 0; jq asserts `protocol_version==1`,
   `mode=="personal"`, `enrolled==false`, `device_id` matches `^dev_`,
   `capabilities_total==3`.
4. `runuser -u punar -- punarctl --json capabilities`: exit 0 (read path open
   to group punar); jq finds the `security.firewall` descriptor with
   `current_state=="enabled"`, `verification=="nftables"`,
   `managed_by=="local"`; cross-check reality:
   `nft -j list table inet punar-base` exits 0 (the state is a live nftables
   read, not a config echo).
5. Allowed mutation (root): `punarctl capabilities set system.hostname
   punar-m3` → exit 0; `/proc/sys/kernel/hostname` and `/etc/hostname` both
   read `punar-m3`; newest audit event (via `punarctl --json audit tail`) has
   `action=="capabilities.set"`, `resource=="system.hostname"`,
   `decision=="allow"`, `result=="success"`, `user_id=="root"`.
6. **Denial (the section-73 test):** `runuser -u punar -- punarctl
   capabilities set system.hostname mallory` → exit code 3; stderr contains
   `administrator` and `personal defaults` (voice check, not full-text
   match); hostname still `punar-m3`; audit gained an event with
   `decision=="deny"`, `user_id=="punar"`, `result=="denied"`,
   `policy_ids==["personal-defaults"]`.
7. Drift visibility + firewall apply: `nft destroy table inet punar-base`;
   `punarctl --json reconcile` (root) → `drift_count==1` with
   `security.firewall` `current_state=="disabled"`, `drift==true` (M3
   reports, does not remediate); then `punarctl capabilities set
   security.firewall enabled` → `nft -j list table inet punar-base` exits 0
   again (real apply+verify exercised); second `reconcile` → `drift_count==0`.
8. Audit schema shape: `punarctl --json audit tail -n 20` → jq asserts every
   event has all 12 required keys, `event_id` matches `^evt_`, `decision` in
   `allow|deny|approval_required`, `agent_session_id` matches `^agt_`
   (sentinel included), timestamp matches an RFC 3339 pattern.
9. Socket authz negative (74.4 "unauthorized IPC"): `runuser -u nobody -s
   /bin/sh -- -c 'punarctl status'` → nonzero exit (expect code 5,
   connection denied by 0660 root:punar before the daemon sees it).
10. No-exec probe (section 60): `punarctl debug rpc system.exec` and
    `punarctl debug rpc shell.run` → both fail with the `unknown_method`
    error surfaced (exit 1, message names the method as nonexistent).

Host-side follow-ups in the same CI job: `punarctl` is also exercised on the
runner? No — binaries are x86_64-image-only; all M3 behavior checks are
in-VM. Host `cargo test` (existing rust job) carries the unit/integration
layer (spec 74.1/74.2): envelope serde round-trips, authz matrix against a
socketpair with fake creds, capability validators (hostname/timezone
syntax, traversal guards), audit schema conformance against
`schemas/audit/audit-event.json` fixtures.

## 9. Services RSS budget (spec 6.2, PERFORMANCE_BUDGETS.md 1.2/2.3)

- `idle-ram.sh`: immediately after the 5-minute sampling loop (still at
  idle, before `punar-m2-check` starts), read
  `/sys/fs/cgroup/system.slice/punard.service/cgroup.procs` and sum the
  `Pss:` line of `/proc/<pid>/smaps_rollup` across those pids (canonical
  metric and cgroup-based attribution fixed by PERFORMANCE_BUDGETS.md §2.3
  — never process-name matching). Emit one console line:
  `PUNAR_SERVICES_RSS_MB=<n>` (integer MB, rounded up). The variable name
  says RSS (fixed consumer contract); the value is **summed PSS** — stated
  in the report comment, per §2.3's "budget is judged against summed PSS".
  If the cgroup is missing (punard dead) emit `PUNAR_SERVICES_RSS_MB=absent`.
- `tools/boot-test.sh`: extend the ram regex phase to also capture
  `PUNAR_SERVICES_RSS_MB=([0-9]+|absent)` and append it to
  `ram-report.txt`.
- `tests/performance/check-budgets.sh`: new gate — `absent`/missing →
  error (punard must be alive at idle); `> 150` → `::error::` + exit 1
  (MVP ceiling, §1.2); `> 100` → `::warning::` (target). TCG-emulated runs
  downgrade to warnings exactly like the existing RAM gate (§5.2) — except
  `absent`, which fails even under TCG (a dead daemon is not an emulation
  artifact). Today only `punard.service` exists; the sum's unit list grows
  as sibling services ship (agentd M7, netd M12, …).

## 10. Contract follow-ups flagged (not relitigated, just tracked)

- `schemas/audit/audit-event.json` requires `agent_session_id`
  (`^agt_`)/`user_id`/`project_id`/`resource` on every event; daemon events
  have no agent/project. M3 conforms via documented sentinels
  (`agt_none`, `"system"` — ipc.md section 6). Recommend the M4 schema owner
  make the agent fields conditional (`if source == "ai_agent"`); until then
  sentinels are the contract.
- Audit rotation: out of M3, target M5 (ipc.md section 6).
- `punarctl update status` stub currently claims M3; retarget when touched.

## 11. Verification status (spec 1.22)

Verified today (2026-08-25, host macOS + network to archive.archlinux.org):

- `nftables 1:1.1.6-3` present in ALA 2026/08/20 `extra.db`; **absent from
  the image's dependency chain** (base's `%DEPENDS%` in the snapshot
  `core.db` pulls neither nftables nor iptables) → the package addition in
  section 4.1 is required, not precautionary.
- `rust 1:1.97.1-1` present in ALA 2026/08/20 `extra.db` (≥ workspace
  `rust-version` 1.85).
- `tzdata 2026c-1` present in `core.db` and a `%DEPENDS%` entry of `glibc`.
- `/run/punar` ownership conflict (0755 `punar:punar`, tmpfiles) read from
  the shipped `punar-desktop.conf` — basis for the socket-path variation.
- Schema `required` lists and Rust `AuditEvent` optionality mismatch read
  from the shipped files.

Asserted, not yet verified (lands with implementation): `nft -j` output
shape against 1.1.6 (observe parser must be written against the real JSON),
`destroy table` in `-f` files on 1.1.6 (documented ≥1.0.8; confirm in-image),
cargo build time under emulation (estimate), rustix transitive set at lock
time, and every m3-check assertion (that is what CI is for).

## 12. Implementation status (2026-08-25)

M3 is **implemented and image-wired**. What exists:

- **Code:** `punar-common` (`ipc`/`audit`/`time`/`descriptor` modules),
  `punard` (std thread-per-connection daemon, three real backends,
  AuditWriter, boot reconcile), `punarctl` (real `status`/`capabilities`/
  `audit tail`/`reconcile`, D-014 formatter, hidden `debug rpc`). Whole
  workspace green in the `docker rust:1` container 2026-08-25: `cargo fmt
  --check`, `cargo clippy --workspace --all-targets --locked -D warnings`,
  `cargo test --workspace --locked` (199 tests, 0 failed). New workspace
  deps landed: `rustix` (net) per §3, plus `signal-hook` (safe
  SIGTERM/SIGINT; sigaction is unreachable from safe std/rustix — justified
  in the workspace `Cargo.toml`).
- **nft fixtures are real:** captured from the pinned builder container
  (`nftables 1:1.1.6-3`) with `--cap-add NET_ADMIN`; `destroy table`
  verified working in `-f` files and on argv on 1.1.6
  (`crates/punard/tests/fixtures/README.md`) — closing two of the
  "asserted" items in §11.
- **Errata (decide-once, flagged by implementation):** audit `source` for
  daemon-initiated events is **`"service"`**, not the planned `"os"` —
  `"os"` is not a `principal_kind` enum value and the shipped schema is the
  contract (ipc.md §6 errata'd; `AuditActor::daemon()` keeps `user_id:
  "punard"`). Also: `punar_common::AuditWriter` fdatasyncs per event —
  stricter than §5's "no per-line fsync" note; accepted (free at M3 event
  rates), revisit only if the RSS/latency budget complains.
- **Image integration (this section supersedes "new image content summary"
  in §7 as the as-built list):** `rust` in the builder Containerfile;
  `stage_punar_binaries()` in `container-build.sh` (gated on `MODE=build` +
  desktop; summary mode never compiles); staged `usr/bin/{punard,punarctl}`
  gitignored; `nftables` in the desktop package list; versioned extra-tree
  files `punard.service` + vendor `multi-user.target.wants` symlink,
  `tmpfiles.d/punard.conf`, `usr/share/punar/nftables/punar-base.nft`
  (staging in `container-build.sh` now wipes only `usr/share/punar/shell` +
  `theme`, so the vendored ruleset survives), `m3-check.sh` +
  `punar-m3-check.service`; `idle-ram.sh` emits `PUNAR_SERVICES_RSS_MB`
  (summed PSS, punard cgroup) after the sampling window and starts
  `punar-m3-check` after `punar-m2-check`, before the export
  (`punar-idle-ram.service` timeout raised to 85 min); `boot-test.sh`
  phase-5 M3 verdict (delivered `PUNAR_M3_FAIL`/truncated report fails;
  missing report warns under KVM, info under TCG — a silently-dead punard
  is still caught by the RSS gate) + services-RSS capture into
  `ram-report.txt`; `check-budgets.sh` services gate (`>150` fail KVM,
  `>100` warn, `absent`/`missing` fails even under TCG); ci.yml shellcheck
  + artifact lists extended, image cache key now includes `Cargo.lock`.
- **Verified locally 2026-08-25** (arm64 Mac, emulated builder — spec 1.22
  labels): shellcheck v0.11.0 clean on every touched script; `mkosi
  summary` for BOTH images via `PUNAR_BUILD_MODE=summary` (staging runs, no
  compile); workspace green in `docker rust:1` (above); actionlint on
  ci.yml; the rebuilt builder container installs `rust 1:1.97.1-1` from
  the pinned snapshot (`pacman -Q` checked); the EXACT
  `stage_punar_binaries` cargo command (`--release --locked`, snapshot
  toolchain, cache paths) compiled both binaries in the builder container
  under emulation in **~50 s** (the §7 +10–30 min estimate was far too
  pessimistic — the dependency tree is deliberately small); m3-check's jq
  filters exercised against representative result JSON (positive and
  negative cases); check-budgets exercised across the full gate matrix
  (ok/warn/fail/absent/missing × kvm/tcg).
- **CI is the arbiter for** (not locally verifiable): the full hermetic
  image build (mkosi build with the staged binaries), every in-VM m3-check
  assertion, the real socket/audit file modes, boot reconcile applying
  punar-base in the image, and the first real `PUNAR_SERVICES_RSS_MB`
  number against the 100/150 MB budget.

### Status audit addendum (2026-08-25, later the same day)

Independent re-verification by the status audit, against the working tree
as it stood:

- `cargo test --workspace --locked` in the `docker rust:1` container:
  green — **200 tests, 0 failed** (the tree gained one test after the
  199-count run above). fmt/clippy not re-run; the §12 run stands.
- shellcheck v0.11.0 (pinned container): clean on `m3-check.sh`,
  `idle-ram.sh`, `boot-test.sh`, `check-budgets.sh`,
  `container-build.sh`. actionlint: clean on `ci.yml`.
  `tools/validate-schemas.sh`: 15 schemas metaschema-checked, 123
  documents validated, ALL PASS.
- **Live CI state:** the latest run,
  [32825539021](https://github.com/smplify-mdm/punar/actions/runs/32825539021)
  (2026-08-25), is fully green — all five jobs, including the first
  execution of the M2 exercise (`PUNAR_M2_OK`; idle RAM 1157 MB mean /
  1162 MB max, over-target warning). That run **predates every M3
  change**: no CI run has compiled the staged binaries, built the image
  with the M3 extra-tree content, or executed `punar-m3-check`. The first
  M3-inclusive run is the arbiter, exactly per the list above.
- The §7 build-strategy decision is now also recorded as
  [ADR-002 — Distribution of First-Party Binaries](../architecture/adr/ADR-002-first-party-binaries.md)
  (Accepted, 2026-08-25).
- Reproducibility note for the container test runs: `CARGO_BIN_EXE_*`
  paths are baked into test binaries at compile time, so a `target/`
  populated with the repo mounted at `/work` makes the punarctl CLI tests
  fail with `NotFound` when re-run with a different mount point (e.g. the
  `/w` in getting-started.md) until the stale test binary is rebuilt.
  Mount-path artifact, not a code defect — verified both ways today.
