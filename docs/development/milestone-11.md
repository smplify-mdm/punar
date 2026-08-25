# Milestone 11 — Browser and web-app integration: design plan

Spec authority: section 76 Milestone 11 ("Deliver current Chromium, native
launcher integration, project/browser context prototype, and web-app install
flow"), grounded in **section 30** (browser requirements; 30.1 engine
strategy — *"upstream-current Chromium plus a small, auditable Punar
integration layer"*, explicitly **not** a new engine and **not** a deep fork;
30.2 release cadence), **section 31** (web apps as native apps — the eleven
requirements, enumerated and answered with an explicit coverage statement in
§4.9), **section 32** (browser contexts and projects — the `PERSONAL /
ACME WORK / ATLAS / PUNAR` picker, the *potential* isolation list, "a project
workspace can bring forward its project-specific browser context"),
**section 58** (browser / OS update separation — "emergency security updates
should not wait for a full OS release"), **section 62** (browser and web-app
security — the five things Punar may not weaken, and the six things
enterprise policy may control), **section 46** (application policy —
`required` / `denied` / `allowUserInstall`), **section 12.2** (the universal
command center as the install/launch surface; *"Natural language must resolve
to typed capabilities. Never generate and blindly execute shell commands."*),
section 10 (one typed capability layer behind every interface; the blessed
example `InstallApplication(package)`), section 13/14 (window grammar,
workspace state), section 6.1–6.4 (budgets; 6.3 "Continuous high-frequency
polling is prohibited"), section 8 (enrollment gates every org surface),
section 53 (audit), section 61 (local IPC security), section 73 (denial and
explanation voice), section 74.4 (security tests), section 1.22 (honesty),
and ADR-001 (vendor-pinned date-snapshot channels, mkosi-built signed images,
btrfs+snapper rollback for MVP — the document that already records *"spec 58
is substrate-neutral in the end: an upstream-current, independently-updated
Chromium channel is Punar-built on every candidate"*).

Binding prior contracts, **not relitigated**:

- `docs/api/ipc.md` §1–§16 — transport, framing (**4096-byte request line
  limit**, which constrains §11's method shapes), envelope, error codes, the
  closed `punard` method table, root-only mutation with the
  `privilege.request` precedent for a *non-root, always-audited* mutating
  method, the audit contract §6, and §8's permanent non-goal: **no generic
  execution method of any kind**. M11 proposes `ipc.md` **§21–§23**,
  additively, still `v: 1`. **This document does not edit `ipc.md`** — §11
  below is the proposed contract text that M11's implementation lands there.
  (§14–§16 are M9's; §17–§20 are reserved by M10's plan of record.)
- `docs/development/milestone-3.md` — the typed capability API, the
  descriptor schema, the **fixed-argv external-tool pattern** (`nft` is
  invoked as an argv vector, never a shell string) and the observe → apply →
  verify → audit backend shape. M11's second capability, `browser.policy`,
  is that shape applied to a file instead of a ruleset.
- `docs/development/milestone-4.md` — the layered policy document, the
  section 39 precedence merge, `policy.effective` / `policy.explain`, and the
  **reconcile-remediates-drift** loop that produced the firewall drift demo.
  M11's managed-policy capability joins that loop; it does not invent a
  second one.
- `docs/development/milestone-5.md` — enrollment, the `policy.d` org layers,
  the Acme fixtures under `/usr/share/punar/fixtures/acme/`, and the rule
  that org citations exist only while enrolled.
- `docs/development/milestone-6.md` — `punar-env` as a **short-lived user
  CLI, not a daemon**, which is why the services-RSS gate is structurally
  untouched by it. M11 reuses that argument and that discipline exactly.
- `docs/development/milestone-7.md` / `milestone-8.md` — the registry, cgroup
  attribution, the process-class map (which already maps `chromium` →
  `browser`), and the ledger's `NOT YET OBSERVED · MILESTONE n` vocabulary.
  M11 does **not** touch `network_destinations`: that stays **M12**.
- `docs/development/milestone-9.md` / `milestone-10.md` — plans of record for
  approvals/secrets and shadow-AI/remote-query, **being implemented
  concurrently**. M11 writes no file either of them owns.
- `docs/development/milestone-2.md` §6 — `~/.local/state/punar/workspaces.json`
  and `schemas/workspace/workspace-state.json`, **SHIPPED**. The M8 Decision-0
  law holds for a fourth milestone: M11 conforms to shipped schemas; it does
  not extend them. The workspace→context binding travels in a **sibling
  file**, never as a new property of a shipped schema.
- `docs/design/mockups/webapps-browser.html` — **Plate D-013, the acceptance
  reference**: the install card with the storage-context choice, the
  installed web app as a native window with a masthead titlebar and no URL
  bar, and the context picker. Its Sect I–III registers are binding claims;
  its Sect IV "implementation notes" are **wrong about which milestone does
  what** and are corrected in §13.
- `docs/design/DESIGN_LANGUAGE.md` §7 (stroke semantics — *"a solid line
  marks an operating production path; a dashed line marks a mechanism
  outside the current production claim"*; coverage vocabulary
  `FULL`/`PARTIAL`/`UNSUPPORTED`, *"silence is not support"*) and §8
  (unmanaged-first — org chrome appears only when enrolled).

M1 put upstream Chromium 151.0.7922.169-1 in the image and bound it to
`SUPER+B`. That is a browser on a desktop, not browser *integration*: nothing
about it is Punar's, nothing about it is inventoried, and nothing about it
follows a project. **M11 builds the integration layer the spec has described
since section 30.1 and keeps it small enough that a reviewer can read all of
it in an afternoon.**

---

## 0. The architectural laws of this milestone

Five sentences. Every decision below is downstream of one of them.

1. **We compose Chromium; we do not modify it.** Every browser behavior M11
   relies on — app windows without an omnibox, per-profile storage, managed
   policy, the sandbox — is an existing, documented, upstream Chromium
   feature that Punar *selects*. There is no patch, no PKGBUILD fork, no
   build flag, no injected extension, and no runtime library preload. The
   integration layer is argv, files, and records.
2. **The integration layer may only ever make Chromium's security posture
   the same or stronger, never weaker** (spec 62). This is enforced by a
   closed argv allowlist compiled into `punarctl`, a closed policy-key
   allowlist in `punard`, and a **grep-able denylist proved absent in the
   image** — because an invariant a script can check is worth more than a
   sentence in a design document.
3. **A context isolates state, not privilege.** Two contexts are two
   Chromium profile trees owned by the same uid. Punar claims cookies,
   storage, sign-ins, history and extensions; Punar does **not** claim a
   kernel boundary, a separate uid, a namespace, or protection against a
   renderer that has already escaped its sandbox. The install card says this
   in copy, and §5.4 says it in a table.
4. **A web app is a user's application, not a Punar service.** It launches
   in the session's own app slice, never in a `punar-` scope or slice, so
   Chromium's memory is never charged to the section 6.2 services budget —
   and §9 states, without flinching, what that budget therefore does *not*
   measure.
5. **Installing a web app is not a privileged act.** On an unenrolled device
   the user may install what they like; the org's ability to forbid it lives
   in a root-owned Chromium managed-policy file the user cannot write, not
   in a courtesy check inside a CLI the user could replace. Punar states
   which of the two is the enforcement point every time it renders a
   decision.

---

## 1. Scope

**In:** the integration-layer inventory and its never-touch list (§3); the
web-app record, the offline install flow, the generated monogram icon, the
`.desktop` entry with `StartupWMClass`, the launch path through `punarctl`'s
fixed-argv builder, workspace assignment, and clean uninstall (§4); browser
contexts as Chromium profile directories, the naming/storage/isolation
claims, the workspace→context binding, and the enrolled-only org context
(§5); the `browser.policy` typed capability that writes and verifies
`/etc/chromium/policies/managed/punar-managed.json`, joins the M4 reconcile
loop, and is Punar's answer to spec 46 and spec 62's "policy may control…"
(§6); the update-separation argument, the narrow pinned-package exception
channel as **DESIGN-ONLY**, and the one implemented sliver — offline browser
provenance reporting (§7); the §62 security posture, the two-sided
allow/deny data files, and the runtime sandbox evidence the check reads out
of `/proc` (§8); budgets and the honest statement of what the RAM gates
measure (§9); the CLI and the D-013 shell surface (§10); the proposed IPC
contract for `ipc.md` §21–§23 (§11); `m11-check` + boot-test **phase 13** +
`punar-m11.png` (§12); the stale-assertion list the honesty law requires
(§13); the scope-out table (§14).

**Out (documented, never silently dropped):** every row of §14's table, chief
among them — any Chromium source patch or fork, ever (**permanently out**, not
deferred); fetching a web-app manifest or icon over the network at install
time; a real second package repository, its signing key, its ring assignment
and any runtime browser updater (§7 is design only); web-app notifications
(no `org.freedesktop.Notifications` implementation exists in the image until
M13 — §4.9 says `UNSUPPORTED`, not silence); file associations and deep-link
scheme handlers; certificate-root deployment (`SIMULATED` — the plate already
draws it dashed and M11 does not undash it); relay/proxy policy (M12,
`punar-netd`); browser network destinations in the access ledger (**M12 —
unchanged by this milestone**); approval-gated installs for AI agents (M11
refuses them outright instead, §4.4); extension *inventory* and per-site
permission surfacing (no read API without a fork); and any attempt to draw
Punar chrome over Chromium's own window content.

---

## 2. Decision summary

| # | Decision |
|---|---|
| 1 | **No fork, no patch, no build flag, no preload — and this is checkable.** Chromium stays exactly the pinned snapshot package (`chromium 151.0.7922.169-1`, M1 §2.1). The integration layer is argv + files + records. `m11-check` asserts the installed package's own file list is unmodified against the package database and that no Punar-owned file names a Chromium build option. §3.1, §12 group 1. |
| 2 | **No new binary and no new daemon.** The launcher shim *is* `punarctl web-apps launch <id>`, which builds argv as a `Vec<String>` and `execve`s `chromium` (the M3 fixed-argv law, M6 podman precedent). Consequence: `PUNAR_SERVICE_UNITS` in `idle-ram.sh` is **unchanged**, the services-RSS gate is structurally untouched, and the `.desktop` files Punar writes never contain the token `chromium` — so a Chromium flag has no syntactic place to hide in them. §3.2, §4.5, §9.1. |
| 3 | **The argv builder is a closed allowlist, compiled in.** `punarctl` may emit exactly seven Chromium flags (`--app=`, `--user-data-dir=`, `--class=`, `--ozone-platform-hint=auto`, `--no-first-run`, `--no-default-browser-check`, `--disable-features=` **only** with the fixed value `PunarNone` — see §8.2) and nothing else, ever. A unit test asserts the const array; a record field can never become a flag because every record field is validated against a regex before it reaches argv. §3.3, §8.2. |
| 4 | **Web-app install is a typed capability with two front doors, one implementation** (spec 10, 12.2). `punarctl web-apps install …` and the command center's D-013 install card both call the **same** `webapps.install` method on `punard` over the existing socket; the card is a renderer of the CLI's typed action, invoked with fixed argv via `Quickshell.execDetached` — the M9 approval-overlay pattern verbatim. No second code path, no shell string. §4.2, §10.2. |
| 5 | **punard decides and remembers; punarctl materializes.** The record of truth is root-owned (`/var/lib/punar/web-apps/<uid>/apps/<id>.json`, `0600 root:root`), because inventory an administrator may be told about must not be forgeable by the thing being inventoried. The `.desktop` entry, the icon and the profile directory live in the user's home and are **derived artifacts**, rebuildable at any time by `punarctl web-apps sync`. punard never reads or writes a user's home. §4.3. |
| 6 | **`webapps.*` mutations are uid-scoped self-service, not root-only** — the `privilege.request` precedent (any connected peer, mutating, always audited). A peer may install, uninstall and define contexts **only within its own uid's scope**; there is no cross-uid verb and no wildcard. Root is not required because installing a web app on your own machine is not a privileged act (law 5). §4.4, §11.2. |
| 7 | **An agent-attributed peer may not install a web app.** `webapps.install` refuses peers carrying an `agent_session_id` (the M7/M8 attribution path) with a section-73 message naming the human path. It does **not** raise an approval: an installed web app is a persistent launcher identity, and M11 declines to invent a new approval `kind` while M9 is landing. Approval-gated install is tracked in §15. §4.4. |
| 8 | **The install flow fetches nothing.** Three record sources: an explicit `--name` (+ optional `--icon`), a local `--from-manifest <path>` reading Punar's own tiny `punar-webapp.json`, or an org-supplied record in the effective policy document. `--fetch-manifest` is **DESIGN-ONLY**: putting an HTTP client that parses attacker-controlled JSON inside a root daemon deserves its own milestone. This is also what makes the CI check offline-safe without pretending. §4.6. |
| 9 | **Icons are generated, not downloaded.** With no `--icon`, Punar renders a deterministic **monogram** PNG from the app name and origin in the design language (paper ground `#FAF9F6`, ink glyph, 2 px rule), written by a ~120-line dependency-free PNG writer in `punar-common` (stored-deflate IDAT + CRC32 — no zlib crate, no image crate). Deterministic bytes: the same name+origin yields the same sha256, which is exactly how `m11-check` asserts it without `cmp` or `diff`. §4.7. |
| 10 | **Window identity is `punar-webapp-<id>`, set with Chromium's own `--class` and mirrored in `StartupWMClass`.** That single string is what the compositor matches, what the workspace rule targets, what the overview prints, and what `punarctl web-apps list` shows. It is a Chromium feature Punar composes, not a Punar mechanism. §4.5. |
| 11 | **Punar does not repaint Chromium's window, and the D-013 masthead is therefore `PARTIAL`.** The frame, the absence of a URL bar (a consequence of `--app=`, upstream's feature) and the context tag on Punar's own surfaces are `FULL`. The exact `LINEAR · ATLAS` string *inside* the compositor decoration is not: the window title belongs to the page, and taking it away is a fork-shaped change. Coverage stated, delta tracked, no claim beyond the evidence. §4.5, §13. |
| 12 | **A context is a Chromium profile directory selected with `--user-data-dir`, not `--profile-directory`.** `--user-data-dir` is the only option under which "own cookies · storage · sign-ins" is unconditionally true; `--profile-directory` shares one browser process and would make the plate's copy a half-truth. The cost is real and stated: each live context is a whole browser process tree. §5.2. |
| 13 | **The isolation claim is a table, not an adjective.** Cookies, localStorage/IndexedDB/CacheStorage, sign-in state, history, and per-profile extensions: **isolated**. Same uid, same filesystem access, same kernel, one shared GPU process where the platform shares it, and no protection against a post-sandbox-escape renderer: **not isolated, and not claimed**. Certificates and network policy appear in the plate's managed row and are marked `SIMULATED`/`M12` respectively. §5.4. |
| 14 | **`personal` always exists, is never deletable, and is the fallback.** Context ids match `^[a-z0-9][a-z0-9-]{0,31}$`; `personal` is reserved and pre-created; `org-<org_id>` is reserved and **derived from `/var/lib/punar/enrollment.json`** — it appears on enrollment, disappears on unenrollment, and no `webapps.context_create` call can mint or remove it. Unmanaged-first as a data rule, not a CSS rule (DESIGN_LANGUAGE §8). §5.3, §5.6. |
| 15 | **"The workspace brings its context forward" means the binding changes, not that windows migrate or a browser starts.** Switching to workspace `atlas` rewrites `~/.local/state/punar/browser-context.json` (shell-written, `FileView` + `atomicWrites`, debounced 1 s — the M2 pattern, inotify, zero polling), so the *next* `SUPER+B` or context-less web-app launch uses `atlas`. Existing windows are not moved and nothing is auto-launched, because auto-starting a browser on a workspace switch is both slow and rude. The picker prints the cause. §5.5. |
| 16 | **The workspace→context binding is a sibling file, never a new property of `workspace-state.json`.** The shipped M2 schema is not extended (M8 Decision-0 law, fourth application). New file, new tiny schema `schemas/browser/browser-context-state.json`. §5.5. |
| 17 | **`browser.policy` is a new typed capability in punard's registry** — the M3 backend shape applied to a file. `desired_state ∈ {managed, unmanaged}`; the backend renders the effective policy document's `applications`/`browser` blocks into `/etc/chromium/policies/managed/punar-managed.json` (`0644 root:root`), then **verifies by re-reading and hashing**. It joins the M4 reconcile loop, so hand-editing that file is drift and gets remediated within one reconcile period — the firewall demo's shape, a second time, for the mechanism that actually enforces spec 62. §6. |
| 18 | **The policy writer has a closed key allowlist, and it is data.** `browser/integration/policy-allowlist.json` names every Chromium policy key punard may write, one per spec-62 family; an effective-policy block naming anything else is refused with a section-73 message, not written best-effort. Reviewed like `signatures/suspected.json` (M7 §7.1 / M10 decision 22 precedent). §6.3. |
| 19 | **There is a second, independent denylist, and its job is the grep.** `browser/integration/forbidden-tokens.txt` lists every argv flag and policy key whose presence would weaken sandbox, site isolation, process boundaries, certificate validation, or extension security. `m11-check` proves the token set is absent from **every** place a Chromium flag can enter this image — the punarctl binary, both `.desktop` trees, both policy directories, `/etc/chromium-flags.conf` and `~/.config/chromium-flags.conf` (Arch's `chromium` wrapper sources these — a real hole, closed by assertion), the Hyprland config, the shell QML, and `/usr/share/punar/`. Two-sided by design: the allowlist governs what Punar writes, the denylist governs everywhere Punar does not. §8.2, §8.3. |
| 20 | **The sandbox proof is read out of `/proc`, not asserted in prose.** After the fixture app launches: a `--type=zygote` process exists in its tree; every `--type=renderer` has `Seccomp:\t2` and `NoNewPrivs:\t1` in `/proc/<pid>/status`; each renderer's user-namespace inode differs from the browser process's; and `/usr/lib/chromium/chrome-sandbox` is still present, `4755 root:root` — a positive assertion that Punar did **not** strip the setuid fallback. Evidence, not a claim (spec 1.22, 74.4). §8.4. |
| 21 | **Origin pinning is asserted at the argv/policy level, and the honest split is stated.** The launched fixture is a `file://` page (the CI VM has no network), and `file://` has no origin — so the fixture proves the launcher, window, context and sandbox plumbing, while origin pinning is proved on a **second, recorded-but-never-launched** `https://linear.app` app by asserting its generated argv and its `URLAllowlist`/`WebAppSettings` policy rows. Two apps, two honest claims, no pretending. §4.6, §12 group 3. |
| 22 | **Spec 58 versus ADR-001 is a genuine tension and is argued, not waved at.** ADR-001 pins every package to one dated snapshot; a Chromium CVE lands days later; bumping the snapshot date is a whole-OS change. The resolution is a **narrow pinned-package exception channel** (`punar-security`) carrying only an allowlisted package set, each pinned by exact version + sha256, with **its own signing key** — and the crucial asymmetry that the *overlay* says which version while the *image build config* says which packages, so two independent keys must fall for arbitrary code to ship. **This whole channel is DESIGN-ONLY in M11.** §7.2–7.4. |
| 23 | **The one update sliver M11 implements is honest reporting, offline.** `punarctl update status` — an M3-era stub that says *"this stub stays until a milestone claims it"* — grows a **`browser` block only**: installed Chromium version, the channel it came from, the pin provenance, and the age of the pin, all read from the local package database with no network. The fleet-orchestration half of the verb stays a stub and keeps saying so. §7.5. |
| 24 | **Chromium is outside the section 6.2 services budget and inside the user's experience, and both halves are said out loud.** Web apps launch in the session's app slice; `PUNAR_SERVICE_UNITS` does not grow; the section 6.1 idle-RAM figure is defined at "no foreground applications launched" (PERFORMANCE_BUDGETS.md §2.1 item 4) and therefore says **nothing** about a desktop with a browser open. M11 adds a **non-gating, recorded** measurement — `PUNAR_M11_WEBAPP_RSS_MB`, the PSS of one app window in one context — so the number exists in the record before anyone is tempted to guess it. §9. |
| 25 | **Uninstall is clean by construction and destroys nothing by default.** `webapps.uninstall` drops the record; `punarctl` removes the `.desktop` entry, the icon and the workspace rule; the **context profile directory is kept** unless `--purge-data` is passed, and the CLI prints exactly what was kept and where (section 73). `m11-check` asserts with `find` that no `punar-webapp-<id>` path survives anywhere under the home or `/var/lib/punar`, and that `--purge-data` removes the profile tree. §4.8. |
| 26 | **`m11-check`**, root oneshot (`punar-m11-check.service`, never enabled, vendor `.wants` symlink absent by construction), started synchronously by `idle-ram.sh` **after `m10-check`** and strictly before the export — i.e. **after** the idle-RAM sampling window has closed, the M6 container discipline applied to a much larger process tree. Boot-test **phase 13**, verdict `/run/punar/m11-report.txt` (`PUNAR_M11_OK`/`PUNAR_M11_FAIL`), screenshot `/run/punar/punar-m11.png`. Committed `0755`. `sha256sum`, never `cmp`/`diff`. `qs -p /usr/share/punar/shell`. Case-insensitive verdict greps. §12. |

---

## 3. The integration layer — exact surface

### 3.1 What Chromium already does, which Punar merely selects

The single most important table in this document. Every row is an upstream
Chromium feature with upstream documentation and an upstream test suite.
Punar's contribution in every row is **choosing it and recording the
choice**.

| Mechanism | Whose feature | What Punar does with it |
|---|---|---|
| `--app=<url>` | Chromium (app mode) | Opens a window with no omnibox, no tab strip, no bookmarks bar. This is *the* thing that makes an installed web app look native. Punar supplies the URL from the record and nothing else. |
| `--user-data-dir=<path>` | Chromium (profile root) | Selects the storage context. Separate cookie jar, storage, sign-ins, history, extension set, and a separate browser process tree. |
| `--class=<name>` | Chromium (Linux/Ozone WM identity) | Sets the Wayland `app_id` / X11 `WM_CLASS`, giving the compositor a real window identity to match rules against. |
| `StartupWMClass=` in a `.desktop` file | freedesktop Desktop Entry Specification | Lets the shell and compositor tie a launcher entry to the window it produces. |
| Enterprise policy JSON in `/etc/chromium/policies/managed/` | Chromium (managed policy, all platforms) | The **enforcement** point for spec 62's "policy may control extensions, allowed web apps, browser contexts, certificate roots, relay policy, download restrictions". Root-owned; a non-root user cannot write it. |
| The multi-process sandbox, site isolation, cert verification, extension model | Chromium | Nothing. Explicitly, provably nothing (§8). |
| PWA support, WebGPU, WebRTC, passkeys, extension compatibility | Chromium | Inherited by staying upstream — spec 30.1's platform floor is met by *not* reimplementing it. |

Punar's own additions are exactly five kinds of thing:

1. **Records** — `/var/lib/punar/web-apps/<uid>/{apps,contexts}/*.json`.
2. **Derived artifacts** — a `.desktop` entry, a generated icon, a profile
   directory, one compositor window rule per app.
3. **An argv builder** — a closed function inside `punarctl` (§3.3).
4. **A policy renderer** — the `browser.policy` capability backend inside
   `punard` (§6).
5. **Data files** — the argv/policy allowlist and the forbidden-token
   denylist, in `browser/integration/` (§8.2).

That is the whole layer. There is no sixth kind.

### 3.2 Where the code lives (and a stated deviation from spec 67)

Spec 67 suggests `browser/integration/` as the browser home. M11 splits it,
and says why:

- **Code** goes in the existing workspace crates — the argv builder in
  `crates/punarctl`, the record store and policy renderer in
  `crates/punard`, the PNG monogram writer in `crates/punar-common`. Every
  other crate in this repo lives under `crates/`, cargo workspace hygiene is
  uniform, and spec 67 says "Suggested… Adapt for actual substrate."
- **`browser/integration/`** holds the layer's **auditable non-code
  surface**: `policy-allowlist.json`, `forbidden-tokens.txt`,
  `desktop-entry.template`, `README.md` (the human-readable statement of
  exactly what §3.1 says), and `fixtures/` (§12).

The practical benefit is decision 2's: **there is no new binary**, so there
is no new thing to audit for flags. `Exec=` in every Punar-written
`.desktop` file names `punarctl`, never `chromium`.

### 3.3 The argv builder — closed by construction

```rust
// crates/punarctl/src/webapps/launch.rs — the complete flag vocabulary.
const ALLOWED_CHROMIUM_FLAGS: [&str; 7] = [
    "--app=",                    // value: the record's start_url, re-validated
    "--user-data-dir=",          // value: the context profile dir, absolute
    "--class=",                  // value: "punar-webapp-<id>"
    "--ozone-platform-hint=auto",// exact, no value form
    "--no-first-run",            // exact
    "--no-default-browser-check",// exact
    "--disable-features=PunarNone", // see §8.2 — present ONLY as this literal
];
```

Rules, each unit-tested:

- The builder returns a `Vec<String>`; it never constructs a shell string and
  is never passed to `sh -c`. (M3's `nft` law, M6's podman law.)
- Every interpolated value is re-validated **at launch time**, not trusted
  from the record: `start_url` must parse as `https://` or `file://` with no
  whitespace, no `--`, and no embedded NUL; the context id must match
  `^[a-z0-9][a-z0-9-]{0,31}$`; the app id must match the same regex; the
  profile path must be an absolute path under the caller's own
  `$XDG_DATA_HOME/punar/browser/contexts/`.
- Any record that fails validation is refused with a section-73 message. A
  corrupt record produces a refusal, never a partially-built argv.
- A unit test asserts the const array's exact contents, so widening the
  vocabulary is a visible diff on a seven-line array, not an incidental
  change inside a builder function.

### 3.4 What Punar must never touch — the standing list

Permanently out, not deferred (this list is repeated in §14 as scope rows and
in §8.1 as the security posture):

- Chromium source patches, `PKGBUILD` forks, custom build flags, custom
  `gn` args, or a vendored Chromium tree.
- `LD_PRELOAD`, injected shared objects, `ptrace`, or any in-process hook.
- A Punar-authored Chromium extension, or `--load-extension` /
  `--disable-extensions-except` in any form.
- Any use of the DevTools protocol (`--remote-debugging-port`,
  `--remote-debugging-pipe`) for product functionality.
- Overriding the certificate store, the CT policy, or the sandbox
  configuration.
- Drawing Punar UI inside Chromium's window content area.

---

## 4. Web-app install flow

### 4.1 The shape of the thing being installed

`schemas/browser/web-app.json` (new schema domain `browser`; M11 creates it
rather than extending any shipped schema — Decision-0 law):

```json
{
  "v": 1,
  "id": "notes",
  "name": "Notes",
  "start_url": "file:///usr/share/punar/fixtures/webapps/notes/index.html",
  "origin": "file://",
  "context": "personal",
  "icon": {"kind": "generated", "sha256": "…", "path_rel": "hicolor/256x256/apps/punar-webapp-notes.png"},
  "workspace": "atlas",
  "installed_at": "2026-08-25T11:02:00Z",
  "installed_by": {"uid": 1000, "source": "cli"},
  "policy_ids": ["personal-defaults"],
  "managed": false
}
```

Ten required fields, all flat, all small — one record fits comfortably inside
`ipc.md` §2's **4096-byte request line limit**, which is precisely why the
install verb takes one app at a time and there is no bulk-install method.

`punar-webapp.json` (the manifest a fixture or an org may hand us) is the
same document minus `installed_at` / `installed_by` / `policy_ids` /
`icon.sha256`. It is Punar's own tiny format — **not** a W3C Web App
Manifest, because parsing a W3C manifest means fetching one, and §4.6 says we
do not fetch.

### 4.2 Who owns the flow (spec 10, 12.2) — recommendation and justification

**Both surfaces, one typed capability, one implementation.**

Spec 10 draws Graphical UI → Command Center → CLI → AI Intent → Remote Query
all converging on a single Typed Capability API, and lists
`InstallApplication(package)` among the good examples. Spec 12.2 requires the
command center to be an install surface and forbids it from generating and
blindly executing shell commands. The only architecture satisfying both is:

```text
D-013 install card (punar-shell)          punarctl web-apps install
        │  Quickshell.execDetached                 │
        │  ["punarctl","web-apps","install", …]    │
        └──────────────┬───────────────────────────┘
                       ▼
          punard  ·  webapps.install   (typed, closed, audited)
                       │
        record written ├─► /var/lib/punar/web-apps/<uid>/apps/<id>.json
        artifacts      └─► returned to punarctl, which writes them as the user
```

Why the shell shells out to `punarctl` rather than opening its own socket
client: it is the pattern M9 already established for the approval overlay
(`Quickshell.execDetached(["punarctl","approvals","resolve", …])`), it keeps
the shell free of a second protocol implementation, and it means the
graphical path and the typed path cannot drift — the card *is* the CLI, with
better typography.

Why not "the shell writes the files directly": then the graphical path would
have no audit record and no policy citation, and D-013's own install card
would be unable to print the `Policy · Web app allowed · eng-baseline-v12`
line it draws.

Why not "punard writes everything as root": punard would be writing into a
user's home as uid 0, which is the wrong side of every ownership boundary
this project has drawn so far, and it would make an unenrolled user's own
launcher a root-managed object. Law 5.

### 4.3 Where things live

| Thing | Path | Owner / mode | Why |
|---|---|---|---|
| App record (truth) | `/var/lib/punar/web-apps/<uid>/apps/<id>.json` | root:root `0600` | Inventory an admin may be told about must not be forgeable by the inventoried party. `/var/lib/punar` is already `0700 root:root` (M3 tmpfiles). |
| Context record (truth) | `/var/lib/punar/web-apps/<uid>/contexts/<id>.json` | root:root `0600` | Same, plus: the org context must be underivable by the user (§5.6). |
| Launcher entry | `~/.local/share/applications/punar-webapp-<id>.desktop` | user `0644` | freedesktop location; the shell's launcher and the compositor read it. |
| Icon | `~/.local/share/icons/hicolor/256x256/apps/punar-webapp-<id>.png` | user `0644` | Icon theme spec location; generated, deterministic. |
| Context profile | `~/.local/share/punar/browser/contexts/<ctx>/` | user `0700` | Chromium's `--user-data-dir`. `0700` because it holds sign-in state. |
| Active-context state | `~/.local/state/punar/browser-context.json` | user `0600` | Session preference, shell-written, `FileView` + atomic (§5.5). |
| Managed policy | `/etc/chromium/policies/managed/punar-managed.json` | root:root `0644` | Chromium's enforcement point; world-readable so the user can read what they are subject to (spec 24.2's spirit). |

Everything in the user's home is **derived**. `punarctl web-apps sync` reads
`webapps.list` and rewrites all of it; `m11-check` deletes a `.desktop` entry
by hand, runs `sync`, and asserts it comes back — the firewall drift demo's
shape at the user layer.

### 4.4 Authorization

`webapps.install` / `webapps.uninstall` / `webapps.context_create` /
`webapps.context_delete` are **mutating, always audited, and not root-only** —
the `privilege.request` precedent from `ipc.md` §5's method table. The
authorization rule, evaluated by punard from `SO_PEERCRED`:

1. **uid scope.** A peer may only touch `/var/lib/punar/web-apps/<its own
   uid>/`. There is no `--uid` parameter and no cross-uid verb. A second
   human in group `punar` gets their own scope, not a view of yours.
2. **Agent-attributed peers are refused.** If the peer resolves to an active
   agent session (the M7/M8 attribution path), the call fails `denied` with
   `details.reason: "agent_attributed"` and the section-73 message: *"An AI
   agent cannot install a web app. Installing creates a launcher identity
   that outlives this session. Next step: install it yourself with `punarctl
   web-apps install`, or ask for it in the command center."* No approval is
   raised (decision 7).
3. **Policy.** The effective document's `applications` block (spec 46) is
   consulted: a `denied` entry matching the origin refuses with `denied` and
   `details.policy_ids` citing the pinning source; `allowUserInstall: false`
   refuses everything not in `required`. On a personal device the citation is
   `personal-defaults` and the answer is yes.

**And then the honest paragraph, which the CLI prints and the card renders:**
this policy check is a *courtesy gate*. A user who can run `chromium
--app=…` by hand — and every user can — is not stopped by it. The thing that
actually stops a denied web app is `browser.policy` (§6), a root-owned
Chromium managed-policy file the user cannot write. Punar names which of the
two is doing the work every time it renders a decision, because saying
"blocked" when we mean "discouraged" is exactly the failure spec 1.22
forbids.

### 4.5 Becoming a native window

Three artifacts, produced together:

```ini
# ~/.local/share/applications/punar-webapp-notes.desktop
[Desktop Entry]
Type=Application
Version=1.5
Name=Notes
Comment=Punar web app · context personal
Exec=punarctl web-apps launch notes
Icon=punar-webapp-notes
Terminal=false
StartupNotify=true
StartupWMClass=punar-webapp-notes
Categories=Network;
X-Punar-WebApp-Id=notes
X-Punar-WebApp-Context=personal
```

- `Exec=` names `punarctl`. It cannot carry a Chromium flag, because it does
  not name Chromium. `punarctl`'s clap parser rejects unknown arguments, so
  a hand-edited `Exec=` line with extra tokens fails loudly rather than
  reaching argv.
- `StartupWMClass=punar-webapp-notes` matches the `--class=` the launcher
  passes. The compositor now has a stable identity.
- One compositor rule per app, written into
  `~/.config/hypr/punar-webapps.conf` (a file Punar owns, sourced by the
  M1 config), using the 0.56 field grammar M2 established:

  ```text
  windowrule = match:class ^(punar-webapp-notes)$, workspace name:atlas
  ```

  Workspace assignment (spec 31) is therefore the same mechanism M2 already
  ships for scratchpads — no special case in the window grammar, exactly as
  D-013 Sect IV register 02 promises.
- `SUPER+B` is retargeted from `chromium --ozone-platform-hint=auto` to
  `punarctl web-apps browse`, which opens a normal browser window **in the
  active context**. This is a behavior change to an M1 binding and is listed
  in §13.

**The masthead, stated at its real coverage.** D-013's app-window stage draws
a masthead titlebar reading `LINEAR · ATLAS`. What M11 delivers:

| Element of the plate | Coverage | Mechanism / reason |
|---|---|---|
| No URL bar, no tab strip | `FULL` | `--app=` — upstream's feature. |
| Window has a real, stable identity | `FULL` | `--class` + `StartupWMClass`. |
| Tiles, tabs, workspace-assigns, answers Super-keys | `FULL` | It is an ordinary Wayland window; M2's grammar applies unchanged. |
| Context tag on Punar surfaces (overview, command center, `punarctl web-apps list`) | `FULL` | Those surfaces read the Punar record. |
| The literal `LINEAR · ATLAS` string inside the compositor's window decoration | `PARTIAL` | The window title belongs to the page. Forcing it means either patching Chromium (law 1) or painting over its window (§3.4). Deferred to M13 polish as a compositor-decoration question; tracked in §15. |
| Web content region | not ours | The plate draws it dashed and labels it *"the app draws itself — not ours to draw"*. Correct, and it stays dashed. |

### 4.6 Where the record comes from — three sources, none of them the network

1. **`punarctl web-apps install <url> --name <name> [--icon <path>]
   [--context <ctx>] [--workspace <ws>]`** — the fully offline path. The
   user names it; Punar generates the icon if none is given (§4.7). This is
   the path `m11-check` uses.
2. **`punarctl web-apps install --from-manifest <path>`** — reads a local
   `punar-webapp.json`. This is how fixtures ship and how an org distributes
   an internal app (the file rides the existing policy-fixture channel;
   `/usr/share/punar/fixtures/acme/` already exists from M5).
3. **The effective policy document.** `applications.web_apps.required[]`
   entries are records; `punarctl web-apps sync` installs the missing ones.
   In M11 this is **user-triggered sync only** — reconcile-driven auto-install
   is §15's, because making `punard`'s reconcile loop write into user homes
   is a bigger decision than this milestone should smuggle in.

`--fetch-manifest` is **DESIGN-ONLY**. Its absence is the reason the CI check
is offline-safe without any pretending: there is nothing to stub, because
there is nothing that fetches.

### 4.7 The generated icon — deterministic, offline, and ours

With no `--icon`, Punar renders a monogram:

- 256×256 PNG, RGB8, no alpha.
- Ground `#FAF9F6` (paper), a 2 px `#000` rule inset from the top per
  DESIGN_LANGUAGE §3, and the app name's first one or two letters in ink,
  centred, drawn from a small embedded 5×7 bitmap glyph set (no font
  dependency, no fontconfig call, no Qt).
- Deterministic: the byte stream is a pure function of `(name, origin)`.
  Same input, same sha256, forever.
- Encoded by a ~120-line writer in `punar-common`: PNG signature, `IHDR`,
  one `IDAT` holding a zlib stream of **stored** (uncompressed) deflate
  blocks with a correct adler32, `IEND`, CRC32 per chunk. No `png` crate, no
  `flate2`, no `image` — no new dependency in `Cargo.lock` for a milestone
  whose whole thesis is a small auditable layer.

Why this matters for the check: `m11-check` installs the same app twice into
two contexts and asserts the two icons' `sha256sum` are **equal** — a real
determinism assertion using the only comparison tool the image has.
(The image has no `diffutils`; `sha256sum` is the house comparison.)

### 4.8 Uninstall

`punarctl web-apps uninstall <id> [--purge-data]`:

1. `webapps.uninstall` drops the record (audited, `result: "uninstalled"`).
2. `punarctl` removes, as the user: the `.desktop` entry, the icon, and the
   `windowrule` line from `punar-webapps.conf`.
3. The **context profile directory is kept** unless `--purge-data`, and the
   CLI prints, in section-73 voice: *"Removed Notes. Its browser data is
   kept at ~/.local/share/punar/browser/contexts/personal — it is shared
   with other apps in this context. Next step: `punarctl web-apps context
   delete personal --purge-data` removes it."* Data loss is opt-in and
   always named.
4. If `--purge-data` **and** the app was the sole occupant of a
   non-`personal` context, the profile tree is removed and the context record
   with it.

`m11-check` asserts cleanliness with `find`: after uninstall, zero paths
matching `*punar-webapp-notes*` exist under `/home/punar` or
`/var/lib/punar`, and `punar-webapps.conf` contains no `notes` rule.

### 4.9 Spec 31's eleven requirements — the explicit coverage statement

DESIGN_LANGUAGE §7: *"silence is not support."* So:

| Spec 31 requirement | M11 | Why |
|---|---|---|
| launcher entry | `FULL` | §4.5 |
| icon | `FULL` | §4.7 (generated; fetched icons DESIGN-ONLY) |
| window identity | `FULL` | `--class` + `StartupWMClass` |
| notifications | **`UNSUPPORTED`** | The image contains no `org.freedesktop.Notifications` implementation. M10 ships only the alert sliver it needs; the notification centre is M13. Chromium web notifications will therefore silently fail, and pretending otherwise would be a spec 1.22 violation. Tracked in §15. |
| file associations | **`UNSUPPORTED`** | No `MimeType=` wiring, no portal handler arbitration. §15. |
| deep links | **`UNSUPPORTED`** | `x-scheme-handler` registration without default-handler arbitration is worse than nothing. §15. |
| keyboard shortcuts | `PARTIAL` | Every Punar window chord works (it is a normal window). In-app shortcuts belong to the page. |
| workspace assignment | `FULL` | §4.5 windowrule |
| permission visibility | `PARTIAL` | `punarctl web-apps show <id>` prints what **Punar** granted (context, workspace, policy citation). Chromium's own per-site permission state has no read API without a fork, so it is not surfaced and not claimed. |
| enterprise policy | `PARTIAL` | `browser.policy` writes and verifies the managed file (§6); certificate roots are **`SIMULATED`** (no real org CA exists); relay policy is **M12**. |
| optional separate storage contexts | `FULL` | §5 |

---

## 5. Browser contexts as projects (spec 32)

### 5.1 What a context is

**A context is a Chromium profile directory plus a Punar record naming it.**
Nothing more. There is no Punar process mediating browser state, no shim
between Chromium and its own storage, and no interception of anything.

### 5.2 `--user-data-dir`, not `--profile-directory` — and what it costs

| | `--user-data-dir=<dir>` | `--profile-directory=<name>` |
|---|---|---|
| Cookies / storage / sign-ins separated | yes, unconditionally | yes |
| History, extensions separated | yes | mostly, with shared-component exceptions |
| Separate browser process, zygote, network service | **yes** | no — one browser process serves all profiles |
| Two org identities cannot leak through a shared network stack | yes | not claimable |
| Memory cost of a second live context | a whole browser process tree | small |

M11 chooses `--user-data-dir` because D-013's install card prints *"Own
cookies · storage · sign-ins"* as a flat claim, and the only option under
which that claim needs no footnote is a separate user-data-dir. The cost is
real, is stated in the picker, and shapes §9: **Punar does not keep contexts
warm.** Only the active context and any explicitly opened ones are running.

### 5.3 Naming and storage

- Context id: `^[a-z0-9][a-z0-9-]{0,31}$`. Display name: the M2 workspace-name
  regex, `^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$`.
- `personal` is **reserved and always exists**. It is created on first
  `webapps.*` call, cannot be deleted, and is the fallback whenever a
  binding resolves to nothing.
- `org-<org_id>` is **reserved and derived** — see §5.6.
- Project contexts are ordinary user contexts named after the project
  (`atlas`, `punar`). Creating one is `punarctl web-apps context create
  atlas`; nothing about the name is magic.
- Profile trees: `~/.local/share/punar/browser/contexts/<id>/`, mode `0700`,
  created by `punarctl` as the user.

### 5.4 The isolation claim — a table, because an adjective would be a lie

| Property | Isolated between contexts? | Basis |
|---|---|---|
| Cookies | **yes** | separate cookie store per user-data-dir |
| localStorage / IndexedDB / CacheStorage / Service Workers | **yes** | separate profile storage tree |
| Sign-in state, tokens held in web storage | **yes** | consequence of the above |
| History, downloads list, autofill | **yes** | separate profile |
| Installed extensions and their state | **yes** | separate profile |
| Browser process, zygote, network service | **yes** | separate `--user-data-dir` ⇒ separate browser instance |
| Tabs | **yes** | separate windows of separate instances |
| Unix uid | **no** | same user runs both — *not claimed* |
| Filesystem access available to an escaped renderer | **no** | a renderer that has escaped the sandbox runs as the user and can read the other context's profile — *not claimed* |
| Kernel namespaces, cgroups, or a security boundary between contexts | **no** | *not claimed, and never described as isolation* |
| Certificates / certificate roots | **`SIMULATED`** | the managed row in D-013 carries a dashed `SIMULATED` tag; M11 does not deploy a real root and does not undash it |
| Network policy / routing | **M12** | `punar-netd` does not exist; nothing about a context routes differently today |

The install card's copy — *"A separate context isolates state, not security —
no claim beyond that"* — is this table compressed to one sentence, and it is
the sentence M11 ships.

### 5.5 How a project workspace brings its context forward

**Binding file** (new, sibling — never a property of the shipped M2 schema):

```json
// ~/.local/state/punar/browser-context.json   (user 0600)
{
  "version": 1,
  "updated": "2026-08-25T11:20:00Z",
  "active": "atlas",
  "active_cause": "workspace:atlas",
  "bindings": [
    {"workspace": "atlas", "context": "atlas"},
    {"workspace": "punar", "context": "punar"}
  ]
}
```

Schema: `schemas/browser/browser-context-state.json`. Writer: `punar-shell`,
on the Hyprland workspace event it already subscribes to, via `FileView` with
`atomicWrites: true`, debounced 1 s — the M2 `workspaces.json` mechanism
exactly. **Event-driven, inotify-backed, no timer, no polling loop**
(spec 6.3). `punarctl web-apps context use <id>` is the manual writer and sets
`active_cause: "manual"`.

**What "brings forward" means, precisely:**

- ✅ The *next* launch that does not name a context uses `active` — that is
  `SUPER+B`, and any web app installed without a pinned `--context`.
- ✅ The picker and the command center print the cause: *"Active · Atlas —
  switched by workspace, or here by hand"*, which is D-013's own copy.
- ❌ Existing windows are **not** migrated. A running Chromium cannot change
  its `--user-data-dir`.
- ❌ Nothing is auto-launched. Starting a browser because someone pressed
  `SUPER+2` would be slow, surprising, and would put a several-hundred-MB
  process on the far side of a keystroke.

Both ❌ rows are printed by `punarctl web-apps context status`. This is the
honest reading of spec 32's *"can bring forward its project-specific browser
context"*, and it is what D-013 draws — the picker names the cause, it does
not animate a migration.

### 5.6 Personal versus managed (spec 8, DESIGN_LANGUAGE §8)

The `ACME WORK` row **is not a styled variant of a user context.** It is a
different kind of object:

- It is **derived**, at read time, from `/var/lib/punar/enrollment.json`
  (root-owned, M5). `webapps.list` synthesises it when and only when that
  file reports an active enrollment.
- `webapps.context_create` refuses the id `org-*` with
  `invalid_params`. `webapps.context_delete` refuses it with `denied` and
  the section-73 line naming `punarctl enroll stop` as the actual next step.
- On `enroll stop` it disappears from every surface, and — matching the
  D-013 mockup's own JavaScript, which falls back to the workspace context
  when leaving managed mode — if it was active, `active` falls back to the
  current workspace's context, then to `personal`.
- Its profile tree is *not* purged on unenrollment by default. Unenrolling is
  a local act (M5); silently destroying the user's signed-in state would be a
  surprise. `punarctl web-apps context delete org-acme --purge-data` is the
  named next step.

Three independent gates make the whole managed path structurally inert on a
personal device, in the M10 decision-20 style: (a) `enrollment.json` does not
exist, so no org context is synthesised; (b) no org policy layer exists, so
`browser.policy`'s effective document has no `applications` block and the
capability's desired state is `unmanaged`; (c) the managed policy file is
therefore **absent**, not empty — and `m11-check` asserts its absence on the
personal pre-state before enrollment is ever exercised.

---

## 6. Enterprise policy: `browser.policy` (spec 46, 62, 12.2)

### 6.1 Why this is a capability and not a method

Spec 62 says *"Enterprise policy may control extensions, allowed web apps,
browser contexts, certificate roots, relay policy, and download
restrictions."* Every one of those is **desired state**, not an action. The
M3/M4 machinery for desired state already exists, is already reconciled,
already produces drift remediation and audit events, and already renders in
`punarctl compliance`. Adding a method would be building a second version of
it.

So: `browser.policy` becomes the registry's fourth capability, alongside
`security.firewall`, `system.hostname`, `time.timezone`.

| Descriptor field | Value |
|---|---|
| `capability` | `browser.policy` |
| `allowed_desired_states` | `["managed", "unmanaged"]` |
| `current_state` | observed live: `managed` if `/etc/chromium/policies/managed/punar-managed.json` exists **and** its sha256 equals the hash of the freshly-rendered document; `unmanaged` if absent; `drifted` if present and mismatched |
| `mutable` | `true` |
| `requires_reboot` | `false` (Chromium re-reads managed policy on next start; running instances are told so by the CLI) |
| `risk` | `medium` |
| `privilege_required` | root |
| `audit_category` | `policy` |
| `verification` | `file_hash` |

Backend (the M3 shape, verbatim): **observe** (hash the file) → **apply**
(render from the effective document, write `0644 root:root` via tmp+rename in
the same directory) → **verify** (re-read, re-hash, must equal) → **audit**.
Failure to verify is `verify_failed`, never a silent success.

### 6.2 Joining the M4 reconcile loop

Because it is a capability, `punard-reconcile.timer` already covers it. Hand-
editing `punar-managed.json` — the single most attractive local bypass of an
enterprise browser policy — is drift, and is remediated within one reconcile
period with a `reconcile.remediate` audit event. **`m11-check` performs the
same demo M4 performs for the firewall**, on the mechanism that actually
enforces spec 62. That is the strongest single assertion in this milestone.

### 6.3 The closed key allowlist

`browser/integration/policy-allowlist.json`, data, reviewed like
`signatures/suspected.json`:

```json
{"v": 1, "families": {
  "extensions":  ["ExtensionInstallBlocklist", "ExtensionInstallAllowlist",
                  "ExtensionInstallForcelist", "ExtensionSettings"],
  "web_apps":    ["WebAppInstallForceList", "WebAppSettings"],
  "urls":        ["URLBlocklist", "URLAllowlist"],
  "downloads":   ["DownloadRestrictions", "DownloadDirectory",
                  "PromptForDownloadLocation"],
  "cert_roots":  ["CACertificates"],
  "hardening":   ["SitePerProcess", "RemoteDebuggingAllowed",
                  "SSLErrorOverrideAllowed", "InsecurePrivateNetworkRequestsAllowed"]
}}
```

Rules:

- A key **not** in this file cannot be written. An effective-policy block
  naming one is refused with `invalid_params` and a section-73 message
  naming the key and the file — never written best-effort, never silently
  dropped.
- The `hardening` family is **value-pinned, one direction only**:
  `SitePerProcess` may only be written as `true`; `RemoteDebuggingAllowed`,
  `SSLErrorOverrideAllowed` and `InsecurePrivateNetworkRequestsAllowed` may
  only be written as `false`. A policy layer asking for the weakening value
  is refused, **even from an org layer** — spec 62 binds Acme too. This is
  the concrete answer to "what does punard writing that file mean for
  section 62": it means Punar's writer is structurally incapable of
  expressing the weakening.
- `CACertificates` is accepted, rendered, and labeled **`SIMULATED`** in every
  surface: the fixture supplies a self-signed test root, no real CA exists,
  and D-013's dashed tag stays dashed.
- `/etc/chromium/policies/recommended/` is **never written** and its absence
  is asserted. A recommended policy is one the user can override; a
  half-enforced enterprise control is worse than an honest absent one.

### 6.4 What this means for spec 46

Spec 46's `applications.required` / `denied` / `allowUserInstall` map onto two
enforcement points, and Punar says which is which:

| Spec 46 concept | Web-app enforcement | Native-package enforcement |
|---|---|---|
| `denied` origin | `URLBlocklist` + `WebAppSettings` in the managed file — **real, root-owned, unbypassable by the user** | out of scope for M11 |
| `required` web app | `WebAppInstallForceList` (Chromium installs it) **and** a Punar record via `web-apps sync` (so it gets Punar's launcher, icon and context) | out of scope |
| `allowUserInstall: false` | courtesy refusal in `webapps.install` (§4.4) **plus** a `URLAllowlist` allowlist-only posture in the managed file, which is the part that binds | out of scope |

Native package policy remains unclaimed. §14.

---

## 7. Update separation (spec 58 versus ADR-001)

### 7.1 The tension, stated without softening

ADR-001 chose vendor-pinned **date-snapshot** channels: every package in an
image comes from one Arch Linux Archive date (`2026/08/20` today), which is
the entire reason builds are reproducible and a channel is a single promotable
object. Spec 58 requires that a Chromium emergency security update *not* wait
for a full OS release.

These pull in opposite directions, and there is no clever framing that makes
them not. Moving the snapshot date to pick up a Chromium CVE fix moves
**every** package — kernel, mesa, Hyprland, Qt — which is a full OS release by
any honest definition, with a full validation cost. Not moving it means
shipping a browser with a known remote-code-execution bug for as long as the
release train takes. ADR-001 already conceded the shape of the answer —
*"an upstream-current, independently-updated Chromium channel is Punar-built
on every candidate"* — without specifying it. §7.2 specifies it.

### 7.2 The narrow pinned-package exception channel (DESIGN-ONLY)

A second repository, `punar-security`, layered **above** the date snapshot at
image-build time, with four properties that together make it narrow enough to
trust:

1. **A closed package allowlist that does not live in the repository.**
   `os/images/security-channel-allowlist.txt` — committed in *this* repo,
   reviewed in *this* repo's PR flow — names the only packages that may be
   taken from the overlay: `chromium` and its direct runtime dependencies,
   enumerated explicitly rather than resolved transitively. The build fails
   if the overlay offers anything else.
2. **Exact pins with content hashes.** Each entry is
   `name = version = sha256`. The overlay cannot ship "latest"; it ships a
   named version whose bytes are checked.
3. **Its own signing key, with its own rotation and its own holder.** The
   snapshot mirror's key does not sign the overlay and vice versa.
4. **The resulting asymmetry, which is the whole point:** the *overlay* says
   **which version**; the *image build config in this repo* says **which
   packages**. Compromising the overlay key gets an attacker a malicious
   Chromium build and nothing else — no kernel, no `punard`, no shell. Two
   independent keys held by two parties must fall for arbitrary code to ship.

Spec 57's staged rollout (`Candidate → Canary → Health → 10% → 50% → 100%`)
applies to the overlay channel with its **own** ring assignment, which is
exactly what spec 58's "staged enterprise browser rollout" asks for: an org
can be on OS ring `stable` and browser ring `canary` simultaneously. Rollback
is the same mechanism as any other: the previous pin, re-pinned.

### 7.3 Delivery to a running machine (DESIGN-ONLY)

Under ADR-001's **declared trajectory** (image-based A/B), a browser-only
update is a new image whose only delta is the overlay packages — small, fast
to build, atomically activated, health-gated, and rolled back by the
bootloader. That is the target and it needs no new mechanism.

Under ADR-001's **MVP substrate** (btrfs + snapper snapshot rollback), a
browser-only update would be a package transaction bracketed by a snapshot.
M11 does **not** build that: a runtime package updater is an update
architecture, not a browser feature, and no section 76 milestone schedules
one. Naming the milestone that would beats shipping half of it.

### 7.4 What is DESIGN-ONLY versus implemented — stated flatly

| Piece | Status in M11 |
|---|---|
| The tension analysis and the channel architecture (§7.1–7.3) | **DESIGN-ONLY** — this document is the artifact |
| A second repository, its metadata, its signing key, its ring assignment | **DESIGN-ONLY** — not built, not stubbed, not mocked |
| A runtime browser updater on the device | **DESIGN-ONLY** — and out of M11's scope entirely (§14) |
| `security-channel-allowlist.txt` and the build-time guard | **DESIGN-ONLY** in M11; the file format is specified above so the M12/M13 implementation has no design left to do |
| Offline browser provenance reporting in `punarctl update status` | **IMPLEMENTED** — §7.5 |

Nothing in M11 downloads anything. The CI VM has no network and the check is
unaffected by every row above.

### 7.5 The implemented sliver: honest provenance, offline

`punarctl update status` is today an M3-era stub whose text reads *"this stub
stays until a milestone claims it."* M11 claims **one block of it** and
leaves the rest stubbed:

```text
PUNAR · UPDATE                                         punar-desktop · dev_9f3k2v8q1x

BROWSER
  Engine          chromium 151.0.7922.169-1
  Channel         snapshot (2026/08/20)
  Pin source      os/images/snapshot.env · PUNAR_SNAPSHOT_DATE
  Pin age         5 days
  Security channel  not configured — browser updates currently ride the OS
                    snapshot pin (SPEC 58 · design: milestone-11.md section 7)

SYSTEM
  Update orchestration is not implemented — SPEC section 11.1 is not scheduled
  by the SPEC section 76 milestone plan; this stub stays until a milestone
  claims it.
```

Everything in `BROWSER` is read from the local package database and the
image's build metadata. No network, no daemon call beyond `status`. The
`Security channel · not configured` line is the honesty: it names the design,
names its document, and does not imply a mechanism exists.

**This fulfils part of an honest placeholder and therefore appears in §13.**

---

## 8. Security posture (spec 62)

### 8.1 What Punar must never do to Chromium

The five upstream properties spec 62 names, and the concrete acts that would
weaken each:

| Property | Forbidden acts |
|---|---|
| **Sandbox** | `--no-sandbox`, `--disable-setuid-sandbox`, `--disable-gpu-sandbox`, `--disable-namespace-sandbox`, `--disable-seccomp-filter-sandbox`, `--test-type`; removing/chmod-ing `/usr/lib/chromium/chrome-sandbox`; disabling unprivileged user namespaces at the kernel level |
| **Site isolation** | `--disable-site-isolation-trials`, `--disable-features=IsolateOrigins`, `--disable-features=site-per-process`, policy `SitePerProcess: false` |
| **Process boundaries** | `--single-process`, `--process-per-site` as a global, `--remote-debugging-port`, `--remote-debugging-pipe`, `--remote-allow-origins`, policy `RemoteDebuggingAllowed: true` |
| **Certificate validation** | `--ignore-certificate-errors`, `--ignore-certificate-errors-spki-list`, `--allow-insecure-localhost`, `--unsafely-treat-insecure-origin-as-secure`, policy `SSLErrorOverrideAllowed: true`, any `CertificateTransparencyEnforcementDisabledFor*` |
| **Extension security** | `--load-extension`, `--disable-extensions-except`, `--allow-legacy-extension-manifests`, shipping a Punar-authored extension by any route |
| (and the general case) | `--disable-web-security`, `--allow-running-insecure-content`, policy `InsecureContentAllowedForUrls`, `InsecurePrivateNetworkRequestsAllowed: true` |

### 8.2 Two data files, two directions

- **`browser/integration/policy-allowlist.json`** (§6.3) — governs what
  Punar *writes*. Closed set, value-pinned in the hardening family.
- **`browser/integration/forbidden-tokens.txt`** — one token per line, every
  string in the table above. Governs everywhere Punar *doesn't* write. This
  is the file `m11-check` feeds to `grep -F -f`.

The odd-looking `--disable-features=PunarNone` in the argv allowlist (§3.3)
deserves its explanation: the flag appears in the allowlist **only** as that
exact literal, so that a future maintainer who needs to disable a Chromium
feature must add a second exact literal to a seven-line const array and a
reviewer sees it in the diff, rather than discovering that
`--disable-features=` accepts a runtime-computed string. If no feature ever
needs disabling, the entry is never emitted; a unit test asserts the value is
never anything else.

### 8.3 The grep invariant — every place a flag can enter this image

Arch's `/usr/bin/chromium` is a **shell wrapper** that sources
`$XDG_CONFIG_HOME/chromium-flags.conf` and `/etc/chromium-flags.conf` before
exec'ing the real binary. Any design that only audits its own launcher misses
that entirely. The complete enumeration `m11-check` scans:

1. `/usr/bin/punarctl` (`grep -a`, binary-safe)
2. `/usr/share/applications/*.desktop`
3. `/home/punar/.local/share/applications/*.desktop`
4. `/etc/chromium/policies/managed/*` and `/etc/chromium/policies/recommended/` (the latter must not exist)
5. `/etc/chromium-flags.conf` and `/home/punar/.config/chromium-flags.conf` (**must not exist**)
6. `/usr/share/punar/**` (shell QML, Hyprland configs, fixtures, check scripts)
7. `/home/punar/.config/hypr/**` (including `punar-webapps.conf`)
8. `/usr/lib/punar/*.sh`
9. The live `/proc/<pid>/cmdline` of every running Chromium process during the exercise

A hit anywhere is `PUNAR_M11_FAIL`. **A grep-able invariant is worth more
than a claim**, and enumerating item 5 is the difference between an invariant
and a comforting one.

### 8.4 Positive evidence the sandbox is intact

Absence of bad flags is necessary, not sufficient. After the fixture app
launches, `m11-check` reads the evidence out of `/proc`:

| Assertion | Reads |
|---|---|
| A zygote exists in the app's process tree | a descendant whose `/proc/<pid>/cmdline` contains `--type=zygote` |
| Every renderer is seccomp-filtered | `Seccomp:\t2` in `/proc/<pid>/status` for every `--type=renderer` |
| Every renderer has no-new-privs | `NoNewPrivs:\t1` in the same file |
| The layer-1 namespace sandbox is active | `readlink /proc/<renderer>/ns/user` ≠ `readlink /proc/<browser>/ns/user` |
| Punar did not strip the setuid fallback | `/usr/lib/chromium/chrome-sandbox` exists, mode `4755`, owner `root:root` |
| Punar did not disable unprivileged userns | `/proc/sys/user/max_user_namespaces` > 0 |
| At least two renderer processes exist for two origins | process-boundary evidence that the multi-process model is running, not collapsed |

These are seven facts about a running system, not seven sentences. The
screenshot (§12) is the human evidence; this table is the machine evidence.

---

## 9. Budgets — the honest position on the elephant

### 9.1 Chromium is outside the section 6.2 services gate

Spec 6.2 budgets *"local control-plane services"* at < 100 MB target /
< 150 MB MVP ceiling. Chromium is a user application. Concretely:

- M11 adds **no daemon**. `PUNAR_SERVICE_UNITS` in `idle-ram.sh` stays
  `punard.service punar-agentd.service` (plus whatever M9 lands). **This
  milestone must not add a unit to that list**, and §13 says so loudly
  precisely because a future reader might think "browser integration" implies
  a browser daemon.
- Web app windows launch from the user's session into the session's own app
  slice — **never** a `punar-` scope or slice. This is the deliberate
  opposite of M6's containers and M7's `punar-agent-<id>.scope`: those
  are managed things Punar is accountable for, a browser window is the
  user's. Putting Chromium in a `punar-` cgroup would charge several hundred
  megabytes to a 100 MB budget and make the number meaningless.
- `punarctl web-apps launch` `execve`s Chromium, so the shim leaves no
  process behind at all.

### 9.2 What the idle-RAM gate measures, and what it does not

PERFORMANCE_BUDGETS.md §2.1 item 4 defines stabilized idle as *"No foreground
applications launched beyond what the default session starts itself."* So:

- ✅ The section 6.1 figure (< 1.0 GB target, 1.5 GB hard ceiling) describes
  **a booted desktop with no browser running**. That is a real and useful
  number — it is the floor the user pays before doing anything.
- ❌ It says **nothing whatsoever** about a desktop with a browser open, and
  therefore nothing about the state most users spend their day in. On the
  8 GB minimum target (spec 5.1), Chromium with a handful of tabs is the
  single largest consumer on the machine, larger than every Punar service
  combined by an order of magnitude.

Saying only the first bullet would be the exact species of dishonesty spec
1.22 forbids: a true number that implies a false thing.

### 9.3 The measurement M11 adds — recorded, not gated

`m11-check` emits, after the exercise and outside the idle window:

```text
PUNAR_M11_WEBAPP_RSS_MB=<summed PSS of one app window's full process tree, one context>
PUNAR_M11_CONTEXT_DELTA_MB=<summed PSS added by opening the same app in a second context>
```

Both are **recorded in `ram-report.txt`, not gated.** Two reasons: the figure
under TCG emulation with llvmpipe is not comparable to real hardware, and a
gate on a number Punar does not control would be a gate on Chromium's
release notes. But the number exists in the record, which means the *second*
context's cost (decision 12's stated price) is a measured quantity rather
than an assertion, and a future milestone that wants to gate it has a
baseline to gate against.

### 9.4 Disk and CPU

- No new timer, no new unit, no new polling loop. The workspace→context
  binding is inotify-driven through the shell's existing `FileView`
  (spec 6.3).
- Writes are per-user-action only: an install writes one record and three
  small artifacts; a context switch writes one small JSON, debounced 1 s.
  Chromium's own profile I/O is Chromium's (spec 6.4 budgets *Punar's*
  telemetry, ledger and logs — and M11 adds none).

---

## 10. Surfaces

### 10.1 CLI (Plate D-014 grammar; spec 11.2)

```text
punarctl web-apps list [--json]
punarctl web-apps show <id> [--json]
punarctl web-apps install <url> --name <name> [--icon <path>] [--context <ctx>] [--workspace <ws>]
punarctl web-apps install --from-manifest <path> [--context <ctx>]
punarctl web-apps uninstall <id> [--purge-data]
punarctl web-apps launch <id> [--context <ctx>]      # the .desktop Exec target
punarctl web-apps browse [--context <ctx>]           # SUPER+B target
punarctl web-apps sync
punarctl web-apps context list [--json]
punarctl web-apps context create <id> [--name <display>]
punarctl web-apps context delete <id> [--purge-data]
punarctl web-apps context use <id>
punarctl web-apps context status
```

D-014 house rules apply unchanged: mono masthead, middle-dot separators,
aligned columns, `--json` on every read verb, **UPPERCASED verdict lines**,
section-73 voice on every refusal, org rows only when enrolled.

```text
PUNAR · WEB APPS                                       punar-desktop · dev_9f3k2v8q1x

ID        NAME     CONTEXT    WORKSPACE   ORIGIN                POLICY
notes     Notes    personal   atlas       file://               personal-defaults
linear    Linear   atlas      atlas       https://linear.app    personal-defaults

CONTEXTS
personal  Personal        cookies · storage · sign-ins · history        default off-project
atlas     Atlas           cookies · storage · sign-ins · history        ACTIVE · workspace atlas

Contexts isolate state, not security. Same user, same machine, same kernel.
```

**Naming delta, recorded honestly:** D-013's context-picker caption reads
*"Same registry as `punarctl app list`"*. M11 ships `punarctl web-apps list`,
because a noun of `app` would claim to list native packages Punar does not
manage (§6.4). The mockup caption should be reconciled when the mockup is
next touched — **not by M11's implementation, which owns no mockup file.**
§13.

### 10.2 Shell (Plate D-013; spec 12.2)

Two additions to `punar-shell`, both following existing patterns:

- **The install card** — the D-013 install-card grammar is the M9 approval-
  card grammar with different content: mono masthead, 2 px rule, one plain
  sentence, grants as chips, the two storage-context rows, the policy
  citation line, `Esc · Cancel` ghost and a single ok-green `Install ↵`
  affirmative. Keyboard-first: `↑↓` chooses the storage row, `↵` confirms,
  `Esc` cancels (spec 12.1). It fires
  `Quickshell.execDetached(["punarctl","web-apps","install", …])` — fixed
  argv, no shell string (spec 12.2).
- **The context picker** — a command-center section listing contexts with
  their isolation meta and the active row's cause. It writes
  `browser-context.json` directly (it is the file's owner, §5.5) and, when
  enrolled, renders the derived `org-acme` row with the `MANAGED` pill and
  the dashed `SIMULATED` cert-roots tag. Unenrolled: those rows do not
  exist — **not greyed out, not present-and-empty; absent** (DESIGN_LANGUAGE
  §8).

Both surfaces are `FileView`/`execDetached` only. The shell gains **no**
socket client, consistent with every milestone since M5.

---

## 11. Proposed IPC contract (to be landed in `docs/api/ipc.md` §21–§23 by M11's implementation)

**This document does not edit `ipc.md`.** The text below is what M11's
implementation lands there, additively, still `v: 1` (§3.3: new methods and
optional result fields are additive). §14–§16 are M9's; §17–§20 are reserved
by milestone-10.md §13.

### 11.1 §21 — Web-app and context contract (M11), punard socket

Transport, framing, envelope, error codes, timeouts: unchanged. All methods
live on `/run/punard/punard.sock`.

### 11.2 §21.1 Method table (additive)

| Method | AuthZ | Mutating | Audited |
|---|---|---|---|
| `webapps.list` | any connected peer (**own uid scope only**) | no | no |
| `webapps.get` | any connected peer (own uid scope) | no | no |
| `webapps.install` | any connected peer **except agent-attributed peers**; own uid scope | yes | always |
| `webapps.uninstall` | any connected peer **except agent-attributed peers**; own uid scope | yes | always |
| `webapps.context_create` | any connected peer **except agent-attributed peers**; own uid scope | yes | always |
| `webapps.context_delete` | any connected peer **except agent-attributed peers**; own uid scope | yes | always |

`webapps.install_all`, `webapps.launch`, `webapps.context_activate` and any
verb accepting a `uid` parameter **do not exist** and answer
`unknown_method`. Launching is not an IPC concern (it is an `execve` in the
user's own session); activation is a session preference in a user-owned file
and is deliberately not a daemon-recorded, audited event — switching
workspaces is not a security event.

### 11.3 §21.2 `webapps.install`

Params:

```json
{"app": {"id":"notes", "name":"Notes",
         "start_url":"file:///usr/share/punar/fixtures/webapps/notes/index.html",
         "context":"personal", "workspace":"atlas",
         "icon": {"kind":"generated"}}}
```

`app` is a `schemas/browser/web-app.json` document minus the server-assigned
fields. Unknown params → `invalid_params` (strict, per §3.1). The whole
request line must fit the 4096-byte limit; an `icon.kind: "file"` variant
carries a **path**, never bytes.

Pipeline: validate → authorize (uid scope, agent refusal, policy) → render
icon if generated → write record (`0600`, tmp+rename) → audit → respond.

Result:

```json
{"app": { "...complete record..." },
 "artifacts": {
   "desktop_entry": "[Desktop Entry]\nType=Application\n…",
   "desktop_path_rel": "applications/punar-webapp-notes.desktop",
   "icon_png_b64": "iVBORw0KGgo…",
   "icon_path_rel": "icons/hicolor/256x256/apps/punar-webapp-notes.png",
   "window_rule": "windowrule = match:class ^(punar-webapp-notes)$, workspace name:atlas"
 },
 "enforcement": {"point": "policy_file", "managed": false,
                 "note": "This check is advisory on an unmanaged device."}}
```

`artifacts` is what `punarctl` writes into the user's home. It is **derived**
— punard can regenerate it from the record at any time, which is what
`webapps.list` with `--artifacts` (a `punarctl`-side flag driving
`webapps.get`) provides for `sync`. `icon_png_b64` is bounded: generated
monograms are ~2 KB, and the method refuses a supplied icon larger than
64 KB, so the response line stays well-bounded even though responses have no
4096-byte cap.

Errors: `denied` (agent-attributed, or policy — `details.policy_ids` cites
the source, `details.reason ∈ {agent_attributed, denied_origin,
user_install_forbidden}`), `invalid_params` (bad id/url/context/regex),
`conflict` (id already installed for this uid), `not_found` (named context
does not exist), `apply_failed`.

### 11.4 §21.3 `webapps.list`

Params: none, or `{"include_artifacts": true}`. Result:

```json
{"apps": [ {...}, ... ],
 "contexts": [
   {"id":"personal","name":"Personal","derived":false,"deletable":false,
    "isolates":["cookies","storage","sign_ins","history","extensions"],
    "profile_path_rel":"punar/browser/contexts/personal"},
   {"id":"org-acme","name":"Acme Work","derived":true,"deletable":false,
    "isolates":["cookies","storage","sign_ins","history","extensions"],
    "simulated":["certificate_roots"], "not_yet_observed":[{"category":"network_policy","milestone":"M12"}],
    "source":"enrollment"}
 ],
 "policy": {"managed": true, "policy_ids": ["eng-baseline-v12"],
            "allow_user_install": true}}
```

The `org-*` context element appears **only while enrolled** and is synthesised
from `enrollment.json` at request time — never persisted as a user context.
`simulated[]` and `not_yet_observed[]` reuse M8/M10's honesty vocabulary
verbatim, so a surface that already knows how to render `NOT YET OBSERVED ·
MILESTONE 12` needs no new code.

### 11.5 §21.4 `webapps.uninstall` / `context_create` / `context_delete`

- `webapps.uninstall`: `{"id":"notes","purge_data":false}` →
  `{"removed": {...record...}, "kept": {"profile_path_rel": "…", "reason": "shared"}}`
  or `{"removed": {...}, "purged": {"profile_path_rel": "…"}}`.
- `webapps.context_create`: `{"id":"atlas","name":"Atlas"}` →
  `{"context": {...}}`. Refuses reserved ids (`personal`, `org-*`) with
  `invalid_params`.
- `webapps.context_delete`: `{"id":"atlas","purge_data":false}`. Refuses
  `personal` and `org-*` with `denied`; refuses a context still referenced by
  an installed app with `conflict` and names the apps.

### 11.6 §22 — `browser.policy` capability (M11)

No new methods. `browser.policy` joins the registry, so
`capabilities.list` / `capabilities.get` / `capabilities.set` / `reconcile` /
`policy.effective` / `policy.explain` / `compliance` all cover it with **zero
protocol change** — the point of having a capability layer. `status`'s
`capabilities_total` goes 3 → 4 and its `compliance.capabilities[]` gains a
row. Both are additive result changes already permitted by §3.3.

`capabilities.set` on `browser.policy` keeps its exact M3 request shape,
root-only authz, error set, and audit action. New error case:
`invalid_params` when the effective document names a policy key outside the
allowlist, or names a hardening key with the weakening value —
`details.key` and `details.allowlist_path` are carried.

### 11.7 §23 — Side contract (M11): `~/.local/state/punar/browser-context.json`

Not IPC. User-owned (`0600`), shell-written, `FileView`-watched. Schema
`schemas/browser/browser-context-state.json`, shape in §5.5.

**Non-authoritative by design, and this time that is not a compromise:** the
file holds a session preference of the user who owns it, for that same user's
own session. Nothing root-trusted reads it. The M9/M10 lesson — a file that
tells a human what to *believe* must be root-owned — does not apply, because
this file tells nobody anything about security; it says which profile the
next window opens with. The root-owned things (records, policy) are root-
owned; the preference is not.

### 11.8 §21.5 Audit additions (M11)

New `action` values on the existing audit contract (§6), same
`schemas/audit/audit-event.json`, no schema change:

| `action` | `resource` | `decision` | `result` |
|---|---|---|---|
| `webapp.install` | `webapp:<id>` | `allow` / `deny` | `installed` / `denied` / `noop` |
| `webapp.uninstall` | `webapp:<id>` | `allow` / `deny` | `uninstalled` / `purged` / `denied` |
| `webapp.context_create` | `browser-context:<id>` | `allow` / `deny` | `created` / `denied` |
| `webapp.context_delete` | `browser-context:<id>` | `allow` / `deny` | `deleted` / `purged` / `denied` |
| `capability.set` (existing) | `browser.policy` | existing | existing |
| `reconcile.remediate` (existing) | `browser.policy` | existing | existing |

`audit_category` is `application` for the `webapp.*` rows and `policy` for
`browser.policy`. The **URL is recorded; the page content, the profile
contents, cookies and any storage value never are** — there is no field
anywhere that could carry them, which is the M8 schema-as-privacy-model
applied to a fourth domain.

---

## 12. In-VM exercise plan — `m11-check`

`/usr/lib/punar/m11-check.sh`, root oneshot (`punar-m11-check.service`,
**never enabled** — no `[Install]`, no `.wants` symlink, asserted by the check
itself), started synchronously by `idle-ram.sh` **after `m10-check`** and
strictly before the artifact export. Committed **`0755`** (a check script
committed non-executable fails `ExecStart` — the standing lesson). `set -u`,
always exits 0; verdict lines into `/run/punar/m11-report.txt`, final
`PUNAR_M11_OK` / `PUNAR_M11_FAIL`; host gate `tools/boot-test.sh`
**phase 13**. All verdict/status greps **case-insensitive**. File comparison
is `sha256sum` — the image has no `diffutils`. Unprivileged commands use the
established session pattern (`runuser -u punar -- env
XDG_RUNTIME_DIR=/run/user/1000 HOME=/home/punar …`). `qs` invocations carry
`-p /usr/share/punar/shell`.

**Ordering discipline.** Every browser process in this exercise starts
**after** the idle-RAM sampling window has closed — the M6 container rule
applied to a much heavier process tree. The check kills every Chromium it
started before it exits, and asserts none survive, so the export and any
later phase see a clean machine.

**Timer discipline.** The check stops `punard-reconcile.timer` at the top for
determinism during groups 1–6 (the m5/m10 precedent) and **restarts it for
group 7**, which is the drift demo and needs the real timer to fire.

**Offline fixtures**, staged by `stage_desktop_extra()` from
`browser/integration/fixtures/` to `/usr/share/punar/fixtures/webapps/`:

- `notes/index.html` — self-contained, inline CSS in the design language, no
  external references of any kind. On load it writes
  `localStorage.setItem('punar-ctx-probe', <value from the URL fragment>)`
  and renders the value, so the page is both the storage probe and the
  screenshot subject.
- `notes/punar-webapp.json` — the manifest for install source 2.
- `notes/icon.png` — a supplied icon, so the `--icon` path is exercised too.

### Groups and assertions

**1 · Preflight and the never-touched invariants.**

1. `punard.service` active; `browser.policy` present in `punarctl
   capabilities` with `allowed_desired_states` exactly `["managed","unmanaged"]`;
   `status --json` reports `capabilities_total: 4`.
2. Chromium is the pinned package and unmodified: `pacman -Qi chromium`
   reports `151.0.7922.169-1`, and `pacman -Qkk chromium` reports **zero**
   modified files. (This is the machine-checkable form of "we did not fork.")
3. `punar-m11-check.service` has no `[Install]` section and no `.wants`
   symlink anywhere under `/usr/lib/systemd`.
4. **The grep invariant.** `grep -a -F -f
   /usr/share/punar/browser/forbidden-tokens.txt` over every path in §8.3
   items 1–8 returns **no** matches. `/etc/chromium-flags.conf`,
   `/home/punar/.config/chromium-flags.conf` and
   `/etc/chromium/policies/recommended/` **do not exist**.
5. Personal pre-state: `/etc/chromium/policies/managed/punar-managed.json`
   is **absent** (not empty — §5.6 gate (c)); `punarctl web-apps context
   list` shows exactly `personal`, and **no** `org-` row.

**2 · Install, offline, both sources.**

6. `punarctl web-apps install file:///usr/share/punar/fixtures/webapps/notes/index.html
   --name Notes --context personal --workspace atlas` (as `punar`) exits 0
   and prints an UPPERCASED verdict line.
7. Record exists at `/var/lib/punar/web-apps/1000/apps/notes.json`, mode
   `0600 root:root`, and validates in-VM with `jq` against the ten required
   fields (host-side JSON-Schema validation happens in CI on the exported
   copy — the VM has no schema validator, the M10 precedent).
8. `.desktop` entry exists, mode `0644`, contains `StartupWMClass=punar-webapp-notes`,
   `Exec=punarctl web-apps launch notes`, and **does not contain the token
   `chromium`**.
9. Icon exists at the hicolor path; is a valid PNG (magic bytes); record's
   `icon.sha256` equals `sha256sum` of the file.
10. **Determinism:** install the same app into a second context (`atlas`) and
    assert the two generated icons' `sha256sum` are **equal**.
11. Install source 2: `punarctl web-apps install --from-manifest
    /usr/share/punar/fixtures/webapps/notes/punar-webapp.json --context atlas`
    round-trips the manifest's fields into the record byte-for-byte for the
    fields the manifest carries.
12. `punarctl web-apps install file://… --name Notes` again → `conflict`,
    exit non-zero, section-73 voice naming the existing id.
13. Audit: exactly the expected `webapp.install` events exist, with
    `resource: "webapp:notes"`, and **no** audit event anywhere in the window
    carries a `localStorage` value, a cookie, or a profile path.

**3 · Origin pinning on a recorded-but-never-launched app (decision 21).**

14. `punarctl web-apps install https://linear.app --name Linear --context atlas`
    succeeds; the record's `origin` is `https://linear.app`.
15. `punarctl web-apps launch linear --dry-run --json` prints the exact argv
    it *would* exec; assert it is exactly the seven-flag vocabulary, that
    `--app=https://linear.app` is present, and that **no** token from
    `forbidden-tokens.txt` appears. Nothing is launched (no network).

**4 · The window is native (the money shot).**

16. Launch: `runuser` the session pattern, `punarctl web-apps launch notes`.
    Wait for the window with `hyprctl -j clients` (bounded, `sleep 1` loop —
    the m2/m4 shape for awaiting an event, not a product polling loop).
17. `hyprctl -j clients` shows a client with `class == "punar-webapp-notes"`
    on workspace named `atlas` — window identity **and** workspace assignment,
    proved from the compositor.
18. The live process's `/proc/<pid>/cmdline` contains `--app=file:///…` and
    `--user-data-dir=/home/punar/.local/share/punar/browser/contexts/personal`,
    and contains **no** forbidden token.
19. **Sandbox evidence**, all seven rows of §8.4.
20. **Screenshot:** `grim /run/punar/punar-m11.png` under the session user
    (m2/m5 session-env pattern), with the app window focused and the shell's
    context pill visible. Screenshot failure is a recorded `FAIL` line, per
    the m2 precedent — never a silent skip.
21. `SUPER+B` equivalence: `punarctl web-apps browse --context atlas` opens a
    browser whose `--user-data-dir` is the `atlas` profile.

**5 · Contexts isolate state.**

22. Both context profile directories exist, mode `0700`, and are disjoint
    absolute paths under `~/.local/share/punar/browser/contexts/`.
23. The `personal` launch (group 4) wrote its probe: `grep -ral
    'punar-ctx-probe-personal' <personal profile>` finds it under
    `Default/Local Storage/leveldb/`. **If it does not, this is a `FAIL`** —
    the assertion cannot silently pass by finding nothing anywhere.
24. The same grep over the **`atlas`** profile finds **nothing**. Then launch
    `notes` in `atlas` with a different probe value, close it cleanly, and
    assert each profile now contains only its own probe value and not the
    other's. This is file-level evidence of cookie/storage separation, not a
    claim about it.
25. Two live contexts ⇒ two distinct browser process trees with distinct
    `--user-data-dir` values and distinct browser-process pids.
26. Workspace binding: rename workspace 1 to `atlas` (m2's dispatcher),
    switch to it, wait past the 1 s debounce, and assert
    `~/.local/state/punar/browser-context.json` reports `active: "atlas"`,
    `active_cause: "workspace:atlas"`. Switch to workspace 2 and assert it
    falls back per the bindings. **Assert no new process, no new timer and no
    browser launch resulted** (`pgrep` count unchanged) — decision 15's ❌
    rows, checked.
27. `punarctl web-apps context status` prints, case-insensitively, both
    honest limits: existing windows are not moved, and nothing is launched.

**6 · Managed policy is real, and the org context is enrolled-only.**

28. `punarctl enroll start acme.com` against the M5 mock (started and stopped
    by this check, m5 discipline). After enrollment: `webapps.list` includes
    the derived `org-acme` context with `derived: true`, `deletable: false`,
    `simulated: ["certificate_roots"]`.
29. `punarctl web-apps context delete org-acme` → `denied`, exit 3,
    section-73 voice naming `punarctl enroll stop`.
30. `punarctl capabilities set browser.policy managed` (root) writes
    `/etc/chromium/policies/managed/punar-managed.json`, `0644 root:root`;
    `jq` asserts every top-level key is in the allowlist, that
    `SitePerProcess` is `true` if present, and that `RemoteDebuggingAllowed`
    / `SSLErrorOverrideAllowed` are `false` if present.
31. **Allowlist refusal:** a fixture org layer naming
    `SSLErrorOverrideAllowed: true` is rejected — `capabilities set` fails
    `invalid_params`, `details.key` names it, the file on disk is
    **unchanged** (sha256 equal to before), and the audit records the
    refusal. *An org layer cannot weaken Chromium either.*
32. **Denied-origin enforcement:** with a `denied` origin in the org layer,
    `punarctl web-apps install <that origin>` refuses with `denied` and
    `policy_ids` citing `eng-baseline-v12`; **and** the managed file contains
    that origin under `URLBlocklist`. The CLI output names the policy file as
    the enforcement point and the CLI check as advisory (§4.4).
33. `punarctl enroll stop` → the `org-acme` context disappears from
    `webapps.list`; if it was active, `active` falls back per §5.6; the
    managed file returns to `unmanaged`/absent; **no org row survives
    anywhere** (unmanaged-first, asserted not assumed).

**7 · Policy drift is remediated (the strongest assertion here).**

34. Re-enroll, set `browser.policy managed`, restart
    `punard-reconcile.timer`, then **corrupt the managed file by hand**
    (append a line as root). Assert `capabilities get browser.policy`
    immediately reports `current_state: "drifted"`.
35. Wait up to 375 s (the m4 firewall-drift budget) for the timer to fire.
    Assert the file's `sha256sum` is restored to the rendered value, that a
    `reconcile.remediate` audit event with `resource: "browser.policy"`
    exists, and that **no manual `punarctl reconcile` was issued in the
    window**. This is spec 62's enforcement point proving it self-heals.

**8 · Uninstall is clean.**

36. `punarctl web-apps uninstall notes` (no `--purge-data`): record gone,
    `.desktop` gone, icon gone, windowrule line gone; the profile directory
    **still exists**; the CLI printed where it is and how to remove it.
37. `find /home/punar /var/lib/punar -name '*punar-webapp-notes*'` returns
    **nothing**.
38. `punarctl web-apps sync` after deleting a `.desktop` by hand restores it
    with an identical `sha256sum` — derived artifacts are recoverable.
39. `punarctl web-apps context delete atlas --purge-data` removes the profile
    tree; `find` confirms.

**9 · Update reporting, offline.**

40. `punarctl update status` exits 0, prints a `BROWSER` block naming
    `chromium 151.0.7922.169-1`, `snapshot (2026/08/20)` and
    `Security channel · not configured`; and still prints the unchanged
    system-orchestration stub text. No network syscall is attempted (the VM
    has none, so any attempt would show as an error line — asserted absent).

**10 · Budgets and cleanliness.**

41. `PUNAR_SERVICE_UNITS` in `/usr/lib/punar/idle-ram.sh` is **unchanged** —
    grep-asserted, so a future edit that adds a browser daemon to the gate
    trips this check.
42. No process named `punar-webapp*` exists (there is no such binary,
    decision 2) and no Chromium process is a member of any `punar-*` cgroup —
    read from `/proc/<pid>/cgroup` for every live Chromium.
43. `PUNAR_M11_WEBAPP_RSS_MB` and `PUNAR_M11_CONTEXT_DELTA_MB` are emitted
    into the report (recorded, not gated — §9.3).
44. Every Chromium started by this check is terminated; `pgrep -c chromium`
    is 0 at exit; `punard-reconcile.timer` is restored to the state found.

**Artifacts exported** (the export tars all of `/run/punar`):
`m11-report.txt`, `punar-m11.png`, `m11-webapp-record.json` and
`m11-context-list.json` (for **host-side** schema validation by
`tools/validate-schemas.py` in CI), `m11-managed-policy.json`, and
`m11-argv-dryrun.txt`.

**Human walkthrough additions** (keyboard-only, extending the M1/M2 lists):
`SUPER+Space` → type `install web app` → the D-013 card → `↓` to choose a
separate context → `↵`; the app appears in the launcher and opens on its
workspace; `SUPER+Space` → context picker → `↑↓↵` switches context and the
next `SUPER+B` opens in it.

---

## 13. Stale assertions this milestone creates (spec 1.22)

The honesty law's second half: when a milestone fulfils an earlier
milestone's honest placeholder, it must name which assertions go stale so
they are updated to assert the **invariant** rather than the placeholder text.
M11 creates six, and one deliberate non-staleness.

| # | Where | What goes stale | Must become |
|---|---|---|---|
| 1 | `crates/punarctl/src/main.rs`, `Command::Update` — *"this stub stays until a milestone claims it"* | **M11 claims the browser half.** Any unit test or check asserting `punarctl update status` exits `FAILURE`, or asserting the stub text is the *whole* output, is now wrong. | Assert `update status` exits **0**, prints a `BROWSER` block with the pinned version and `Security channel · not configured`, **and** still prints the system-orchestration stub text. The stub sentence must be narrowed in the source to name only orchestration. |
| 2 | `docs/development/keyboard-grammar.md` — `SUPER + B  Browser (chromium, Wayland ozone)` and walkthrough step 12 *"chromium launches"* | `SUPER+B` no longer execs `chromium` directly; it goes through `punarctl web-apps browse` and honors the active context. | The binding line becomes *"Browser in the active context"*; walkthrough step 12 asserts a browser window whose `--user-data-dir` is the active context's profile — the invariant, not the binary name. |
| 3 | `os/modules/desktop/hypr/hyprland.conf` line 94, `$browser = chromium --ozone-platform-hint=auto` | The value changes to the context-aware launcher; the `--ozone-platform-hint` flag moves into `punarctl`'s allowlisted argv. | `$browser = punarctl web-apps browse`. Any doc or comment quoting the old value must be updated with it. No committed check greps this line today — verified — so this is a docs-and-config change, not a check change. |
| 4 | `docs/development/milestone-1.md` §2.1 — *"Browser: chromium (upstream, unpatched) … launch/window integration only in M1"* | The *"only in M1"* caveat is fulfilled. | An **M11 amendment note** in the M1 row (the M3-amended-under-M4 convention). M1 is a build record; it is annotated, never rewritten. |
| 5 | `docs/design/mockups/webapps-browser.html` Sect IV — 01 claims M1 ships *"Chromium with the Punar integration layer; install flow writes the launcher entry"*, 03 claims contexts land in *"M3–M4"*, 04 claims the managed context row lands in *"M5"* | **All three are false as shipped.** M1 shipped Chromium with no integration layer; M3–M4 shipped no contexts; M5 shipped no managed context row. M11 does all three. | Sect IV 01/03/04 should read **M11**. Sect III 04's dashed `SIMULATED` cert-roots tag **stays dashed** — M11 does not deploy a real root and must not undash it. The Sect II 04 "Notifications" register must gain a `PARTIAL`/deferred mark (§4.9: `UNSUPPORTED` in M11). The Sect III caption *"Same registry as `punarctl app list`"* becomes `punarctl web-apps list` (§10.1). **M11's implementation owns no mockup file** — this is a tracked design-doc delta for whoever next touches the plate, and it must not be silently left as-is. |
| 6 | `PERFORMANCE_BUDGETS.md` §2.3 — *"Units summed as of M7"* | Not stale, and that is the point: **M11 adds no unit.** Recorded here because a reader encountering "browser integration" may reasonably assume a browser daemon appeared and try to add one. | Add an explicit M11 line: *"M11 adds no service unit — web apps run in the user's session slice by design (milestone-11.md §9.1)."* `m11-check` assertion 41 enforces it. |

**One deliberate non-staleness, stated so nobody 'fixes' it:**
`docs/development/milestone-8.md` §3's process-class map entry
`"chromium": "browser"` remains correct. `punarctl web-apps launch` **`execve`s**
Chromium, so the resulting process's `comm` is `chromium` and the M8
attribution still resolves. And `network_destinations` in the ledger stays
**`NOT YET OBSERVED · MILESTONE 12`** — M11 observes no network traffic
whatsoever, and no surface may start implying otherwise because a browser now
has an inventory.

---

## 14. Scope table

| Item | In M11 | Note |
|---|---|---|
| Chromium source patch, fork, custom build, vendored tree | **never** | Permanently out (spec 30.1, law 1) — not deferred |
| Punar-authored browser extension; `--load-extension` | **never** | Spec 62 extension security |
| DevTools protocol used for product function | **never** | Spec 62 process boundaries |
| Punar UI painted inside Chromium's content area | **never** | §3.4 |
| Upstream-current Chromium in the image | ✅ | Already shipped by M1; M11 asserts it is unmodified |
| `--app=` window, no URL bar | ✅ | Composed |
| Per-context `--user-data-dir` | ✅ | §5.2 |
| `.desktop` + `StartupWMClass` + `--class` window identity | ✅ | §4.5 |
| Workspace assignment via compositor rule | ✅ | §4.5 |
| Generated deterministic icon | ✅ | §4.7 |
| Offline install (2 local sources) | ✅ | §4.6 |
| Network manifest/icon fetch (`--fetch-manifest`) | ✗ | DESIGN-ONLY; needs an HTTP client in a root daemon — its own milestone |
| Clean uninstall, opt-in data purge | ✅ | §4.8 |
| `browser.policy` capability + reconcile drift remediation | ✅ | §6 |
| Closed policy-key allowlist with one-directional hardening pins | ✅ | §6.3 |
| Certificate-root deployment | **`SIMULATED`** | Fixture root only; the plate's dashed tag stays dashed |
| Relay / proxy policy in the managed file | ✗ | **M12** (`punar-netd`) |
| Browser network destinations in the access ledger | ✗ | **M12 — unchanged by this milestone** |
| Web-app notifications | ✗ | **`UNSUPPORTED`** — no notification daemon until M13 (§4.9) |
| File associations, deep-link scheme handlers | ✗ | §4.9, tracked §15 |
| Chromium per-site permission surfacing; extension inventory | ✗ | No read API without a fork |
| Native package install/deny policy (spec 46 non-web half) | ✗ | Unclaimed; no milestone schedules it |
| `punar-security` overlay repo, its key, its rings | ✗ | **DESIGN-ONLY** (§7.2–7.4) |
| Runtime browser updater on the device | ✗ | **DESIGN-ONLY**; an update architecture, not a browser feature |
| Browser provenance in `punarctl update status` | ✅ | §7.5 — offline, local package DB only |
| Reconcile-driven auto-install of `applications.required` web apps | ✗ | §15 — punard's reconcile writing into user homes is its own decision |
| Approval-gated install for AI agents | ✗ | M11 refuses agent peers outright (decision 7); §15 |
| Cross-uid web-app management | **never** | No verb, no parameter (§4.4) |
| A browser daemon of any kind | **never** | Decision 2, assertion 41 |

---

## 15. Deferred, tracked

1. **Web-app notifications** — needs an `org.freedesktop.Notifications`
   implementation. M13 owns the notification centre; the web-app channel
   should ride it rather than growing a second one.
2. **The literal `LINEAR · ATLAS` masthead inside the window decoration** —
   a compositor-decoration question (§4.5), M13 polish. Until then the
   coverage statement is `PARTIAL` on every surface that mentions it.
3. **File associations and deep links** (spec 31) — needs portal handler
   arbitration to be worth shipping.
4. **`--fetch-manifest`** — a network manifest/icon fetcher, with the
   attacker-controlled-JSON-in-a-root-daemon threat model written first.
5. **Reconcile-driven `applications.required` web-app install** — requires
   deciding whether `punard`'s reconcile may cause writes into user homes,
   and by what mechanism (a user-session agent? a login hook?).
6. **Approval-gated web-app install for agents** — a new approval `kind`;
   deliberately not invented while M9 is landing.
7. **The `punar-security` overlay channel** — build-time guard, allowlist
   file, key management, ring assignment (§7.2), and its interaction with the
   A/B trajectory.
8. **Gating `PUNAR_M11_WEBAPP_RSS_MB`** — once real-hardware baselines exist
   and the number is not dominated by llvmpipe under TCG.
9. **Per-context network policy** — the row that makes D-013's `ACME WORK`
   meta line fully true, and it is M12's by name.

---

## 16. Honest limits (spec 1.22)

Written down here so no surface has to discover them:

- **A context is not a security boundary.** Same uid, same filesystem, same
  kernel. A renderer that has escaped Chromium's sandbox can read every
  context's profile. Punar says "isolates state" and never "isolates"
  unqualified.
- **The install policy check is advisory on an unmanaged device**, and Punar
  labels it as such every time. The binding control is the root-owned managed
  policy file, and only while `browser.policy` is `managed`.
- **Certificate roots are `SIMULATED`.** The fixture root is a test artifact.
  No real CA is deployed, no real chain is validated against a Punar-supplied
  anchor, and the plate's dashed tag is correct.
- **Nothing about a context routes differently.** There is no per-context
  network policy, no proxy, no relay. That is M12, and the picker's meta row
  says `M12`, not silence.
- **Punar observes no browser traffic.** Not destinations, not domains, not
  requests. The access ledger's `network_destinations` stays
  **`NOT YET OBSERVED · MILESTONE 12`** and this milestone does not move it
  one inch.
- **Notifications from web apps will not appear** until M13. The coverage
  table says `UNSUPPORTED`; a user who installs Slack as a web app in M11
  gets a window, not a badge.
- **`file://` has no origin**, so the launched CI fixture cannot prove
  origin pinning. The recorded-but-unlaunched `https://linear.app` app proves
  it at the argv and policy level instead, and §12 group 3 says exactly that
  rather than implying a full end-to-end origin test happened.
- **The browser update channel is a design, not a mechanism.** Nothing on the
  device updates Chromium independently today; `punarctl update status`
  prints `Security channel · not configured` precisely so that the gap is
  visible rather than assumed away.
- **`pacman -Qkk chromium` proves the files are unmodified, not that the
  upstream build is trustworthy.** Supply-chain assurance for the Chromium
  package itself is ADR-001's vendor-mirror question, not M11's.
