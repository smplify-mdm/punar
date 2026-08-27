# Punar third-party applications — installation, survival, and update

**Status:** design (proposed) · 2026-08-26 · **Owner:** `punard`
**Unimplemented.** Spec 1.22: nothing in this document ships today. Every
sentence below is a plan until a milestone lands it and
`IMPLEMENTATION_STATUS.md` says so.

**This document extends [`app-catalog.md`](app-catalog.md).** It does not fork
its vocabulary, its five laws, its `source.kind` enum, its trust tiers or its
catalog schema. It answers the three questions app-catalog left to a sibling:

1. What happens to **every** install route when the root slot is replaced —
   not just the Flatpak route app-catalog already blessed.
2. What `punarctl app install <id>` actually **is**, end to end, from typed
   argument to exit code — and what Google Chrome specifically does when you
   type it.
3. Who **updates** an installed application, on what cadence, under whose
   consent, and what can be undone.

**Spec authorities:** §46 (application policy — `required` / `denied` /
`allowUserInstall`; *"Application semantics should remain stable even if the
underlying package system changes"*), §10 (one typed capability layer; never a
generic root RPC), §12.2 (natural language resolves to typed capabilities;
*"Never generate and blindly execute shell commands"*), §16 (avoid
preinstalling toolchains; prefer project isolation), §6.2 (services RSS), §6.3
(no polling loops), §55 (offline behaviour), §57 (update architecture), §58
(browser/OS update separation), §60 (hard safety constraints), §73 (every
restriction explains itself), §1.22 (honesty).

**Binding prior contracts, not relitigated here:**

- [`ADR-003`](../architecture/adr/ADR-003-ab-slots-over-snapper.md) — A/B root
  slots; `/var` and `/home` shared and never rolled back; *"Punar-owned mutable
  `/etc` state becomes a capability output, never a file an update must
  preserve."* §1 below is the same sentence applied to user-installed software,
  which ADR-003 does not cover.
- [`app-catalog.md`](app-catalog.md) — the five laws, the catalog document, the
  `source.kind` enum, `trustTier` × `containment`, the `apps.*` method table,
  the §1.6 bypass list and its recompute-and-refuse rule, the ≤ 3 runtimes cap.
- [`execution-trust.md`](execution-trust.md) — `punar.trustTier` and
  `punar.containment` **unchanged**; the `fanotify` gate, its mark set, origin
  zones, and the `/var` question §6 below closes.
- [`update-and-rollback.md`](../development/update-and-rollback.md) — the
  `update.*` methods, channels, staged rollout, health-gated blessing, the
  metered-link rule (§5.3.2), the offline rules (§11), and the shape of
  `punarctl update status` (§7.2), which §5 below extends and must not
  contradict.
- [`installer.md`](installer.md) §4.3 — `/var`, `/home` and `/var/tmp` are
  **three separate btrfs subvolumes, separately mounted**, on `PUNAR-DATA`.
  This is load-bearing for §6.
- Plate **D-014** (`docs/design/mockups/cli-grammar.html`) — CLI grammar and
  the six exit codes, fixed since M3. §2.5 works inside them and does not
  widen them.
- Plate **D-010** (`docs/design/mockups/updates-apps.html`) — the Applications
  surface, acceptance reference.
- **Schema Decision-0** — conform to shipped schemas; a new domain gets a new
  file. `schemas/catalog/app-catalog.json` is *proposed*, not shipped, so §3.3
  adds fields to it rather than minting a parallel schema. That is the only
  schema this document touches.

---

## 0. Where this document amends app-catalog.md

Two sentences in app-catalog need correcting rather than reinterpreting, and
both corrections are recorded here in full so no reader of that document is
surprised by this one.

| app-catalog says | Corrected reading | Why |
|---|---|---|
| §3.5: *"**No background updater, ever.** Spec 6.3."* | **No third-party background updater, ever** — not Flatpak's own, not GNOME Software's, not Google's, not Brave's. Punar adds exactly one low-frequency, typed, audited, Punar-owned refresh path (§4.1), which is a *checker* by default and an *applier* only for the narrow set argued in §4.2. | The original sentence was written to refuse *foreign* updaters running outside Punar's transport, and it succeeds at that. Read literally it also refuses the only mechanism by which an installed browser ever gets a CVE fix, which is not a defensible product. The amendment narrows the refusal to what it was for. |
| §6.3: *"The complete set of triggers"* — three rows, none periodic with network. | Four rows. The fourth is `punar-app-refresh.timer` (§4.1). | The three-row table is what a design with no update lifecycle looks like. This document supplies the lifecycle the user asked for; the table grows by one row and the §6.3 no-polling argument is re-made for it from scratch in §4.1.2. |

Everything else in app-catalog stands. In particular: law 1 (the request
carries an id, never a package string), law 2 (A/B decides where an app may
live), law 3 (every preinstall is permanent), law 4 (tier and containment are
two sentences), law 5 (a toolchain question resolves to a project).

---

## 1. Where user-installed software lives, and the survival rule

> **An OS that silently eats an app is unacceptable. So every install route on
> this machine is one of three things: it survives, or it is refused at the
> moment you ask with the consequence stated, or it is inventoried, warned
> about before the swap, and re-announced after it. There is no fourth
> category, and nothing disappears quietly.**

### 1.1 The problem ADR-003 creates and does not answer

A Punar update replaces the inactive root slot wholesale and boots into it.
Slot B has no memory of slot A. `/var` and `/home` are shared and are never
rolled back.

ADR-003 works this out for one case — Punar's own `/etc` state, which becomes a
capability output rather than a preserved file — and stops there. The case it
does not work out is the one that decides whether people can live on this OS:
**a package the user installed into the root filesystem is destroyed by the
next OS update, and nothing in the system currently tells them.** `pacman -S
libvirt` succeeds, works for three weeks, and is gone after a restart that
announced itself as an *update*. That is the failure mode §1.22 exists to
forbid, and it is worse than a refusal because it is delayed.

### 1.2 The complete rule, every route

`SLOT` = lives in the root slot, replaced by the next update.
`SHARED` = lives on `PUNAR-DATA` (`/var` or `/home`), survives both an OS
update and an OS rollback.

| Route | Where the bytes land | Survives an OS update? | What Punar **does** |
|---|---|---|---|
| **Catalog `image` kind** (Chromium, `git`, `neovim`, the §2 preinstall set) | `SLOT`, from the signed image | **Yes** — by being rebuilt into the new slot, identically | Nothing to do. `punarctl app list` prints `Ships with the image · <snapshot>`. Removing one lasts until the next update, and the row says so (app-catalog §2.5). |
| **Catalog `flatpak` kind** — the supported path | `/var/lib/flatpak` → `SHARED` | **Yes** | This is the answer. §1.3 confirms it against app-catalog's verdict. |
| **Catalog `webapp` kind** | M11 record + browser profile → `SHARED` | **Yes** | M11 owns it. No second flow. |
| **Catalog `env` kind** (`kubectl`, `terraform`, `node`) | nowhere on the host; a `punar-env` manifest line | **Yes** — the project is the unit and it is in your repository | Resolves to a manifest snippet, not an install (law 5). |
| **Catalog `snapshot` kind, via `punarctl`** | would be `SLOT` | No | **Refused** at the moment you ask, with app-catalog §4.5's second message, exit 3. The consequence is stated *before* anything happens. |
| **`pacman -S` by hand** | `SLOT` | **No** | **Not blocked** (unmanaged-first). Inventoried by `punarctl app doctor`; **warned before every `update apply`** (§1.5); remembered across the swap and re-announced after it (§1.6). |
| **AUR build by hand** (`makepkg`, `paru`, `yay`) | `SLOT` | **No** | Same as above, plus: `punarctl app` will **never** build from the AUR (§1.4). |
| **A downloaded binary in `$HOME`** — `~/Downloads`, `~/.local/bin`, `~/bin` | `/home` → `SHARED` | **Yes** | Survives. Has no update path of any kind, ever, and `doctor` says so. Execution is gated per §6.3. |
| **A downloaded binary in `/usr/local/bin`** | `SLOT` today → `SHARED` under §1.7 | **Yes, once §1.7 lands** | §1.7 makes `/usr/local` a symlink onto the shared partition. One line at image build, and it removes the single most common way an image-based OS eats a user's tool. |
| **An AppImage anywhere in `$HOME`** | `SHARED` | **Yes** | Survives; no sandbox, no signature, no inventory, no update path. `doctor` lists it. Punar neither blesses nor blocks it. |
| **A container image** (`podman`, `punar-env`) | `/var/lib/containers` → `SHARED` | **Yes** | Already true, already shipped, restated here because people ask. |
| **A Flatpak the user installed by hand** (`flatpak install …`) | `/var/lib/flatpak` → `SHARED` | **Yes** | Survives. Tier `unknown` (not in the catalog); `doctor` lists it as installed outside the catalog; it is **not** touched by Punar's update path (§4.5). |

Two readings of that table matter more than the rows.

**Every route that lands on `PUNAR-DATA` survives, and every route that lands
in the slot does not.** That is the whole rule, and it is a property of the
partition layout, not of Punar's cleverness. The design's only job is to make
it *visible* at the moment a person can still act on it.

**Only one row survives *and* has an update path *and* declares its
permissions *and* has provenance.** That is the Flatpak row, which is why it is
the supported path and why everything else is a report rather than a feature.

### 1.3 Confirming app-catalog's Flatpak verdict

App-catalog §3.1 adopts Flatpak *"as the single supported runtime install path
for graphical applications, and as nothing else"*, forced by ADR-003. This
document **confirms it without amendment**, and adds the two industry data
points app-catalog did not need but a reader will want:

- **Fedora Silverblue and bootc solve exactly this problem exactly this way.**
  An rpm-ostree/bootc root is replaced on update; user applications live in
  Flatpak on `/var`. The mechanism is not novel and its failure modes are known
  rather than hypothetical.
- **The alternative they also ship — package layering (`rpm-ostree install`) —
  is the thing Punar is refusing.** Layering makes every update a rebuild of
  the user's private image, which is a build system on the device, a second
  transport, and a class of update failure that is the user's package choice
  rather than the vendor's release. ADR-003's *"the update unit is a whole
  root-slot image"* forecloses it, and app-catalog §1.4 already refuses it. No
  new argument is needed; the point is that the road not taken is a real road
  and it was measured.

What this document adds to the verdict is **the honest cost of it being the
only path**: an application with no Flathub ref, no web app, and no place in a
project environment has no supported install on Punar at all. Chrome is not
that case (§3). Zoom, Docker Desktop, a vendor's proprietary VPN client with a
`.deb` and a kernel module, and most of the AUR *are* that case, and §9 states
it as a limit rather than burying it.

### 1.4 Why `punarctl app` will never build from the AUR

Three independent reasons, any one of which is sufficient:

1. **It lands in the slot.** Whatever `makepkg` produces is a pacman package
   installed into the running root. It is destroyed by the next update. Adding
   a verb whose result is discarded is the §1.22 failure.
2. **A `PKGBUILD` is arbitrary shell executed at build time.** Spec 12.2 —
   *"Never generate and blindly execute shell commands"* — and app-catalog law
   1 both forbid a path where a string from a remote index reaches an
   interpreter running as a Punar-invoked process. There is no way to build an
   AUR package that is not exactly that.
3. **It needs `base-devel` on the host.** Spec 16 is a sentence about not
   putting toolchains on the host. A verb that requires 300 MB of compiler on
   every device to serve the users who use it is law 3's permanent claim.

`punarctl app install` therefore has no AUR mode, no `--aur` flag, and no
fallback that reaches one. What it has is a refusal that names three real
paths — a catalog request, `punar-env` if the thing is a toolchain, and the
Flatpak if one exists — and a `doctor` that reports what you built anyway.

**Punar does not block `paru`.** Unmanaged-first (design language §8) means the
machine is yours. What Punar owes you is the consequence, on time.

### 1.5 Before the swap: the pre-apply warning

This is the mechanism that converts "silently eats your apps" into "told you
while you could still act."

`punarctl app doctor` already diffs the running slot against the image manifest
(app-catalog §1.4). This document makes that diff a **precondition of the OS
apply path**, not a separate command a user has to know about:

```text
$ sudo punarctl update apply --reboot

PUNAR · UPDATE · APPLY                                        punar-desktop

  Release         2026.09.02.1 · staged in slot B · verified

  3 things you installed will not survive this update.

    libvirt              pacman · installed 2026-08-11
    paru                 aur    · installed 2026-08-04
    ripgrep-all          pacman · installed 2026-08-19

  A Punar update replaces the whole root filesystem (ADR-003). Anything in
  /var, /home or /usr/local is untouched — that is 41 Flatpak and container
  items and every file you own.

  Punar has written this list to /var/lib/punar/apps/slot-residue.json.
  It survives the update and `punarctl app doctor` will show it afterwards.

                              [↵] APPLY AND RESTART      [ESC] CANCEL
```

Rules that keep that screen honest:

- **It is shown once per staged release, not per invocation.** M10's anti-nag
  rule (§5.2) applies verbatim: the identity is the release id, and a user who
  cancels and re-runs sees the same screen once, not an escalation.
- **The list is empty on most devices, and then the block does not render at
  all.** Design language §2: a screen with no decision to report has no colour,
  and no block either. The default Punar device installs nothing into its slot
  and never sees this text.
- **`--yes` skips the prompt, not the record.** A non-interactive apply still
  writes `slot-residue.json` and still emits the audit event. The record is not
  a function of whether anyone was watching.
- **It never blocks the update.** Refusing to update a machine because the user
  installed `libvirt` would be Punar managing the user. It informs, it records,
  and it proceeds when told to.

### 1.6 After the swap: remember, tell, and do not re-execute

`slot-residue.json` lives on `PUNAR-DATA`, so it crosses the swap. On the first
boot into the new slot, `punarctl app doctor` — and the Applications surface —
lead with it:

```text
PUNAR · APPLICATIONS · DOCTOR                                 punar-desktop

3 packages you installed before the update are gone.

They lived in the root filesystem, which this update replaced. This is how
Punar updates; it is not a fault and nothing else was lost.

  libvirt              was pacman · lastseen release 2026.08.25.1
                       → punarctl app request libvirt --image
  paru                 was aur
                       → no supported path; see `punarctl app explain aur`
  ripgrep-all          was pacman
                       → catalog: not present · punar-env: available

Nothing on this list will be reinstalled automatically.

  punarctl app doctor --forget      clear this list
```

**Punar does not reinstall them.** The decision, stated plainly because it is
the one people will argue with:

> Automatic post-swap reinstall would mean the OS running `pacman -S` — or
> worse, `makepkg` — unattended, as root, from a list of package name strings,
> with no human present. That is a generic execution path assembled out of
> user-supplied strings, which is exactly what spec 60 and app-catalog law 1
> exist to prevent, and it would reintroduce it through the back door of
> convenience. It would also make the *first boot after an update* the moment
> the machine does the most unattended network work, which is the worst
> possible time.
>
> The supported way to have an application after an update is to install it
> where it survives. Punar's job is to make that route obvious, make the other
> route's cost visible in advance, and never pretend it did something it did
> not. So: **warn before, remember across, tell after, reinstall never.**

An organization that genuinely needs a package present on every device has the
right mechanism already and it is not this one: put it in the image, or make it
a catalog `required` entry (§46), both of which are release-time decisions with
a review and a signature behind them.

### 1.7 `/usr/local` becomes shared

**Decision: `/usr/local` is a symbolic link to `/var/usrlocal`, created at
image build, and `/var/usrlocal` is created by the installer on `PUNAR-DATA`.**

- **Cost:** one symlink in the image tree, one `mkdir` in the installer, one
  build assertion.
- **What it buys:** the single most common thing a competent Linux user does —
  drop a binary or a `make install` prefix into `/usr/local` — stops being
  silently destroyed by an OS update. It is the difference between "this OS
  eats software" and "this OS replaces its own filesystem and told me where the
  line is."
- **Precedent:** rpm-ostree systems have shipped `/usr/local → /var/usrlocal`
  for years for this exact reason. This is not an invention.
- **What it does *not* buy, stated:** contents are unsigned, uninventoried by
  any package manager, tier `user` or `unknown` at the gate (§6.3), and have no
  update path. `punarctl app doctor` lists non-empty `/usr/local` as *"software
  outside every package system — it survives updates and nothing updates it."*
- **Honest wrinkle:** whether the root slot is mounted read-only is not settled
  in ADR-003 or `image-pipeline.md`. The symlink is correct either way — if the
  root is read-only, the symlink is the only way `/usr/local` is writable at
  all; if it is read-write, the symlink is what makes the writes survive. The
  decision does not depend on the open question, which is why it can be made
  now.

---

## 2. `punarctl app` — the command, end to end

### 2.1 The verb set

Exactly these. Anything else answers with D-014's usage error, exit 2.

| Verb | Method | Mutating | Audited | Network |
|---|---|---|---|---|
| `punarctl app search <text>` | `apps.catalog` | no | no | no |
| `punarctl app list [--all]` | `apps.list` | no | no | no |
| `punarctl app show <id>` | `apps.catalog` | no | no | no |
| `punarctl app install <id>` | `apps.install` | yes | always | yes |
| `punarctl app remove <id>` | `apps.remove` | yes | always | no |
| `punarctl app update [<id>\|--all\|--security]` | `apps.update` | yes | always | yes |
| `punarctl app rollback <id>` | `apps.rollback` | yes | always | **no** (§4.5) |
| `punarctl app refresh [--trigger timer]` | `apps.refresh` | yes | always | yes |
| `punarctl app status` | `apps.status` | no | no | no |
| `punarctl app doctor [--forget]` | `apps.doctor` | no | no | no |
| `punarctl app policy` | `policy.effective` (existing) | no | no | no |
| `punarctl app request <id> [--image\|--recheck]` | local file write | — | yes | **no** |

`apps.rollback`, `apps.refresh`, `apps.status` and `apps.doctor` are **new**
methods this document proposes on top of app-catalog §4.1's five. The
permanent non-goals are unchanged and restated because they are the security
design: **no `apps.install_all`, no verb that takes a package name, a ref, a
URL, a remote, a commit, a flag, or a `uid`, and no generic execution method of
any kind.** Those answer `unknown_method`.

Section numbers in `ipc.md` are allocated at merge time in merge order
(app-catalog §4.1); this document does not hard-code one. The unique thing is
the method names.

### 2.2 `install` — the pipeline, step by step

```text
punarctl app install google-chrome
  │
  ├─ 1. PARSE.        Exactly one positional argument. It is matched against
  │                   ^[a-z0-9][a-z0-9-]{0,63}$ in the CLI, before the socket.
  │                   A string that is not a catalog id shape never travels.
  │
  ├─ 2. RESOLVE.      punard reads /usr/share/punar/catalog/catalog.json —
  │                   root-owned, 0444, inside the signed image — and looks the
  │                   id up. This is the ONLY place a package string is ever
  │                   produced. Not found → §2.6's card, exit 2.
  │
  ├─ 3. KIND GATE.    source.kind must be `flatpak` or `webapp`.
  │                   `image` → "already on this machine", exit 0, noop.
  │                   `env`   → the punar-env card, exit 0, noop.
  │                   `snapshot` → refusal with the ADR-003 sentence, exit 3.
  │
  ├─ 4. POLICY.       Read the M4 effective document. app-catalog §4.3's table,
  │                   unchanged. denied / allowUserInstall:false → exit 3 with
  │                   the §73 five-answer block and the named policy id.
  │
  ├─ 5. AUTHORIZE.    Agent-attributed peer (M7 cgroup attestation) →
  │                   approval_required, an approval is created, NOTHING
  │                   executes, exit 4.
  │
  ├─ 6. CARD.         Render §2.3 from the catalog record plus a metadata read
  │                   of the ref. No application bytes are fetched. Containment
  │                   is RECOMPUTED from the ref (app-catalog §1.6); if it
  │                   disagrees with the record, stop: `permissions_changed`.
  │
  ├─ 7. CONSENT.      One explicit keystroke. The confirm carries
  │                   confirm_permissions_sha256 — a digest of the permission
  │                   set that was SHOWN. punard refuses if it does not match
  │                   what it computes. Consent is to a specific set or it is
  │                   not consent.
  │
  ├─ 8. PRECHECK.     Free space on PUNAR-DATA ≥ 1.2 × (downloadBytes +
  │                   installedBytes + any missing runtime). Short → exit 1
  │                   with both numbers, before a byte is fetched.
  │
  ├─ 9. APPLY.        punard execs a FIXED ARGV built from the record:
  │                     ["/usr/bin/flatpak", "install", "--system",
  │                      "--noninteractive", "--assumeyes",
  │                      <remote>, <ref>, "--commit=" + <commit>]
  │                   An argv vector, never a shell string. Every element is
  │                   from the signed catalog record or is a compiled-in
  │                   constant. M3's `nft` pattern, unchanged.
  │
  ├─ 10. VERIFY.      `flatpak info --system <ref>` reports the pinned commit
  │                   deployed. Mismatch → verify_failed, exit 1.
  │
  ├─ 11. AUDIT.       system.install_package · resource <id> · the commit ·
  │                   audit_category application.
  │
  └─ 12. PRINT.       §2.3's result block, exit 0.
```

Steps 2, 7 and 9 are the security design. Step 2 is the only string source,
step 7 is the only consent, step 9 is the only execution — and none of the
three can be reached with caller-supplied text.

### 2.3 What it prints (D-014 grammar)

Before consent — this is app-catalog §4.7's card, rendered by the same
formatter module as every other `punarctl` surface (M3 §6: no command formats
itself):

```text
PUNAR · APPLICATIONS · INSTALL                                punar-desktop

  GOOGLE CHROME                     CATALOG · CURATED · SANDBOX BYPASSED
  ────────────────────────────────────────────────────────────────────────
  Google's browser. Proprietary, and packaged for Flathub from Google's
  own binary release rather than built from source.

  Source        flathub · com.google.Chrome · commit 4a91c7e2
  Publisher     packaged by Flathub · not published by Google
  License       Proprietary · Google Chrome Terms of Service
  Update        pinned to catalog 0.4.2 · security-sensitive · auto
  Updater       Google's own updater is disabled by the Flathub packaging.
                Updates reach this machine through Punar, or not at all.
  Size          112 MB download · 398 MB installed
                + 1.2 GB runtime (org.freedesktop.Platform 25.08, not present)

  Reaches       every device on this machine, including cameras and
                microphones — its sandbox does not constrain devices
                the internet
                your Downloads folder

  Sends         usage statistics and crash reports to Google by default.
                You can turn this off in Chrome's own settings.
                Sign-in syncs your browsing data to a Google account.

  Policy        Personal defaults · you install what you want

                                          [↵] INSTALL      [ESC] CANCEL
```

After:

```text
  Installed     google-chrome · com.google.Chrome · commit 4a91c7e2
  Runtime       org.freedesktop.Platform 25.08 · fetched (1.2 GB)
  Updates       automatic · security-sensitive · applies when you next
                start Chrome · punarctl app update policy notify to change
  Launch        PUNAR+Space → Chrome
```

House rules, all inherited: mono masthead, `PUNAR · <SECTION>` + hostname,
tracked-uppercase bright-black labels, middle-dot separators, aligned columns,
status words on the ANSI semantic slots, `NO_COLOR`/non-TTY drops the ANSI and
keeps the columns, `--json` prints the IPC `result` verbatim. The warn colour
appears on exactly one thing on that screen — the device-access sentence —
because that is the only deviation being reported (design language §2).

### 2.4 The siblings

**`search`** — ranks catalog entries by id, name, summary and keywords, offline,
capped at 50 with `truncated: true`. Prints tier and containment on every row,
because a tier is only useful if it is visible without opening anything:

```text
$ punarctl app search browser

PUNAR · APPLICATIONS · SEARCH                    CATALOG 0.4.2 · 4 MATCHES

  firefox         Independent browser engine       CURATED  · SANDBOXED
  google-chrome   Google's browser · proprietary   CURATED  · DEVICE ACCESS
  brave           Chromium-based, ad-blocking      CURATED  · DEVICE ACCESS
  zen-browser     Firefox-based                    COMMUNITY · SANDBOXED
```

**`list`** — what is on *this* machine, joined against the catalog at request
time. There is no third database (app-catalog §1.1): the image set comes from
`pacman -Q`, the shared set from `flatpak list --system`. `--all` adds the
`unknown` rows — things installed outside every sanctioned route.

**`remove`** — `flatpak uninstall --system --noninteractive <ref>`, fixed argv.
Denied for an `applications.required` id with the policy named. Refuses for
`image` kind with the truth: *"Chromium ships in the image. Removing it lasts
until the next update."* Prunes the retained previous deployment (§4.5) and says
how many bytes it freed.

**`doctor`** — the honesty verb. Four sections, and it is the only place on the
machine that sees all four at once: slot-resident packages that will not
survive; the post-swap residue list (§1.6); Flatpaks with no catalog entry;
non-empty `/usr/local` and `~/.local/bin`. It performs **no network I/O**, adds
no timer, and is a `pacman -Qm`-shaped diff plus two directory reads.

**`request`** — writes to a local file and says so. On an unenrolled machine
there is nobody to send it to and implying otherwise would be a lie (design
language §8; app-catalog §4.5).

### 2.5 Exit codes

D-014 fixed six exit codes at M3 and this document **does not widen them.**

| Code | Meaning | When `app` returns it |
|---|---|---|
| `0` | ok | Installed, removed, updated, rolled back, nothing to do, or a card printed |
| `1` | daemon / runtime error | Remote unreachable · download failed · digest mismatch · `verify_failed` · disk short · `permissions_changed` |
| `2` | usage | Unknown verb or flag · malformed id · **id not in the catalog** |
| `3` | denied | punard refused: org policy **or** architecture (a `snapshot`-kind install). The §73 block always says which |
| `4` | `approval_required` | Agent-attributed peer. An approval exists; nothing executed |
| `5` | daemon unreachable | `punard` socket absent or not answering |

Two conventions worth stating because they are easy to get wrong:

- **An unknown catalog id is exit 2, not exit 1.** You named something that
  does not exist in this release's namespace; the fix is in your hand, not the
  daemon's. §2.6 is the screen.
- **No `punarctl app` verb encodes a fact about the world in its exit code.**
  `app status` with 14 pending updates exits `0`. Exit codes describe what
  happened to the *request*, never what the request found. A script that wants
  the fact reads `--json`. This is M3's discipline and it is why `1` covers
  both "the network died" and "the permission set changed" — a caller that must
  distinguish them reads `error.code`, which is where the distinction lives.

### 2.6 The failure that matters most

```text
$ punarctl app install chrome

PUNAR · APPLICATIONS                                          punar-desktop

chrome is not in this release's catalog.

Punar installs from a pinned catalog, not from a live index — every
application on this machine is a version you can point to.

  Catalog     punar-catalog 0.4.2 · snapshot 2026/08/20 · 148 entries
  Searched    chrome · google · browser
  Did you     google-chrome   catalog · curated · device access
  mean        chromium        installed · ships with the image
              brave           catalog · curated · device access

Next step
  punarctl app install google-chrome
  punarctl app request chrome     records the request on this device.
                                  Nothing is sent anywhere.
```

Exit 2. It names the catalog version so the claim is falsifiable, offers near
matches with their tiers so the user can decide rather than guess, and does not
fuzzy-match its way into installing something the user did not name.

---

## 3. Google Chrome, worked honestly

This is the user's literal question — *"provide a way to download google chrome
as a command so it installs it"* — and it is a good question because Chrome is
the hardest easy case.

### 3.1 The four facts, and why they resolve

| Fact | Consequence for Punar |
|---|---|
| Chrome is **proprietary and not redistributable**. | Punar cannot ship it, cannot mirror it, and cannot put it in the image. Any design that involved Punar carrying the bytes was never available. |
| Chrome is **not in Arch's official repositories** — only in the AUR (`google-chrome`), which fetches Google's `.deb` and repacks it. | The AUR route is refused for the three independent reasons in §1.4, the first of which is that it lands in the slot and dies at the next update. |
| Chrome **ships its own updater** — on Linux, Google's package installs a repository and a periodic update job. | An updater running outside Punar's transport breaks the pin, breaks the audit, and adds a resident periodic task nobody budgeted. §3.2 makes this an admissibility rule rather than a shrug. |
| **`com.google.Chrome` is on Flathub**, packaged by the Flathub maintainers from Google's official binary, with Google's updater removed by the packaging. | This is the whole answer. Punar can offer Chrome as a one-command install **without shipping it, without an AUR build, and without Google's updater running outside our transport** — because Flathub already solved the redistribution and the updater problems, and `/var/lib/flatpak` solves the survival problem. |

So: **`punarctl app install google-chrome` works, it is a catalog entry like any
other, and nothing about it is special-cased.** The mechanism is app-catalog's
mechanism unchanged. What Chrome forces this document to add is not a code
path; it is a *disclosure*, and one new admissibility rule.

### 3.2 The `bundledUpdater` rule — new, and it is the important one

> **A catalog entry whose application updates itself outside Punar's transport
> is inadmissible. It is refused at catalog build, not at install.**

Field, on every `flatpak` entry:

| `bundledUpdater` | Meaning | Admissible? |
|---|---|---|
| `none` | The upstream has no self-updater (Firefox's Flatpak, most FOSS apps). | Yes |
| `disabled-by-packaging` | The upstream ships one; the Flathub packaging removes or neuters it, and the sandbox has no route to reinstate it. | Yes — and the card says so in words |
| `active` | The app can update itself in place. | **No.** Catalog CI refuses the entry with the arithmetic attached |

Why this is a rule and not a preference:

- An app that updates itself makes `commit` pinning a **lie**. The catalog says
  you are running commit `4a91c7e2`; the app has quietly replaced its own
  binary; `punarctl app status` reports a version the machine is not running.
  A reproducibility claim that the software can invalidate on its own is worse
  than no claim.
- It makes `containment` a lie too. The permission set was reviewed for the
  bytes we pinned. A self-updated binary is different bytes with the same
  declared permissions and no recompute.
- It is a resident periodic network task Punar never budgeted, does not audit,
  and cannot turn off — a direct §6.2/§6.3 violation smuggled in as an app.

Chrome's Flathub build is `disabled-by-packaging`: the sandbox has no writable
path to its own installation and the packaging strips the updater. **That is
precisely why Chrome is admissible at all**, and it is worth saying out loud
that the reason Punar can offer Chrome is not that Google cooperated but that
the Flatpak packaging removed the part that would have made it inadmissible.

`bundledUpdater` is `TO VERIFY` per entry at catalog build, from the ref's own
manifest and finish-args, and it is re-verified every catalog release like
`review.reviewedForCatalogVersion`.

### 3.3 The disclosure block — three fields, added to the proposed schema

App-catalog law 4 says tier and containment are two different sentences and no
surface may print one word for both. *Proprietary* and *sends telemetry* are a
third and fourth sentence, and collapsing them into the tier would be the same
mistake one level down. So they get their own fields rather than a tier.

Added to `schemas/catalog/app-catalog.json` (proposed, unshipped — Decision-0
permits this; it forbids extending *shipped* schemas):

```json
"license": "proprietary",
"licenseName": "Google Chrome Terms of Service",
"publisher": "flathub",
"bundledUpdater": "disabled-by-packaging",
"securitySensitive": true,
"disclosures": [
  {"id": "telemetry:default-on",
   "text": "Sends usage statistics and crash reports to Google by default. You can turn this off in Chrome's own settings."},
  {"id": "account:sync",
   "text": "Signing in syncs your browsing data to a Google account."}
]
```

- **`license`**: `free` | `proprietary` | `mixed`. Not a tier and not a
  judgement — a fact the user is entitled to before they commit disk.
- **`publisher`**: `upstream` | `flathub` | `third-party`. **This is a real
  provenance distinction and the catalog has been silent about it.**
  `org.mozilla.firefox` is published on Flathub by Mozilla; `com.google.Chrome`
  is published by the Flathub maintainers repackaging Google's binary. Both are
  pinned and both verify against the same remote key, so the *tier* is the same
  — but "the people who wrote it published it" and "volunteers repackaged a
  vendor blob" are not the same sentence, and §46's stability requirement is
  about semantics, not about hiding provenance.
- **`disclosures[]`**: second-person sentences, exactly the grammar of
  `permissions[].text`. `--filesystem=home` is not something a person can
  consent to; neither is "telemetry: yes."

**Chrome's trust tier is `curated`, and that is not an endorsement.** App-catalog
§1.5 defines `curated` as *"Punar wrote the summary, read the permission set,
pinned the commit, and re-reviews it every catalog release"* — a claim about
**who vouches for the bytes and who read the permissions, and nothing else**,
explicitly *not* a source audit (§8.4). Punar can do all four of those things
for Chrome. Demoting it to `community` to signal disapproval would be exactly
the collapse law 4 forbids: using a provenance word to carry an opinion. The
opinion goes in `license` and `disclosures`, where a user can read it.

### 3.4 Chrome's containment, and the self-correcting mechanism

As of our last check, `com.google.Chrome`'s finish-args include `--device=all`
(it wants camera, microphone and every DRI/input device without portal
brokering). Under app-catalog §1.6's bypass list, `device: all` computes
`containment = sandbox-bypassed`. So Chrome renders as
**`CATALOG · CURATED · SANDBOX BYPASSED`**, and the card leads with the
device sentence in warn colour.

That specific permission set is **`TO VERIFY`** and this document does not need
it to be right, which is the point: app-catalog §1.6's **recompute-and-refuse**
rule reads the permissions from the actual ref at install time and stops if
they disagree with the record. If Chrome's Flathub packaging has narrowed to
`--device=dri`, the recompute produces `sandboxed`, the record is stale, and
the install refuses with `permissions_changed` and both sets printed — a
visible correction rather than a card that lied. The mechanism is
self-correcting in both directions and neither direction is silent.

The install button stays affirmative either way. It is the user's machine and
their decision; the colour states the deviation, not a veto (design language
§2).

### 3.5 The other four people actually ask for

One line each, in the same grammar, all sizes and permission sets `TO VERIFY`
at catalog build:

| App | Catalog id | The one honest sentence |
|---|---|---|
| **Firefox** | `firefox` | `CURATED · SANDBOXED`, `publisher: upstream` — Mozilla publishes its own Flathub ref, `bundledUpdater: none` (the Flatpak has no in-app updater), and its `fallback-x11` sits *alongside* `wayland`, which §1.6's rule deliberately does not treat as a bypass. This is the cleanest entry in the catalog and the one everything else is measured against. |
| **Brave** | `brave` | `CURATED · DEVICE ACCESS`, `license: mixed` (MPL-2 engine, proprietary services and a built-in crypto wallet the summary names), `bundledUpdater: disabled-by-packaging` — Brave's own updater exists in its `.deb` and not in the Flatpak. Same `--device=all` posture as Chrome, same warn sentence, same `TO VERIFY`. |
| **VS Code** | `vscode` | `CURATED · SANDBOX BYPASSED`, **and this one is bypassed on purpose**: the Flatpak holds `--filesystem=host` and `talk-name=org.freedesktop.Flatpak` so it can reach your files and spawn tools on the host. A development environment that cannot reach your files is not one. The card says so in words rather than pretending. **Budget consequence:** its runtime is `org.freedesktop.Sdk`, not `Platform` — roughly 2 GB, a *second* runtime family, and therefore one of the three slots in app-catalog §3.3's cap. §7.2 counts it. The toolchains it drives still belong in `punar-env` (law 5). |
| **Slack** | `slack` | `CURATED · DEVICE ACCESS`, `license: proprietary`, `publisher: flathub` (repackaged from Slack's `.deb`), `bundledUpdater: disabled-by-packaging`, `securitySensitive: true` — it renders untrusted remote content and holds camera and microphone for calls. Disclosure: *"Your workspace administrator can retain and export messages, including direct messages, under Slack's own policies. Punar has no visibility into and no control over that."* |

All four are `securitySensitive: true` except VS Code, which is not
network-content-facing in the same way; §4.2 explains why that flag decides
whether an app updates itself without asking.

---

## 4. The update lifecycle

> **The user's real question was the second one. An install path without an
> update path is a way to acquire unpatched software.**

### 4.1 The trigger: one new timer, and the §6.3 argument for it

#### 4.1.1 The unit

```ini
# usr/lib/systemd/system/punar-app-refresh.timer
[Unit]
Description=Punar application update check

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=4h
AccuracySec=1h

[Install]
WantedBy=timers.target
```

```ini
# usr/lib/systemd/system/punar-app-refresh.service
[Unit]
Description=Punar application update check (oneshot)
After=network-online.target punard.service

[Service]
Type=oneshot
ExecStart=/usr/bin/punarctl app refresh --trigger timer
```

Wiring is the standing house rule (M1's mkosi `/etc`-preset lesson, M4 §5, M10
§3.1): the arming link is a **vendor `.wants` symlink** at
`usr/lib/systemd/system/timers.target.wants/punar-app-refresh.timer`, and
checks assert **the symlink plus `Wants=` in `systemctl show`** — never
`is-enabled`.

**The pass runs through `punarctl`, not inside `punard`.** M4 §5 and M10 §3.1's
rationale, inherited: the timer path is then the *same* socket, authz and audit
path a human uses, so there is exactly one code path to verify and the daemon
gains no internal clock. Cost is one transient process a day.

**One deliberate deviation from the house idiom, and its reason.** M10 and M4
use monotonic timers (`OnBootSec` / `OnUnitActiveSec`). This one is a calendar
timer with `Persistent=true`, because `OnUnitActiveSec` runs on
`CLOCK_MONOTONIC`, which does not advance across suspend. A laptop suspended
sixteen hours a day would drift a daily monotonic timer into a two-day one and
the drift would be invisible. `OnCalendar=daily` + `Persistent=true` fires once
on resume if the day was missed — once, not a catch-up storm. The deviation is
recorded here rather than discovered in a bug report.

#### 4.1.2 Cadence: 24 hours, and the argument

Three constraints, satisfied at once (M10 §3.2's shape).

1. **Patch latency has to be short enough to matter.** The applications where
   CVE latency is the dominant risk publish security builds on a 1–14 day
   cadence; a browser emergency respin typically reaches Flathub within 1–3
   days of disclosure. A 24 h period plus up to 4 h of jitter puts Punar's
   worst case at roughly **28 h behind Flathub's publish**. That is materially
   worse than Chrome's own updater, which checks roughly every 5 hours — and
   Chrome's updater is a resident periodic process, which is exactly the cost
   §6.2 and §6.3 refuse. **28 h versus 5 h is the price of not running a vendor
   daemon, and it is stated rather than hidden.**
2. **Bytes and politeness.** A refresh fetches remote summary and appstream
   metadata for the installed set — on the order of a megabyte, not the
   applications. Daily is ≈ 30 MB/month/device. Six-hourly would be ≈ 120 MB
   for at most 4× the freshness on a set of applications that publish weekly:
   the freshness-per-byte curve is flat past daily, and a fleet hitting a
   community-funded CDN four times a day per device is a bad citizen.
3. **§6.3 has to be satisfiable by inspection, not by argument.** A period
   measured in seconds or minutes that performs network I/O is a polling loop
   under any honest reading. A daily calendar timer with an hour of accuracy
   slack and four hours of jitter is unambiguously not one, and nobody has to
   be persuaded.

#### 4.1.3 Coalescing: no, twice, for two different reasons

- **It does not coalesce with `punard-reconcile.timer` (120 s) or
  `punar-agentd-scan.timer` (240 s).** Those are local observation passes at
  seconds cadence with **zero network I/O**, and that is the entire reason they
  are affordable. Folding a network fetch into a 120-second timer would convert
  the two cheapest periodic tasks on the machine into 720 network wakeups a day
  — the precise thing §6.3 prohibits. The cadences are two orders of magnitude
  apart because the work is two orders of magnitude apart.
- **It does not coalesce with the OS update timer either** (`OnBootSec=15min`,
  `OnUnitActiveSec=6h`, `RandomizedDelaySec=1h`), even though that one *is*
  periodic and *does* touch the network, and this is the closer call. Three
  reasons: one unit is one failure domain, and a Flathub outage should not make
  `update.check` look broken; the OS check is root-only and audited under
  `update.check` with `system.update_channel` as its policy owner, while an app
  refresh answers to `application.updates` and an org may legitimately pin one
  without owning the other; and the OS timer's real job is streaming a ~2 GB
  payload into the inactive slot, which is a different I/O profile from a 1 MB
  metadata read and should be schedulable independently.
- **What they do share, verbatim:** the **metered-link rule**
  (`update-and-rollback.md` §5.3.2). If NetworkManager reports the connection
  metered, the metadata refresh still runs — it is a megabyte — and **no
  application payload is downloaded**. `punarctl app status` says so in words.

#### 4.1.4 Budget

`punar-app-refresh.service` is `Type=oneshot`. **No new resident process, no
new daemon, no addition to the §6.2 services sum.** The transient peak — a
few tens of MB while `ostree` reads remote metadata — is recorded as
`PUNAR_APP_REFRESH_PEAK_RSS_MB` in the perf report, **recorded and not gated**,
the M11 decision-24 idiom already used for
`PUNAR_APP_INSTALL_PEAK_RSS_MB` (app-catalog §3.3). Per M4/M5/M13 precedent, the
timer is **stopped at the top of every in-VM `mN-check` and restarted at the
end**, so no `apps.*` audit event lands inside an idle-RAM sampling window.

### 4.2 The default: `security-auto`, and its defence

**Decision: the shipped default of the `application.updates` capability is
`security-auto`.**

| Value | Behaviour |
|---|---|
| `manual` | The timer does not run. Nothing is checked, nothing is fetched, nothing changes. `punarctl app update` still works when you type it. |
| `notify` | Refresh runs. Available updates are *recorded and shown*. **Nothing is downloaded and nothing is applied.** |
| `security-auto` | **Default.** Refresh runs. Entries with `securitySensitive: true` are downloaded and deployed automatically, subject to §4.3's widening rule. Everything else behaves as `notify`. |
| `auto` | Everything is downloaded and deployed automatically, subject to §4.3's widening rule. Available for a user who wants it and for an org that requires it. |

It is a capability, so it flows through the existing M4 layered merge and the
M5 `policy.d` envelope with zero new policy machinery, `punarctl policy explain
application.updates` works for free, and a managed device's org value cites the
pinning source rather than "personal preference." §46's `applications` block
governs *what may be installed*; this capability governs *how what is installed
stays current*, and they are deliberately separate keys.

#### 4.2.1 Against the security argument

The security argument is correct and is the reason the default is not `notify`:
unpatched browsers are how people get owned, and a notification a user did not
read is not a patch. `security-auto` puts the automatic behaviour exactly where
the exposure is — applications that render hostile remote content on every use.
The flag that decides it is `securitySensitive`, which app-catalog §3.4 already
defined for a closely related purpose (gating `update.mode: upstream`), so this
introduces no new judgement call and no new list to maintain.

#### 4.2.2 Against the autonomy argument

The autonomy argument is also correct, and the reason the default is not
`auto`. Design language §8 and `update-and-rollback.md`'s rule that **nothing
reboots a personal machine without the human** are not softened here. The
reconciliation rests on a specific technical fact rather than on a preference:

> **A Flatpak update does not change what is running.** `flatpak update`
> deploys a new commit alongside the old one; a running instance keeps the
> deployment it started with until it exits. Nothing closes, no work is lost,
> nothing on screen changes, and there is no progress bar between a person and
> their laptop.

So the rule Punar actually follows is consistent across both surfaces, and it
is one sentence:

> **Punar never changes what is running under you. It may change what starts
> next time, for the narrow set where waiting is the larger harm — and it tells
> you afterward, per app, with a one-command undo.**

An OS update needs a reboot, so it waits for the human. An application update
does not, so it does not. That is a distinction in the mechanism, not a
convenience carved out of a principle.

Four things make it survivable rather than merely defensible:

1. **The widening rule (§4.3) is absolute.** An update that asks for more
   than the user consented to is never automatic under any policy value,
   including `auto`. Auto-update is therefore not a privilege-escalation
   channel, which is the objection that would otherwise be fatal.
2. **It is undoable, offline, in one command.** `punarctl app rollback <id>`
   re-pins the retained previous commit (§4.5).
3. **It is told, once.** The **first** time an automatic update lands, one
   calm line appears, naming the app, the versions, and the two commands that
   change the policy. After that, per M10's anti-nag rule (§5.2), routine
   automatic updates are silent and visible in `punarctl app status` — because
   the eleventh notification teaches people to ignore the first. Punar does not
   ask at onboarding either: a question about update policy before the user has
   installed anything is a question they cannot yet answer, and the right moment
   to speak is the first time it is real.
4. **Turning it off is one command and it is honoured completely.**
   `punarctl app update policy manual` stops the timer. `punarctl app status`
   then says so, in words, permanently — the same discipline
   `update-and-rollback.md` §5.3.2 applies when a user disables automatic
   staging.

#### 4.2.3 Managed devices

Org policy per §46 and the M4 merge, unchanged. An org may pin
`application.updates` to any of the four values. Two notes:

- An org that pins `manual` and also lists `applications.required` has chosen a
  fleet of pinned, un-updated applications. That is its right; `punarctl
  compliance` reports the age of the oldest installed ref so the choice is
  visible rather than assumed.
- An org that pins `auto` has consented on the user's behalf to updates
  landing without a prompt — **except** for the widening rule, which no policy
  value can switch off. A permission expansion always stops and asks, and on a
  managed device the ask is a policy decision the org must make, not a dialog
  the user clicks through.

### 4.3 The widening rule

> **An update that widens an application's permission set is never applied
> automatically, under any policy value, on any device.**

App-catalog §1.6 already recomputes containment from the ref and refuses an
*install* on disagreement. This extends the same rule to updates, with a
direction:

| Permission delta | `security-auto` / `auto` | `notify` / `manual` |
|---|---|---|
| Unchanged | applied | listed |
| **Narrowed** (the app asks for less) | applied | listed |
| **Widened** (any new finish-arg) | **not applied.** Downgraded to a notification carrying the diff, requiring the human's confirm-with-digest exactly like an install | listed with the diff |
| Widened *across the §1.6 bypass line* (`sandboxed` → `sandbox-bypassed`) | **not applied**, and the notification leads with the sentence that says what changed about reach, in warn colour | same |

Without this rule, automatic updates would be a channel by which an application
grants itself access to your home directory between one launch and the next,
with a consent record pointing at a permission set that no longer exists. The
rule is what makes `security-auto` defensible; it is not a refinement of it.

### 4.4 Failure, and offline

| Situation | What happens | What the user sees |
|---|---|---|
| **Offline** (§55) | The refresh is a **noop**, not an error. Cached state is untouched, `lastCheckAt` is not advanced, nothing is retried in a loop; the next timer tick tries again. | `Applications  12 installed · last checked 6 days ago · offline since 2026-08-20`. **Staleness is displayed, never hidden** — `update-and-rollback.md` decision 27, adopted verbatim. After 30 days: *"Update status for your applications is unknown. Your applications are unaffected and still work."* |
| **Remote unreachable / 5xx** | Same as offline. **One** transition-only audit event when the state changes from reachable to unreachable — never one per retry, which encodes no new fact (the M5 `enroll.sync` precedent). | The staleness line, with the remote named. |
| **Download interrupted** | `ostree` pulls are resumable by object; a partial pull leaves the **old deployment active**. No half-updated application can exist. | Nothing, until it succeeds. |
| **Deploy fails** (corrupt object, digest mismatch) | The old deployment stays active. `apply_failed` audit event naming the ref and the reason. **One** automatic retry on the next timer tick, then it stops trying and reports. | *"Firefox could not be updated (2 attempts). Your installed version is unaffected and still runs. Next step: punarctl app update firefox"* |
| **Disk full on `PUNAR-DATA`** | Precheck refuses **before** fetching: free space must be ≥ 1.2 × (download + installed + missing runtime). | Both numbers, and what to free. A user who is out of disk is told the arithmetic, not handed `ENOSPC`. |
| **A runtime the update needs is not installed** | Fetched as part of the transaction, and its size is in the precheck. If the entry needs a *fourth* runtime family, that is a catalog CI failure that never reached the device (app-catalog §3.3). | The runtime size is named before the fetch. |
| **The catalog no longer contains the id** (the app was dropped from a newer catalog shipped by an OS update) | The installed application is **not touched**. It keeps working. Its tier becomes `unknown` — nothing vouches for it any more, which is the truth. | `doctor`: *"google-chrome is installed but is not in catalog 0.5.0. It still runs. Punar no longer tracks its updates."* |

### 4.5 Rollback, honestly — and it is not the OS's rollback

**Flatpak's rollback story and the OS's A/B story are different mechanisms with
different guarantees, and the surfaces must never imply otherwise.**

What is true:

- `flatpak` retains the **previous deployment** of an app after an update, and
  `flatpak update --commit=<previous>` redeploys it. So `punarctl app rollback
  <id>` is real, it is **offline**, and it is fast — the bytes are already on
  disk.
- Because ostree hardlinks identical content-addressed objects, retaining the
  previous deployment costs approximately the **delta**, not a second full
  copy. A 400 MB browser with a 40 MB delta costs ~40 MB to keep rollable.
- Punar's retention policy: **exactly one previous deployment per application.**
  Older ones are pruned on the next successful update. `punarctl app remove`
  prunes both and says how many bytes it freed.

What is **not** true, and must be said wherever rollback is offered:

- **Rolling back the OS does not roll back your applications.** `/var/lib/flatpak`
  is on the shared partition, deliberately, so an OS rollback leaves your apps
  exactly where they were. This is the consequence people get wrong (app-catalog
  §6.2) and it is printed on the OS rollback surface, not just in a document.
- **App rollback is per-ref, not transactional.** It does not roll back the
  runtime. If a runtime update broke your app, rolling the app back may not fix
  it, and `doctor` reports a runtime/app version skew as an incompatibility
  rather than letting it present as a crash.
- **Rollback works until the next prune.** After a second successful update the
  version before last is gone. There is no version history, no generations, and
  no "three updates ago." One step back. Anything more would be a disk cost
  nobody agreed to.
- **There is no health gate.** The OS has boot counting and health-gated
  blessing (ADR-003) because a bad OS update can make the machine unusable
  and unreachable. An application that crashes on launch leaves the rest of the
  machine working, so it needs a human noticing and one command — not a
  supervisor deciding on their behalf. Automatic app rollback is **refused**,
  not deferred: a mechanism that decides an application is unhealthy would need
  to define health per application, and it would eventually roll back something
  the user wanted.

Coverage, in the house vocabulary (design language §7):

| Claim | Coverage |
|---|---|
| An application update can be undone | `PARTIAL` — one step, until the next prune, per ref, no runtime, no automatic trigger |
| An OS rollback restores your applications | `UNSUPPORTED` — by design; they are on the shared partition and are never rolled back |
| A failed update leaves the old version running | `FULL` — ostree deploys alongside; the active deployment changes last |
| An update cannot expand what an app can reach | `FULL` (once implemented) — §4.3's widening rule, in `punard`, not in the CLI |

---

## 5. The seam with OS updates

An OS slot swap and an application update are **different transactions with
different rollback semantics**, and the two surfaces have historically been the
easiest place in a system like this to start lying.

### 5.1 The two transactions, side by side

| | OS update | Application update |
|---|---|---|
| Unit | The whole root slot | One Flatpak ref |
| Where it lands | The **inactive** slot | `/var/lib/flatpak`, shared |
| Takes effect | On the **next boot** | On the **next launch of that app** |
| Interrupts you | Never — the running system is untouched until you restart | Never — the running instance keeps its deployment |
| Consent | **Always the human.** Nothing reboots a personal machine without them | Automatic for `securitySensitive` apps by default; never for a permission widening |
| Undo | `punarctl update rollback` → the previous **blessed** slot, firmware-selectable, works when userspace does not | `punarctl app rollback <id>` → the retained previous commit, one step, until the next prune |
| Automatic undo | **Yes** — systemd-boot boot counting (tries = 3) with blessing withheld unless health passes | **No**, and refused, not deferred (§4.5) |
| Verification | manifest signature → admissibility → streamed digest → re-read digest → UKI last | remote GPG key pinned in the signed image → ostree commit signature → pinned commit verified deployed |

### 5.2 The contradiction to prevent, and the rule that prevents it

The failure to avoid is a user reading `punarctl update status` saying **"up to
date"** and concluding their browser is patched, when what is up to date is the
OS image and the browser is a Flatpak eleven days behind.

**Rule: no Punar surface prints "up to date" without a scope word, and each of
the two surfaces carries a one-line pointer to the other.**

`punarctl update status` gains a third block. M11's `BROWSER` block is
**preserved verbatim** — this extends the surface, it does not replace it:

```text
PUNAR · UPDATE                                  punar-desktop · dev_9f3k2v8q1x

SYSTEM
  Current         2026.08.25.1 · slot A · blessed · booted 3 days ago
  Desired         2026.09.02.1 · staged in slot B · ready
  Channel         stable · metadata 2 h old · rollout 10% · this device is in
  Health          PASS · boot ok · services ok · session ok · capabilities verified
  Rollback        available → 2026.08.19.2 (slot B, blessed 2026-08-25)
  Next step       Restart to apply, or: sudo punarctl update apply --reboot

BROWSER
  Engine          chromium 151.0.7922.169-1
  Channel         snapshot (2026/08/20)
  Pin source      release 2026.08.25.1 · snapshot_pin
  Pin age         5 days
  Security channel  not configured — browser updates currently ride the OS
                    snapshot pin (SPEC 58 · design: update-and-rollback §9)

APPLICATIONS
  Installed       12 Flatpak · 3 web apps · shared partition
  Updates         2 available · 1 security · checked 3 h ago
  Policy          security-auto · security updates apply on next launch
  Not covered     An OS rollback does not roll back applications.
  Next step       punarctl app status
```

`punarctl app status` mirrors it and points back:

```text
PUNAR · APPLICATIONS · STATUS                                 punar-desktop

  Catalog         punar-catalog 0.4.2 · shipped with release 2026.08.25.1
  Installed       12 · all on the shared partition · survive OS updates
  Checked         3 h ago · flathub reachable
  Policy          security-auto        punarctl app update policy <value>

  Updates available
    firefox         143.0 → 143.0.4    security · applies on next launch
    obsidian        1.9.2 → 1.10.0     waiting for you · punarctl app update obsidian

  Permission changes waiting for you
    zen-browser     1.4.1 → 1.5.0      now asks for your whole home directory
                                       punarctl app show zen-browser --diff

  Slot-resident      3 packages will not survive the next OS update
                     punarctl app doctor

  System             2026.09.02.1 is staged and applies on restart
                     punarctl update status
```

Three properties make that pair non-contradictory by construction:

1. **Neither surface says "up to date" unqualified.** Every currency claim
   carries its scope word — `SYSTEM`, `BROWSER`, `APPLICATIONS` — and its
   as-of time.
2. **Each names the other's limit rather than its own strength.** The OS block
   says an OS rollback does not roll back applications; the app block says the
   OS has a staged release. A surface that only advertises what it covers is
   how "up to date" becomes a lie by omission.
3. **They read one source.** `punarctl app status` renders
   `/var/lib/punar/apps/state.json` and `punarctl update status` renders
   `/var/lib/punar/update/`; the two pointer lines are computed at render time
   from the *other* file, not cached. Two renderers over the real state, never
   two stored opinions.

### 5.3 Interactions, decided

- **An OS update never applies application updates.** A slot swap must not be a
  moment when apps change, because the user consented to a restart, not to
  eleven new application versions. `apps.refresh` on next-boot runs on its own
  timer, at its own jitter, and reports normally.
- **An OS update ships a new catalog, and that is not an app update.** The new
  slot's catalog may pin newer commits. The installed apps are unchanged until
  the refresh notices and the policy decides. `punarctl app status` says
  `catalog 0.5.0 · 4 of your applications are pinned behind it` — a fact, not
  an action.
- **App health never triggers an OS rollback.** The health gate that withholds
  blessing checks boot, services, session and capabilities. A Flatpak that
  crashes is not in that set and must never be — otherwise a broken third-party
  app could roll back the operating system.
- **An OS rollback can strand a forward-dated app.** Apps live in `/var` and
  survive backwards, so an app installed under release N+1 that needs a portal
  interface release N lacks will misbehave after a rollback. `punarctl app
  doctor` reports it as an incompatibility with both versions named, rather
  than letting it present as a crash (app-catalog §6.2). This is the one real
  asymmetry and it is forward, not backward.

---

## 6. Trust and execution

Vocabulary is [`execution-trust.md`](execution-trust.md)'s, **used unchanged**:
`punar.trustTier = system | curated | community | user | unknown` and
`punar.containment = sandboxed | sandbox-bypassed | none`.

### 6.1 The mapping, every route

| What it is | `trustTier` | `containment` | Why |
|---|---|---|---|
| A preinstalled image package | `system` | `none` | pacman verified it against the keyring at image build; it runs as you and reaches what you reach |
| A **curated** catalog Flatpak whose review is current | `curated` | computed per §1.6 | The ostree commit signature verified against a catalog-pinned remote key, **and** a human read the permission set |
| A catalog Flatpak whose `review.reviewedForCatalogVersion` is stale | **`community`** | computed | app-catalog §8.1's automatic demotion. Punar keeps vouching for the pin and stops vouching for the review — nobody has to remember to be honest |
| A **community** catalog Flatpak | `community` | computed | Same pin and signature verification, no review |
| A Flatpak **the user installed by hand** | `unknown` | computed | Not in the catalog: nothing vouches for these bytes. It still runs; `doctor` lists it |
| Something the user **compiled** — `cargo build`, `make` | `user` | `none` | This machine produced it. No evidence of foreign origin |
| A binary **downloaded into an origin zone** (`~/Downloads`) | `unknown` | `none` | Carries evidence of foreign origin. **The only tier that can raise an approval.** The worst cell in the matrix, and the interface says so plainly |
| A binary in `~/.local/bin` or `/usr/local/bin` with no quarantine mark | `user` | `none` | `~/.local/bin` is deliberately not an origin zone (execution-trust §5.3); `/usr/local` is now shared (§1.7) and equally unvouched. Named as a hole in §9, and it is the same hole macOS has |
| An AppImage in `$HOME` | `user` or `unknown` | `none` | Depends only on whether it came through an origin zone. No sandbox, no declared permissions, no update path |

Two things this table is careful not to say. It never calls a sandboxed
`community` app "less trusted" than an unsandboxed `system` one — those are two
different sentences on two different axes (app-catalog law 4). And it never
uses the word *malware*, *threat* or *suspicious* about the `unknown` tier:
`unknown` is not an accusation, it is a statement that the human has not yet
said yes to these bytes (execution-trust §4).

### 6.2 The fanotify gate and `/var/lib/flatpak` — the question, closed

Execution-trust §3.3 raised this and deliberately left it open:

> *`/var/tmp` lives on the `/var` mount, and so does `/var/lib/flatpak`. A
> mount mark placed for `/var/tmp` marks all of `/var`, which means every
> Flatpak application launch becomes a permission event… The adopting milestone
> chooses one of: mark `/var` and accept the events; give `/var/tmp` its own
> mount; or drop `/var/tmp` from the mark set.*

**[`installer.md`](installer.md) §4.3 already closed it, and this document
records the consequence for applications.** The shared partition carries
`/var`, `/home` and `/var/tmp` as **three separate btrfs subvolumes, separately
mounted**. So:

- **`/var` itself is not in the mark set.** `FAN_MARK_MOUNT` on `/var/tmp`
  marks the `/var/tmp` mount and nothing else.
- **Therefore `/var/lib/flatpak` is unmarked, and a Flatpak launch generates
  zero `fanotify` events.** The "the common case generates no kernel event"
  property that the entire cost argument rests on survives the arrival of
  Flatpak. This is the sentence execution-trust could not yet write.
- **`/var/tmp` may be dropped from the mark set as well** and remains the
  cheaper option (execution-trust's own recommendation, and §5.3's argument
  against `/tmp` applies to it verbatim). Either choice leaves Flatpak on the
  no-event path.

The honest consequence, stated because it is a real reduction in what the gate
covers: **the gate does not see Flatpak application launches at all.** The
`curated` and `community` tiers are therefore surface facts and `punarctl trust
check` answers, not gate verdicts — exactly as execution-trust §4.1 already
concluded for `system` and `curated` under `/usr`. The compensation is real and
it is on the other axis: a Flatpak's *containment* is enforced by bubblewrap and
the portals continuously, which is a stronger runtime property than a one-time
consent gate. The gate exists for the case Flatpak cannot reach — a loose ELF
of foreign origin — and that division of labour is the design, not a gap.

### 6.3 What a self-built or downloaded binary gets instead

Nothing from this document, and that is the point:

- **A binary you built** runs under tier `user` with no prompt. `cargo`'s output
  lives on `/home`, which *is* marked, so it does generate an event — answered
  in microseconds by two `fgetxattr` calls (execution-trust §3.3/§8.1). The
  developer is not interrogated about their own compiler output.
- **A binary you downloaded** into the origin zone runs under tier `unknown`
  and gets **one deliberate human decision**, once, for those bytes — the
  Gatekeeper property, honestly reproduced. Approve it and it runs forever;
  the mark travels with the file, so moving it to `~/bin` does not launder it.
- **Neither gets a sandbox, a declared permission set, an inventory entry, a
  signature, or an update.** `punarctl app doctor` lists both, and the line it
  prints is the true one: *"software outside every package system — it survives
  updates and nothing updates it."*

There is no `punarctl app install <url>` and there will not be. Law 1 is not
negotiable, and a verb that took a URL would be the generic execution method
§60 permanently forbids, wearing a friendlier name.

---

## 7. Budget

### 7.1 Disk, against ADR-003 and the installer's layout

Fixed OS cost is ADR-003's and is unchanged by anything here: ESP 1 GiB +
root A 8 GiB + root B 8 GiB = **17.0 GiB**. `PUNAR-DATA` is the remainder:
**≈ 102.2 GiB** on the §5.1 minimum 128 GB disk (119.2 GiB usable),
**≈ 221.4 GiB** on the §5.2 recommended 256 GB target.

| Item | Size | Where | Share of `PUNAR-DATA` (128 GB disk) |
|---|---|---|---|
| Flatpak machinery preinstalled (`flatpak` + `ostree` + `bubblewrap` + `appstream` + deps) | ≈ 60 MB of app-catalog §2.3's ≈ 90 MB | **slot**, ×2 | 1.1 % of one 8 GiB slot; 0 % of `PUNAR-DATA` |
| Offline fixture repo | < 16 MiB (asserted) | slot, ×2 | — |
| `org.freedesktop.Platform` 25.08 | ≈ 1.2 GB `TO VERIFY` | `/var/lib/flatpak` | 1.1 % |
| Runtime cap: **3 runtime families** (app-catalog §3.3) | ≈ 3 GB ceiling | `/var/lib/flatpak` | **2.7 %** |
| Retained previous deployments, one per app | ≈ the delta, not a copy (ostree hardlinks identical objects) | `/var/lib/flatpak` | ~0.1 % for a 12-app machine |
| `/var/usrlocal` (§1.7) | 0 until the user puts something there | `PUNAR-DATA` | 0 |
| `slot-residue.json` | < 8 KiB | `PUNAR-DATA` | 0 |

**A corrigendum, since precision is the house rule.** App-catalog §3.3 and
execution-trust §13 both state three runtimes as *"≈ 2.5 % of the minimum
disk"*. That figure divides 3 **GB** by 119.2 **GiB** as though the units
matched. Done consistently: 3 GB = **2.79 GiB**, which is **2.34 %** of the
119.2 GiB usable disk and **2.73 %** of the 102.2 GiB `PUNAR-DATA` partition.
The conclusion is unchanged — it is affordable — and the arithmetic now says
what it means.

Against the installer's **16 GiB `PUNAR-DATA` floor** (§4.5), the ceiling of
three runtimes is **17 %** of the floor. That is the number that decides
whether a small-disk device can use the catalog at all, it is large, and it is
recorded here because it is the one that will bite first.

### 7.2 The three-runtime cap, under pressure from the worked examples

App-catalog's cap is `len(runtimes) <= 3`, asserted in catalog CI. §3.5's four
worked apps consume it as follows:

| App | Runtime family | Slot consumed |
|---|---|---|
| Firefox, Chrome, Brave, Slack | `org.freedesktop.Platform` | 1 (shared) |
| VS Code | **`org.freedesktop.Sdk`** ≈ 2 GB `TO VERIFY` | 2 |
| (any Electron/GNOME/KDE app in the catalog) | `org.gnome.Platform` or `org.kde.Platform` | 3 |

So the four applications people ask for first plus one desktop-toolkit family
**exhausts the cap**. That is the cap working as designed — it forces the
tradeoff to be argued at catalog-review time with arithmetic attached, rather
than discovered as an 8 GB `/var/lib/flatpak` on someone's laptop. A pull
request adding an app that needs a fourth family does not add a runtime; it
waits for a runtime bump or is refused.

### 7.3 Preinstall the runtime, or fetch it on first install?

**Decision: fetch on first install. The runtime does not ship in the image.**

The argument is decisive and is about A/B, not about size in the abstract:

> The image is what fills the root slot, and **there are two root slots**. A
> 1.2 GB runtime carried in the image is **2.4 GB of the 16 GiB of slot
> budget**, and it is 24 % of ADR-003's `R_max = 5 GB` image ceiling — for
> bytes that are *unusable where they sit*, because `flatpak` reads from
> `/var/lib/flatpak` on the shared partition. Preinstalling means paying for
> the runtime twice in the slot and then paying a third time to copy it to
> `/var` before anything can use it. It also violates app-catalog law 3: a
> permanent claim on every device forever, to serve the users who install a
> Flatpak, imposed on the users who never do.

The cost of that decision, stated: **an offline machine cannot install any
Flatpak application, at all.** Not a degraded experience — no runtime, no app.
Consequences that follow:

- The browse view renders `flatpak`-kind entries as **`UNAVAILABLE · OFFLINE`**
  when `flathub` has never been reachable, rather than offering an install
  button that fails after the user commits. Same for a metered link, with the
  metered word instead.
- The fixture repo (app-catalog §9) proves the *mechanism* offline and installs
  a ~3 MB fixture app. It is not a substitute for a runtime and the checks must
  never be read as proving that a real install works.
- **The named remedy, drawn dashed and not built:** the installer ISO is
  already ≈ 2.5–4 GB (installer.md §3). Adding `org.freedesktop.Platform` and
  seeding `/var/lib/flatpak` at install time would cost ≈ 1.2 GB of ISO and
  give every freshly installed machine one working runtime with no network.
  That is a real option with a real price and it is **DESIGN-ONLY** — not
  built, not stubbed, not mocked.

### 7.4 Services and CPU

- **Nothing in this document becomes a resident daemon.** The §6.2 sum (target
  < 100 MB, MVP ceiling < 150 MB) is structurally unchanged, because that gate
  sums Punar daemons and this document adds none. `flatpak-system-helper` is
  D-Bus activated and exits; app-catalog §3.6's build invariant — the enabled
  unit-file set diffed against `os/images/enabled-units.allow`, build fails on
  any addition — is what keeps a future `flatpak` package from quietly shipping
  its own timer.
- **One new timer, one transient process a day** (§4.1). §6.3's idle-CPU target
  is *effectively 0 % when idle*; a daily oneshot with an hour of accuracy slack
  does not move it.
- **The `enabled-units.allow` file gains exactly one line:**
  `punar-app-refresh.timer`. That addition is the whole services-budget delta
  and it is one line in a reviewable file.

---

## 8. Verification — what can be proven offline, and what cannot

The CI VM has **no network**. This is a hard constraint of the project, and the
honest split matters more than the list.

### 8.1 Provable offline, and therefore required

**Catalog CI (host, pure JSON, no VM):**

1. Schema validation, including the new `license` / `publisher` /
   `bundledUpdater` / `disclosures[]` fields.
2. **`bundledUpdater != "active"` for every entry** (§3.2). The admissibility
   rule is a CI assertion, not a guideline.
3. `len(runtimes) <= 3` and every entry's `source.runtime` is a member.
4. `containment` recomputed from each entry's recorded permission set against
   `catalog/containment-bypass.json` matches the recorded `containment`.
5. Every entry with `license: proprietary` has at least one `disclosures[]`
   entry — a proprietary app with nothing to disclose is an unreviewed record.
6. Every `securitySensitive: true` entry has a `publisher` and a
   `bundledUpdater` — because §4.2 will auto-update it and those are the two
   facts that decide whether that is safe.

**In-VM, offline:**

7. `punarctl app search browser` renders tiers and containment from the catalog
   with **no socket opened to the network** (asserted, not assumed).
8. `punarctl app show google-chrome` renders the full §2.3 card — license,
   disclosures, publisher, updater, permission sentences — from the catalog
   record alone.
9. **The policy refusal path.** `allowUserInstall: false` → exit **3**, the §73
   five-answer block, the policy id named, and **nothing installed**.
   `applications.denied` → the same. `snapshot`-kind → exit 3 with the ADR-003
   sentence.
10. **The approval path.** `apps.install` from an agent-attributed peer →
    `approval_required`, exit **4**, an approval record created with
    `kind: application_install`, and **nothing executed**.
11. **`unknown_method`** for `apps.install_all` and for any probe carrying a
    package name, ref, URL, remote or `uid`.
12. **A real install end to end**, against the `file://` fixture remote:
    resolve → policy → permission confirm-with-digest → fixed argv → install →
    verify the pinned commit → audit event → remove. No Flathub contact at
    build time or test time.
13. **`permissions_changed`**: a fixture whose recomputed permission set differs
    from its record → install refuses, exit 1, both sets printed.
14. **The widening rule** (§4.3): a fixture app updated to a wider permission
    set under `auto` policy → **not applied**, notification raised with the
    diff, old deployment still active.
15. **App rollback offline**: install fixture v1, update to v2, `punarctl app
    rollback` → v1 active, **no network**, one audit event.
16. **The survives-an-A/B-swap property — the load-bearing one.** Install the
    fixture app, install a package with `pacman`, drop a binary in
    `/usr/local/bin`, write a file in `$HOME`. Stage and apply an OS update to
    the other slot. Reboot. Assert: the Flatpak is present and launches; the
    `/usr/local` binary is present (§1.7); the `$HOME` file is present; the
    pacman package is **gone**; `slot-residue.json` survived and `punarctl app
    doctor` names it. **This single check is the whole of §1, and it is entirely
    offline.**
17. **The pre-apply warning** (§1.5) renders when slot residue exists, does not
    render when it does not, and appears once per staged release.
18. **Timer wiring**: the vendor `.wants` symlink exists,
    `systemctl show punar-app-refresh.timer` reports `Wants=`, `OnCalendar` and
    `Persistent` are as specified, and `punar-app-refresh.service` is
    `Type=oneshot`. Never `is-enabled`.
19. **The refresh is offline-safe**: run the timer's oneshot with no network →
    exit 0, noop, `lastCheckAt` unchanged, staleness rendered in `app status`,
    and **exactly one** transition audit event, not one per attempt.
20. **The seam** (§5.2): `punarctl update status` and `punarctl app status` are
    diffed against each other in one check; neither prints "up to date" without
    a scope word, and each contains the other's pointer line.
21. **No new resident process**: the §6.2 idle-RSS sample taken with the
    refresh timer stopped is unchanged from the pre-Flatpak baseline.

### 8.2 Not provable offline — named, not skipped

These are marked **NEEDS NETWORKED ENVIRONMENT**. None of them is quietly
absent from a check list; each is a row in the coverage table that says
`UNSUPPORTED` with a reason.

| Cannot be proven in CI | Why | What would prove it |
|---|---|---|
| `com.google.Chrome` (or any Flathub ref) still exists at the pinned commit | Catalog CI has no network; ref liveness is a live-index property (app-catalog §8.2) | A networked job outside CI, which **does not exist**. Until it does, a delisting surfaces as an install failure for a user rather than a review failure for us |
| Chrome's actual finish-args, and therefore its real `containment` | Same | §3.4's recompute-and-refuse makes it self-correcting on the device, which is the mitigation, not a proof |
| That the freedesktop Platform runtime is ≈ 1.2 GB, or the Sdk ≈ 2 GB | Published figures, not a measurement on a Punar image | The first real install on a networked machine. Both are marked `TO VERIFY` and §7 says so |
| That a real Flathub install completes, and how long it takes | No network | A networked soak on real hardware |
| That the update path works against a moving remote — a genuine upstream release arriving and being applied | No network, and no moving fixture can simulate a real publisher | Networked environment. The fixture proves the *transaction*; it cannot prove the *ecosystem* |
| Metered-link deferral against a real metered connection | NetworkManager reports it; CI has no connection to report on | Networked environment with a metered profile |
| Flathub's GPG key rotation behaviour | No network | Networked environment |

The honest summary: **CI can prove that Punar's mechanism is correct and that
its refusals refuse. It cannot prove that the internet is still there.** The
first contact with a real remote is a user's own install on their own networked
machine, and that fact belongs in the release notes.

---

## 9. Honest limits

What this design does not solve, in the house vocabulary (design language §7 —
*silence is not support*).

**1. An application with no Flathub ref has no supported install.** Zoom,
Docker Desktop, most vendor VPN clients, anything needing a kernel module, and
the great majority of the AUR. The answer is a `request` recorded locally, a
`punar-env` project if it is a toolchain, or the user doing it themselves into a
slot that will eat it. This is the largest gap in the design and no amount of
catalog work closes it.

**2. Anything installed outside every sanctioned route is reported, never
prevented.** A user with a shell can `pacman -S`, `makepkg`, `flatpak install`
by hand, `curl | sh`, or drop an AppImage in `$HOME`. Punar's coverage for all
of it is `PARTIAL`: `doctor` lists it, the gate may ask about it once if it came
through an origin zone, and nothing else. **Punar reports rather than claims.**
On a managed device that means `applications.denied` is enforced against
`punard`'s path and not against a determined user's — which is the same limit
every endpoint product has and most of them do not say.

**3. `~/.local/bin` and `/usr/local/bin` are unvouched and un-gated.** Neither
is an origin zone (execution-trust §5.3, deliberately, so ordinary tooling does
not prompt). Software that arrives there without passing through a download
directory runs silently as tier `user`. This is the same hole macOS has and
naming it is the only thing this design does about it.

**4. There is no update path for anything that is not a Flatpak or a web app.**
A binary in `$HOME` or `/usr/local` survives every OS update forever and is
never updated by anything. §1.7 made it survive; nothing makes it current. That
is a real and permanent asymmetry.

**5. `pinned` applications receive no security update until the catalog moves,
and in the MVP the catalog moves only inside a new image.** App-catalog §8.3's
limit, restated because §4's lifecycle does not fix it: the refresh timer can
only offer what the pinned catalog and the `upstream`-mode entries allow. The
signed catalog-only artifact that would decouple them is **DESIGN-ONLY**.

**6. App rollback is one step, per-ref, and not runtime-aware.** §4.5.

**7. Automatic updates depend on `securitySensitive` being right.** It is a
human judgement recorded in a file, re-read every catalog release. A
mis-flagged app either updates when the user did not expect it to, or does not
when it should. The flag is reviewable data, which is the mitigation; it is not
a guarantee.

**8. An org cannot approve an install exception.** M5's control plane is a
mock; the affordance is drawn dashed and its own copy says *"Recorded on this
device. No channel carries this to Acme yet."* Unchanged from app-catalog §4.4.

**9. The gate never sees a Flatpak launch** (§6.2). Provenance for Flatpaks is
an install-time property, not an execution-time one. If a `/var/lib/flatpak`
deployment is tampered with by a local root after install, nothing in this
design notices. §12 of execution-trust already concedes root.

**10. Nothing here is implemented.** Not the command, not the timer, not the
symlink, not the schema fields, not one check. `IMPLEMENTATION_STATUS.md` is
the authority and it does not mention any of it.

### 9.1 Coverage table

| Claim | Coverage |
|---|---|
| A Flatpak application survives an OS update | `FULL` (once implemented) — it is on the shared partition; check 16 proves it offline |
| A `/usr/local` binary survives an OS update | `FULL` (once §1.7 lands) — one symlink, checked |
| A pacman/AUR install survives an OS update | `UNSUPPORTED` — by construction. Warned before, remembered across, told after, reinstalled never |
| Punar never silently loses software you installed | `FULL` for *silently* — every route is refused, warned, or inventoried. `UNSUPPORTED` for *never loses* |
| `punarctl app install <id>` never reaches a package manager with caller text | `FULL` (once implemented) — the id resolves in a signed file; the argv is fixed |
| Google Chrome installs in one command | `FULL` (once implemented) — `punarctl app install google-chrome`, needs network |
| Chrome's own updater does not run on this machine | `PARTIAL` — true for the Flathub build, which is why it is admissible; asserted at catalog build as `bundledUpdater`, and `TO VERIFY` per release |
| Security-sensitive applications stay patched | `PARTIAL` — daily check, ~28 h worst-case latency behind Flathub, and only for what the catalog carries |
| An automatic update cannot widen what an app can reach | `FULL` (once implemented) — §4.3, in `punard`, no policy value disables it |
| An application update can be undone | `PARTIAL` — one step, per ref, until the next prune, no runtime |
| An OS rollback restores your applications | `UNSUPPORTED` — by design, and printed where rollback is offered |
| Flatpak applications work on an offline machine | `UNSUPPORTED` for the *first* install — the runtime is fetched, not shipped (§7.3). `FULL` afterwards |
| Catalog refs are known to still exist upstream | `UNSUPPORTED` — no offline check can establish it |
| The catalog can be updated without an OS update | `UNSUPPORTED` — DESIGN-ONLY |

---

*Punar · Field Note design language · `docs/design/third-party-apps.md`*
