# Punar application catalog and install experience — design

**Status:** design of record, proposed 2026-08-25 · unimplemented (spec 1.22:
nothing in this document ships today; every claim below is a plan until a
milestone lands it and `IMPLEMENTATION_STATUS.md` says so).

**Spec authorities:** section 16 (developer experience; *"Avoid preinstalling
excessive toolchains on the host. Prefer project isolation."*), section 46
(application policy — `required` / `denied` / `allowUserInstall`, and *"Application
semantics should remain stable even if the underlying package system changes"*),
section 12.2 (the universal command center as the install surface; `> install
Firefox`; *"Natural language must resolve to typed capabilities. Never generate
and blindly execute shell commands."*), section 10 (one typed capability layer
behind every interface; the blessed example `InstallApplication(package)`),
section 6 (budgets; 6.2 services RSS, 6.3 no polling), section 28 (approval
gates), section 41 (capability registry), section 42/43 (reconcile, drift
classification), section 57/58 (update architecture; browser/OS separation),
section 60 (hard safety constraints), section 73 (denial voice), section 1.22
(honesty).

**Binding prior contracts, not relitigated here:**

- `docs/design/DESIGN_LANGUAGE.md` — section 2 colour semantics (colour is a
  decision, never decoration), section 7 stroke/honesty semantics (*a solid line
  marks an operating production path; a dashed line marks a mechanism outside
  the current production claim*; the `FULL` / `PARTIAL` / `UNSUPPORTED` coverage
  vocabulary; *"silence is not support"*), section 8 unmanaged-first (org chrome
  only when enrolled; enrollment annotates, never restructures).
- `shell/theme/punar-tokens.json` — every surface below consumes tokens; no
  hardcoded colour appears in this design.
- `docs/api/ipc.md` — transport, framing (**4096-byte request line limit**),
  envelope, the closed method table, structured errors, exit code 4
  (`approval_required`), the M9 approval envelope (§14), and §8's permanent
  non-goal: **no generic execution method of any kind**. This document
  *proposes* one additive section carrying the `apps.*` methods and does not
  edit `ipc.md`. **Section numbers are allocated at merge time, in merge
  order** — see §4.1; the provisional order is M11 §21–§23, this document §24,
  [`execution-trust.md`](execution-trust.md) §25–§27. (§17–§20 are reserved by
  milestone-10.md.)
- `docs/architecture/adr/ADR-003-ab-slots-over-snapper.md` — A/B root slots,
  shared `/var` + `/home` never rolled back, *"Punar-owned mutable `/etc` state
  becomes a capability output, never a file an update must preserve."* This ADR
  determines almost everything below and is the reason section 3 answers the way
  it does.
- `docs/development/milestone-11.md` — the web-app record, `webapps.*`, the
  `browser.policy` capability and its closed key allowlist, and §7's
  DESIGN-ONLY security-overlay channel. Web apps are M11's; this catalog
  *references* them as a source kind and adds no second web-app flow.
- `docs/development/milestone-6.md` — `punar-env` as a short-lived user CLI, and
  §6's hand-assembled deterministic offline OCI archive, which section 9 below
  copies as a pattern for the offline Flatpak fixture.
- `docs/design/mockups/updates-apps.html` — **Plate D-010, the acceptance
  reference** for the Applications surface. Its Sect IV register (required pins,
  denial voice, stable `required`/`denied`/`allowUserInstall` vocabulary, "no
  empty policy chrome waiting to be filled") is binding. This document supplies
  the browse view D-010 gestures at and corrects nothing in it.
- `schemas/desired-state/desired-state.json` — the `applications` block is
  **strict** (`additionalProperties: false`) and its entries are bare package
  names. Section 7 below is written to that fact, not around it.
- **Schema Decision-0 law** (M8, held for four milestones): conform to shipped
  schemas; do not extend them. A new domain gets a new schema file.

**Sibling designs:** [`theme-system.md`](theme-system.md) ·
[`execution-trust.md`](execution-trust.md). The combined budget arithmetic for
all three — services RSS against spec 6.2, disk against ADR-003 — is in
[`execution-trust.md`](execution-trust.md) §13.3. This document owns the only
number in it large enough to argue about: ≤ 3 GB of Flatpak runtimes.

**Vocabulary alignment — resolved 2026-08-25.** This document and
[`docs/design/execution-trust.md`](execution-trust.md) now share **one** trust
vocabulary, defined once in a schema both consume
(`schemas/common/trust.json`, proposed):

```text
punar.trustTier   = system | curated | community | user | unknown
punar.containment = sandboxed | sandbox-bypassed | none
```

Two changes landed to get there, and both went in the direction this document
argued. Execution trust dropped its `catalog` tier in favour of `curated` and
**deleted its `sandboxed` tier entirely** — a tier named after containment was
the collapse law 4 forbids, and containment is now the second axis there as it
is here. This document renamed `unverified` to `unknown`, so that *nothing
vouches for these bytes* is one word on both surfaces. `user` remains
runtime-only (a catalog entry is never `user`); `system`, `curated` and
`community` mean the same sentence in both places.

---

## 0. The five laws of this design

Every decision below is downstream of one of these.

1. **The catalog is data in the read-only root slot; the request carries an id,
   never a package string.** `punard` looks the id up in a signed file it ships
   with and builds a fixed argv from the record. No caller — human, shell, CLI,
   or agent — can put a package name, a URL, a ref, or a flag on the wire that
   reaches a package manager. This is section 60 applied to installation.
2. **A/B slots decide where an app may live.** Anything installed into the root
   slot disappears at the next update. Therefore the supported user-install path
   must write to shared `/var`, and the only mature mechanism that does is
   Flatpak. Section 3's verdict is forced by ADR-003, not by taste.
3. **Every preinstall is a decision the user cannot undo.** Removing a package
   from the running slot is reverted by the next image swap. A preinstalled app
   is therefore a permanent claim on every device, and the burden of proof sits
   with the addition, not the omission.
4. **Trust tier and containment are two different sentences.** *Who vouches for
   this* and *what can it reach* are independent, and an interface that prints
   one word for both is lying. Section 1.4 keeps them apart in the schema so no
   surface can accidentally merge them.
5. **The catalog answers a toolchain question with a project, not a package.**
   `kubectl`, `terraform`, `node` and their kin resolve to `punar-env`, because
   section 16's own sentence says so. There is no "Development" category.

---

## 1. The catalog model

> **A version is a date you can point to; an application is an id you can point
> to.** The catalog is the machine-readable answer to "what can this release of
> Punar install, from where, on whose word, and with what reach."

### 1.1 Where it lives

| Thing | Path | Owner / mode | Why |
|---|---|---|---|
| Catalog document | `/usr/share/punar/catalog/catalog.json` | root:root `0444` | Root slot. It ships **inside the signed image**, so it inherits the image's signature and its A/B rollback — the catalog you can install from is exactly the catalog the running slot was built with. |
| Catalog digest | `/usr/share/punar/catalog/catalog.sha256` | root:root `0444` | Printed by `punarctl app policy`; makes the acting catalog citable in an audit without hashing a 60 KB file in the surface. |
| Schema | `schemas/catalog/app-catalog.json` | repo | New schema domain `catalog` (Decision-0: create, do not extend). |
| Flatpak state | `/var/lib/flatpak/` | flatpak-owned | **Shared partition** — survives an image swap and an OS rollback (section 6). |
| Offline fixture repo | `/usr/share/punar/flatpak/punar-fixture/` | root:root `0444` | Section 9: the only Flatpak content in the image, ~3 MB, built deterministically at image-build time. |

There is **no third database.** `punard` does not keep its own inventory of
installed applications: `apps.list` observes the truth (`pacman -Q` for the
image set, `flatpak list` for the shared set) and joins it against the catalog
at request time. An inventory kept alongside two package managers is a drift
source with no owner, and the observe/apply/verify model (spec 42) already tells
us to read the world instead of remembering it. The policy-relevant history —
who installed what, when, under which policy — already exists in the audit log.

### 1.2 The document shape

```json
{
  "v": 1,
  "catalogVersion": "0.4.2",
  "generatedAt": "2026-08-25T00:00:00Z",
  "snapshot": "2026/08/20",
  "runtimes": [
    {"ref": "runtime/org.freedesktop.Platform/x86_64/24.08",
     "remote": "flathub", "installedBytes": 1288490188}
  ],
  "remotes": [
    {"id": "flathub", "url": "https://dl.flathub.org/repo/",
     "gpgKeyFile": "/usr/share/punar/catalog/keys/flathub.gpg",
     "reachability": "network_required"},
    {"id": "punar-fixture", "url": "file:///usr/share/punar/flatpak/punar-fixture/",
     "gpgKeyFile": null, "reachability": "local"}
  ],
  "categories": [
    {"id": "browsers", "label": "BROWSERS", "order": 3,
     "blurb": "Engines other than the system Chromium."}
  ],
  "apps": [
    {
      "id": "firefox",
      "name": "Firefox",
      "category": "browsers",
      "summary": "Mozilla's browser. An independent engine, kept separate from the system Chromium.",
      "source": {
        "kind": "flatpak",
        "remote": "flathub",
        "ref": "app/org.mozilla.firefox/x86_64/stable",
        "commit": "9b1c4f0a…",
        "runtime": "runtime/org.freedesktop.Platform/x86_64/24.08",
        "downloadBytes": 92341760,
        "installedBytes": 287309824
      },
      "persistence": "shared",
      "trustTier": "curated",
      "containment": "sandboxed",
      "permissions": [
        {"id": "network", "text": "Reaches the internet"},
        {"id": "filesystem:xdg-download", "text": "Reads and writes your Downloads folder"},
        {"id": "device:dri", "text": "Uses the GPU"}
      ],
      "update": {"mode": "pinned"},
      "review": {"reviewedAt": "2026-08-18", "reviewedBy": "punar-catalog",
                 "reviewedForCatalogVersion": "0.4.2"},
      "profiles": ["constrained", "standard", "ai-workstation"],
      "notes": []
    }
  ]
}
```

Field rules that matter:

- **`id` is the stable application name of spec 46.** See section 1.3 — this is
  the single most consequential interop decision in the document.
- **`source.kind`** is the whole architecture in one enum (section 1.4).
- **`persistence`** is derived from `source.kind` and stored anyway, because the
  surface must print it and a derived field a surface has to recompute is a
  field two implementations will derive differently. `image` / `snapshot` →
  `"slot"`; `flatpak` / `webapp` → `"shared"`; `env` → `"project"`.
- **`permissions[].text`** is a **sentence in the second person**, not a Flatpak
  finish-arg. `--filesystem=home` is not a permission a person can consent to;
  "Reads and writes every file in your home directory" is. The `id` keeps the
  machine mapping.
- **`commit`** pins the exact ostree commit. A catalog release is a set of pinned
  commits in the same way a snapshot date is a set of pinned packages (section
  3.4).
- **`review.reviewedForCatalogVersion`** is what makes staleness mechanical
  rather than aspirational (section 8.1).
- **`profiles`** gates entries by spec section 7 hardware profile — a 4 GB
  Electron app is not offered first on a constrained device. Omitted means all.
- Unknown fields are rejected by the schema (`additionalProperties: false`
  throughout). A catalog is signed data read by a root daemon; permissiveness
  here buys nothing and costs a parsing surface.

### 1.3 The catalog id *is* spec 46's application name

Spec 46 says *"Application semantics should remain stable even if the underlying
package system changes"*, and its example lists bare names (`1password`,
`tailscale`) — not `pacman` packages, not Flatpak refs. The shipped
`desired-state.json` binds `required` / `denied.package` to a non-empty string
with no grammar, deliberately.

**Decision: an organization's `applications.required` / `denied` entries are
catalog ids, resolved through `/usr/share/punar/catalog/catalog.json`.**

This is exactly the indirection spec 46 asks for: the org writes `firefox`, and
which release ships it as a Flatpak, a snapshot package, or a web app is a
catalog fact that can change under the policy without the policy changing. It
also produces one honest failure that must be surfaced rather than swallowed:

> An org names an application this release's catalog does not contain. The
> required app is unresolvable. Compliance for `application.policy` is
> `non_compliant` with reason `unknown_application`, the app is named, and the
> §73 message says which catalog version was searched. It is **not** silently
> treated as satisfied, and it is **not** guessed at by fuzzy-matching a package
> name — a policy engine that guesses is worse than one that reports.

### 1.4 `source.kind` — five kinds, and what each one costs

| `kind` | Where the bytes are | `persistence` | Installable at runtime? | Why it exists |
|---|---|---|---|---|
| `image` | root slot, from the pinned snapshot, inside the signed image | `slot` | **No** — it is already there | So the Applications surface can list what is on the machine and say where it came from. Section 2's preinstall set is exactly the `image` entries. |
| `flatpak` | `/var/lib/flatpak` (shared) | `shared` | **Yes** — the supported path | Section 3. |
| `webapp` | M11's record + the user's launcher | `shared` | **Yes**, via M11's `webapps.install` | The catalog lists it; M11 owns the flow. No second web-app path is created here. |
| `env` | nowhere on the host | `project` | **No** — it resolves to a manifest snippet | Law 5. `kubectl`, `terraform`, `node`, `helm`, cloud CLIs. |
| `snapshot` | root slot, via `pacman` | `slot` | **No in MVP** (section 6.2) | Honesty. It names the mechanism that exists, and states what happens to it at the next update. |

`snapshot` deserves its own paragraph, because refusing it is the most
surprising decision in this document.

> **A `pacman` install into the running root slot does not survive an update.**
> ADR-003: the update unit is a whole root-slot image; slot B has no memory of
> what you installed into slot A. Offering "install" for a mechanism that
> silently discards the result at the next update is precisely the failure spec
> 1.22 forbids. So `punarctl app install` refuses `snapshot` entries with the
> section-73 explanation, and names the two paths that do work.
>
> **`pacman` is not removed, not blocked, and not hidden.** Unmanaged-first
> (design language §8) means a user's machine is theirs; a distro that fights
> its own package manager is managing the user. What Punar owes them is the
> truth about the consequence, which is why `punarctl app doctor` exists
> (section 6.2): it diffs the running slot against the image manifest and prints
> *"3 packages in this slot are not in the image and will not survive the next
> update."* One `pacman -Qm`-shaped diff, no daemon, no timer.

### 1.5 Trust tiers — provenance and review only

Four tiers. Each is a claim about **who vouches for the bytes and who read the
permissions**, and nothing else.

| Tier | Meaning | Stroke (design language §7) |
|---|---|---|
| `system` | In the root slot, built from the pinned snapshot, covered by the image signature. Runs with the user's full privilege, unsandboxed. Punar chose it and cannot un-choose it without a release. | solid |
| `curated` | In the catalog. Punar wrote the summary, read the permission set, pinned the commit, and re-reviews it every catalog release. Punar vouches for the pin **and** has read what the app asks for. | solid |
| `community` | In the catalog and pinned, therefore installable — but **not reviewed**. Summary and permissions come from the app's own AppStream metadata. Punar vouches for the pin, not for the app. | solid, always labelled |
| `unknown` | Not in the catalog. `punard` will not install it. The user may install it themselves and Punar will not stop them; `punarctl app doctor` lists it as installed outside the catalog. | dashed |

The fifth value of the shared enum, **`user`**, cannot occur here: it names
bytes this machine produced, and the catalog describes bytes somebody
published. It appears only at execution time
([`execution-trust.md`](execution-trust.md) §4), and it is the tier under which
every `cargo build` artefact on the machine runs. The enum is shared so that a
single surface — the Applications rail, `punarctl app show`, an approval card —
prints one word with no translation table behind it.

The tier does **not** say what the app can reach. That is `containment`:

| `containment` | Meaning | Rendered as |
|---|---|---|
| `sandboxed` | Flatpak sandbox with a permission set that does not defeat it. | plain |
| `sandbox-bypassed` | Flatpak sandbox present, but the app holds at least one permission that dissolves it (section 1.6). | **warn** colour, with the sentence that says why |
| `none` | `image` and `snapshot` kinds. Runs as you, reaches what you reach. | plain, stated |

`system` + `none` is the honest description of Chromium on this machine today.
`community` + `sandboxed` is a stronger *containment* claim than `system` +
`none` while being a weaker *provenance* claim, and a design that had one word
for both could not say that sentence. Hence law 4.

### 1.6 The bypass list — computed, not asserted

`containment` is **computed from the permission set of the exact ref about to be
installed**, by a rule in one place:

```text
containment = sandbox-bypassed  if any of:
  filesystem: host | host-os | host-etc | home
  talk-name:  org.freedesktop.Flatpak          (spawn on the host — full escape)
              org.freedesktop.Flatpak.Development
  device:     all
  socket:     x11 | fallback-x11   (without wayland; no Wayland security boundary)
              session-bus (unfiltered)
  feature:    devel
```

This list is data, reviewed like M11's `policy-allowlist.json` and M10's
signature file, at `catalog/containment-bypass.json`. Two consequences the
surfaces must honour:

1. A `sandbox-bypassed` app never renders the word "sandboxed" anywhere. The
   card says, in the second person: *"This app can read and write every file in
   your home directory. Its sandbox does not constrain your files."*
2. **The card recomputes containment from the ref, and stops if it disagrees
   with the catalog record.** An app that added `--filesystem=host` in a version
   published after our review is exactly the case a stale record would
   mis-describe. Disagreement is an install refusal (`conflict`,
   `details.reason: "permissions_changed"`), naming both permission sets and
   next step *"the catalog entry is stale; report it with `punarctl app request
   firefox --recheck`"*. Refusing on a permission surprise is cheap; the
   alternative is a card that lied.

---

## 2. What ships preinstalled

> **The default install is a claim on every Punar device forever, and the burden
> of proof sits with the addition.**

### 2.1 The line

A package ships in the image only if it satisfies at least one of:

- **(a) Reach or recover.** Without it you cannot reach the catalog, diagnose
  the network, or repair the machine.
- **(b) Host integration point.** It is a session or identity mechanism that
  genuinely cannot live in a container or a Flatpak sandbox — it needs `$HOME`,
  the session bus, the agent socket, or the compositor.
- **(c) Cross-project primitive, cheaper shared than duplicated.** It is used by
  every project, is small, and is version-insensitive.

And it must satisfy all of:

- **(d) No enabled unit and no timer.** Spec 6.3. A preinstall that adds a
  resident process or a periodic wakeup needs its own budget line and its own
  argument; none below has one.
- **(e) Named in spec 16, or required by a decision in this document.**

Everything else is one keystroke away.

### 2.2 What is already there, and why it stays

`hyprland`, the two portals, `quickshell`, `greetd`, `foot`, `pipewire` +
`pipewire-pulse` + `wireplumber`, `mesa`, `polkit`, `hyprpolkitagent`, `grim`,
`slurp`, `wl-clipboard`, `noto-fonts`(+`-emoji`), `nftables`, `podman` + `crun`
+ `netavark` + `aardvark-dns`, `chromium`, `git`, `neovim`, `jq`.

These are the compositor, the session, the shell, the audio and graphics stack,
`punard`'s firewall backend, `punar-env`'s runtime, the browser M11 integrates,
and two developer tools plus `jq` already justified in M1/M3. Nothing here is
reopened.

### 2.3 The additions, one argument each

| Package | ≈ installed | Rule | Argument |
|---|---|---|---|
| `openssh` (client only) | 10 MB | (b) | Your keys live in `$HOME`, `ssh-agent` is a session service, and `git` over SSH is the default for every private repository on earth. It cannot live in a container without either copying keys in (worse) or forwarding the agent (a sandbox hole). **`sshd` is installed but never enabled** — spec 44.5 makes inbound SSH an enterprise service control, and a distro that opens a listening port by default has decided something the user should decide. |
| `curl` | 1 MB | (a) | You cannot diagnose a network you cannot make a request on. Named in spec 16. `libcurl` is already resident via `pacman`; this is the binary. |
| `ripgrep` | 5 MB | (c) | Search across the whole machine is not a per-project act, and duplicating a 5 MB static binary into every environment is pure waste. Named in spec 16. |
| `fd` | 3 MB | (c) | Same argument, same sentence. Named in spec 16. |
| `fzf` | 4 MB | (c) | This is the terminal's half of the keyboard-first grammar: `fzf` is how a terminal user does the type-to-filter interaction that the command center does graphically. Spec 12 wants both halves to feel like one system. Named in spec 16. |
| `tmux` | 1 MB | (b) | A session multiplexer is how a terminal user survives a compositor crash or a logout, which is a host-session property by definition. Spec 16 says "tmux or equivalent". |
| `man-db` (+`less`) | 5 MB | (a) | Spec 12.3: *"Avoid requiring users to memorize dozens of undocumented shortcuts."* Every package we ship carries its own man pages for free; without `man-db` they are unreadable bytes on disk. **`man-pages`** (the ~35 MB POSIX/kernel sections 2/3 set) is **not** included — it is a developer reference, and it is in the catalog. |
| `flatpak` + `ostree` + `bubblewrap` + `appstream` | ≈ 60 MB | (d),(e) | Required by section 3. Adds **no enabled unit and no timer** on Arch: `flatpak-system-helper` is D-Bus activated, and Punar never installs a background updater. Section 3.6 states this as an asserted build invariant, not a hope. |

**Total added: ≈ 90 MB.** Verified against the pinned ALA snapshot
(`os/images/snapshot.env`, 2026/08/20) on 2026-08-25 — every package above
exists in the official repositories at the version and installed size quoted;
the direct sum of the twelve named packages is **55.9 MB**, and the ≈ 90 MB
figure is that sum plus the new transitive dependencies `flatpak` and
`appstream` pull in (`libmalcontent`, `xdg-dbus-proxy`, `python-gobject`,
`dconf`, `fuse3`, `gpgme`, `json-glib`, `libxmlb`). So ≈ 90 MB is an honest
upper bound rather than an estimate. Against ADR-003's `R_max = 5 GB` image
budget that is **1.8 %**; against the 8 GiB slot itself it is **1.1 %**; and
against the spec 5.1 minimum 128 GB disk, **0.07 %.** (An earlier draft
reported the 1.8 % figure as a fraction *of the slot*; it is a fraction of
`R_max`.) Against the section 6.1 idle-RAM budget it is **zero**: none of
these starts at boot, none is a daemon. Against the section 6.2 services gate it
is **structurally zero**: the gate sums Punar daemons, and none of these is one.
Disk is the only budget a preinstall spends — *unless it adds a unit*, which is
why (d) is a hard rule and not a preference.

### 2.4 The refusals, which are the actual argument

A line that admits everything proposed is not a line.

| Refused | Why it is catalog or `punar-env`, not image |
|---|---|
| `github-cli` (`gh`) | ~30 MB Go binary that authenticates to exactly one vendor. It is a *service client*, not an OS integration point. A user who does not use GitHub pays for it on every device forever (law 3). One keystroke. Spec 16 says "make frictionless", and a catalog entry that installs in seconds is frictionless. |
| VS Code / `code-oss`, JetBrains | Spec 16 asks for a **path**, not a preinstall. Both are Flatpak catalog entries; JetBrains additionally has Toolbox. ~300 MB and ~2 GB respectively — the two largest things anyone would propose adding, and the two most personal. |
| `podman-docker` (the `docker` shim) | ~1 MB, and still no: it silently shadows a real `docker` if one is ever installed, and a surprise is worse than a keystroke. Catalog entry, with the shadowing named in its summary. |
| `kubectl`, `helm`, `terraform`/`opentofu`, `awscli`, `gcloud`, `az` | The exact things spec 16's *"avoid preinstalling excessive toolchains"* sentence is about, and version-sensitive in the way that bites: `terraform` 1.5 and 1.9 disagree about state files, and the version that is right is a property of the repository, not of the laptop. `env`-kind catalog entries that resolve to a `punar-env` manifest snippet. |
| Language runtimes (`node`, `python` beyond what base pulls, `go`, `rustup`) | Same, more so. This is the sentence spec 16 wrote. |
| `unzip`, `p7zip` | `bsdtar` from `libarchive` is already in `base` and reads zip. An addition that duplicates a capability we already ship fails rule (c) on the word "cheaper". Listed here so the omission is visible rather than accidental. |
| A GUI store application | Section 5: the surfaces already exist (command center, System Control). A second application to browse applications is 200 MB of Electron to avoid writing 400 lines of QML. |

### 2.5 The consequence of preinstalling, restated

Because slot B is built, not mutated, **a user cannot permanently remove a
preinstalled app.** `pacman -R chromium` in slot A is undone by the next update.
The Applications surface says so on `system`-tier rows: *"Ships with the image ·
removing it lasts until the next update."* This is the whole reason the list
above is short. It is also, honestly, an argument for the catalog: a
Flatpak-installed Firefox *can* be removed and stay removed, which makes it a
better citizen of the user's machine than a preinstall.

---

## 3. Flatpak: verdict and reasoning

> **Adopt it — as the single supported runtime install path for graphical
> applications, and as nothing else.** The decision is forced by ADR-003 before
> any of its own merits are counted.

### 3.1 The forcing argument

ADR-003 makes the root slot an image, not a mutable filesystem: `/var` and
`/home` are shared and never rolled back; everything else is replaced wholesale
on update. So the question "should Punar adopt Flatpak?" is really the question
**"where may a user-installed application live such that it is still there
tomorrow?"** The complete list of places:

| Candidate | Survives an image swap? | Suitable for GUI apps? |
|---|---|---|
| root slot via `pacman` | **No** | — |
| `/var/lib/flatpak` | Yes | **Yes** |
| a `punar-env` container | Yes | No — it is a project boundary, correctly, and a GUI app is not a project |
| M11 web app record + browser profile | Yes | Only for things that are web pages |
| `~/.local/bin`, AppImage, tarball in `$HOME` | Yes | Yes, with no sandbox, no permission declaration, no update path, no signature, and no inventory |

There is one row that is a real answer. Punar could refuse it and ship an OS on
which the only supported way to install an application is to rebuild the image —
which is a defensible product (it is roughly what several immutable distros do),
and it is *not* the product spec 12.2 describes when it puts `> install Firefox`
in the command center as a worked example.

### 3.2 What adoption buys, beyond survival

1. **Portals are already installed and already paid for.** `xdg-desktop-portal`
   + `xdg-desktop-portal-hyprland` are in the image since M1. The file-chooser,
   screenshot, and screencast brokering that makes a sandbox usable is running
   cost we have already accepted.
2. **Permissions are declared and readable *before* install.** This is the
   requirement in section 5 and there is no `pacman` equivalent: a pacman package
   runs arbitrary `.INSTALL` scriptlets as root at install time, and nothing in
   its metadata tells you what it will touch afterwards. A Flatpak ref's
   permission set is inspectable ahead of the bytes. Section 1.6 turns that into
   the pre-install card.
3. **It gives spec 46 `denied` a real enforcement point** for graphical apps, on
   the same principle M11 established for the browser: a root-owned file the
   user cannot write beats a courtesy check inside a CLI the user could replace.
4. **A weaker principal is available at all.** Today every application on Punar
   runs with the user's full authority. The trust ladder in section 1.5 is only
   meaningful because a tier below "runs as you" exists.

### 3.3 The costs, counted honestly

**Disk, and it is the real one.** `org.freedesktop.Platform` **25.08** — the
current freedesktop-sdk stable series, verified against Flathub on 2026-08-25;
an earlier draft of this section said 24.08, which is two series stale — is on
the order of **1.2 GB** installed. Every additional runtime *family or major
version* is roughly another gigabyte, and runtime duplication is the standard
way a Flatpak installation reaches 8 GB of dependencies for 400 MB of
applications. The 1.2 GB figure is itself `TO VERIFY`: it comes from the
published size of the runtime, not from a measurement on a Punar image, and
the first real install should record it.

The mechanism, not the promise:

> **The catalog pins at most three runtimes per catalog release**, listed in the
> top-level `runtimes[]` array, and every `flatpak` entry's `source.runtime`
> must be one of them. Catalog CI asserts `len(runtimes) <= 3` and asserts the
> membership. A pull request adding an app that needs a fourth runtime does not
> add a runtime; it either waits for the next release's runtime bump or is
> refused with the arithmetic attached.

Three runtimes ≈ 3 GB. The arithmetic against ADR-003, corrected: the §5.1
minimum 128 GB disk is 119.2 GiB, of which ADR-003 fixes **17 GiB** as ESP plus
two 8 GiB root slots, leaving **≈ 102 GiB shared between `/var` and `/home`** —
not 110 GiB, and the `/var`:`/home` split is not specified anywhere yet. So the
defensible sentence is **≈ 2.5 % of the minimum disk**, and *"2.7 % of `/var`"*
is a number this project cannot yet compute. It is affordable either way. What
is not affordable is an uncapped runtime set, which is why the cap is a CI
assertion rather than a guideline, and why the partition layout is listed as a
prerequisite rather than assumed.

**A second package system.** True, and mitigated by scope rather than denied:
the user never types `flatpak`. The catalog, `punarctl app`, and the command
center are the surface; `flatpak` is an implementation detail `punard` drives
with a fixed argv. It is not hidden — running `flatpak` by hand works, and
`punarctl app doctor` reports what you installed that way as `unknown`.
"Second package system" is a maintenance cost we pay, not a concept the user
learns.

**Idle cost.** Zero, and asserted (section 3.6): no enabled unit, no timer, no
resident process. `flatpak-system-helper` is D-Bus activated and exits.

**Peak cost during an install.** `flatpak` + `ostree` can use a few hundred MB
resident while pulling and deploying. That is not an idle number, it is not a
Punar daemon, and it is therefore outside the section 6.2 services gate.
Recorded as `PUNAR_APP_INSTALL_PEAK_RSS_MB` in the perf report, **recorded and
not gated** — M11 decision 24's idiom, for the same reason: a number in the
record beats a number someone guesses at review time.

### 3.4 How Flatpak interacts with the pinned-snapshot model

ADR-001's whole reproducibility claim is that a release is one pinned date.
Flathub is a live, moving index. Punar reconciles them by **applying the same
discipline in the other package system**:

- **Every `flatpak` catalog entry pins a `commit`.** Installs are
  `flatpak install --system --noninteractive <remote> <ref> --commit=<sha>`.
  A catalog release is a set of pinned commits exactly as a snapshot date is a
  set of pinned packages, and `catalogVersion` + `catalog.sha256` is the thing
  you cite in an audit.
- **`update.mode` is `pinned` by default.** Installed apps stay at the catalog's
  commit until the catalog moves.
- **`update.mode: "upstream"` exists and is narrow.** It tracks the remote
  branch head, and it is permitted only for entries the catalog marks
  `securitySensitive: true` — network-facing apps whose CVE latency is the
  dominant risk. This is spec 58's argument (*"emergency security updates should
  not wait for a full OS release"*) applied one level up: some applications have
  a cadence that is not the OS's, and pretending otherwise ships known-vulnerable
  code on purpose. The entry says which mode it is in and the card prints it, so
  a user always knows whether their copy is reproducible or current.
- **The remote's GPG key is pinned in the image**, at
  `/usr/share/punar/catalog/keys/`. Flatpak verifies the commit signature; Punar
  verifies that the key it verified against is the one that shipped in a signed
  image.

**The honest limit** (section 8.3 restates it): a `pinned` app receives no
security update until the catalog is republished, and in the MVP the catalog is
republished only by shipping a new image — which is exactly the ADR-001 versus
spec 58 tension M11 §7.1 refused to soften. The remedy is named and drawn
dashed: a **signed catalog-only artifact** delivered to `/var/lib/punar/catalog/`
and verified with the update manifest's own verification order (ADR-003:
signature → admissibility → digest → re-read digest). That is DESIGN-ONLY. It is
not built, not stubbed, not mocked.

### 3.5 What Punar does *not* adopt from Flatpak

- **No Flathub-as-a-front-door.** Flathub is a pinned *source*; it is not a
  browsable index inside Punar's UI. You browse the catalog, which is 40–160
  reviewed entries, not 3,000.
- **No `--user` installs.** Everything is `--system`, into shared `/var`,
  because a managed device's required apps are a device fact and because two
  parallel installation scopes is the confusion that makes Flatpak folklore.
- **No background updater, ever.** Spec 6.3. Updates are a user act or a
  reconcile-classified act (section 6.3).
- **No `flatpak override` as a user-facing feature in MVP.** Editing an app's
  permissions after install is a real capability and it belongs behind a typed
  capability with an audit event; designing it here would be designing it badly.
  Tracked, not claimed.

### 3.6 The build invariants that make these claims checkable

An invariant a script can check is worth more than a sentence in a design
document (M11 law 2, adopted verbatim):

| Invariant | Check |
|---|---|
| No enabled unit outside the Punar set | `systemctl list-unit-files --state=enabled` diffed against `os/images/enabled-units.allow` at image build; build fails on any addition. Catches a future `flatpak` package that starts shipping an update timer. **Verified 2026-08-25:** Arch `flatpak` 1:1.18.1-1 ships `flatpak-system-helper.service` (D-Bus activated), three user services and four D-Bus service files, and **no `.timer` at all** — so the invariant currently holds and the check exists to keep it holding. |
| At most 3 runtimes, and every entry uses one of them | Catalog CI, offline, pure JSON. |
| Catalog validates against `schemas/catalog/app-catalog.json` | Catalog CI, offline. |
| Every `image`-kind entry is actually in the image | In-VM check: `pacman -Q <pkg>` for each. Offline. |
| Every `image`-kind package in the image has a catalog entry | The reverse direction, so the Applications surface can never show an unexplained package. Offline. |
| No `flatpak` bytes in the image except the fixture repo | Size assertion: `/usr/share/punar/flatpak` < 16 MiB (M6's tripwire idiom). |

---

## 4. The install flow as a typed capability

> **The request carries an id. Everything that reaches a package manager comes
> from a signed file in a read-only filesystem.**

### 4.1 Proposed IPC surface (`apps.*` — additive, still `v: 1`)

> **Section numbers are allocated at merge time, in merge order, and no design
> document may hard-code them.** `ipc.md` ends at §20 (M10). Five unmerged
> designs queue behind it — M11 (`webapps.*`, `browser.policy`), M12 (network),
> M13 (`update.*`), this one (`apps.*`), and
> [`execution-trust.md`](execution-trust.md) (`trust.*`) — and three of them had
> independently written "§24" into their own text. The unique thing is the
> method names, not the heading number. Provisional order, recorded so a reader
> has something to hold: M11 §21–§23, this document §24, execution trust
> §25–§27, M12 and M13 after them.

| Method | AuthZ | Mutating | Audited |
|---|---|---|---|
| `apps.catalog` | any connected peer | no | no |
| `apps.list` | any connected peer | no | no |
| `apps.install` | any connected peer (policy decides); **agent-attributed peers gate to approval** | yes | always |
| `apps.remove` | any connected peer (policy decides); agent-attributed peers gate to approval | yes | always |
| `apps.update` | any connected peer; agent-attributed peers gate to approval | yes | always |

`apps.install_all`, `apps.launch`, any verb taking a package name, a ref, a URL,
a remote, or a flag, and any verb taking a `uid`, **do not exist and answer
`unknown_method`.** Launching is an `execve` in the user's own session and is
not an IPC concern (M11's rule, reused).

`apps.install` params: `{"id": "firefox", "confirm_permissions_sha256": "…"}`.
Two fields. The second is the digest of the permission set the *caller was
shown* — the pre-install card's contents — and `punard` refuses if it does not
match the set it computes from the ref (section 1.6, `permissions_changed`).
Consent is to a specific set of permissions or it is not consent.

`apps.catalog` params: `{"query": "…"}` | `{"category": "…"}` | `{"id": "…"}`,
with results capped at 50 entries and `"truncated": true` when clipped, so the
response stays bounded without a pagination protocol.

### 4.2 The pipeline

```text
resolve id in catalog            ← the only place a package string comes from
  ↓  not found → honest failure (4.5)
policy check (spec 46, effective document)
  ↓  denied → denied, §73 message, named policy
authorize peer
  ↓  agent-attributed → approval_required (exit 4), nothing executes
compute permissions from the ref, compare to caller's confirmed digest
  ↓  mismatch → conflict (permissions_changed)
build fixed argv from the record, execute as root
verify: flatpak info <ref> reports the pinned commit deployed
audit: action system.install_package, resource <id>
respond
```

Observe → apply → verify → audit is M3's shape, unchanged. The fixed-argv rule
is M3's `nft` pattern, unchanged: an argv vector, never a shell string, with
every element drawn from the catalog record or a compiled-in constant.

### 4.3 The policy check (spec 46)

Read from the M4 effective document, so the citation is whatever layer won:

| State | Requester: human | Requester: agent-attributed |
|---|---|---|
| unenrolled (`personal-defaults`) | **allow** | `approval_required` |
| `allowUserInstall: true`, id not denied | **allow** | `approval_required` |
| id in `applications.required` | **allow** (it is org-required) | `approval_required` |
| `allowUserInstall: false`, id not required | **deny**, cite the policy, offer the exception path (dashed) | **deny** — the agent path does not outrank the org rule |
| id in `applications.denied` | **deny**, cite the policy, offer the exception path (dashed) | **deny** |

`apps.remove` mirrors it: removing an `applications.required` app is `denied`
with the policy named; everything else the user installed is theirs to remove.

### 4.4 Approval — and what `approval_required` can honestly mean

The design language's own approval card is this exact flow, verbatim:

```text
APPROVAL · APR_123 · EXPIRES 14:02                        [MEDIUM]
──────────────────────────────────────────────────────────────────
Claude Code requests system.install_package · libvirt
```

So an AI agent asking to install an application is canon, and it is the case
`approval_required` was built for. M9's envelope takes **one more `kind`**,
additively (`ipc.md` §14.3 defines `kind` as selecting which sibling fields are
meaningful — adding one is exactly the additive change §3.3 permits).
[`execution-trust.md`](execution-trust.md) adds a second new kind,
`execution_request`; the two are siblings, not rivals — one governs *may these
bytes be installed*, the other *may these bytes run* — and neither should
describe itself as "the fourth", since whichever merges second would be lying:

| Field | Value |
|---|---|
| `kind` | `application_install` |
| `capability` | `apps.install` |
| `resource` | the catalog id (`libvirt`) |
| `contract` | `InstallApplication(libvirt)` — spec 10's blessed form |
| `risk` | the catalog entry's `containment`: `sandboxed` → `medium`, `sandbox-bypassed` / `none` → `high` |
| executor on `resolve(approved)` | **punard**, immediately, in the resolver's request, under the store lock — identical to `capability_set` (§14.6) |

The card carries the permission sentences and the trust tier, because a person
approving an install is answering "may this thing reach my files", not "may a
package be installed".

**And now the finding this design will not paper over.**

> **An approval whose only available resolver is the person the policy restrains
> is theatre.** M9's resolver rule is human-only and routes to `approval.user` —
> the local human is the only entity on the device that can answer. That makes
> `approval_required` meaningful exactly when **the requester is not the
> resolver**: the AI case. An org rule that a human must "get approval" to
> install something needs an approver the device cannot reach, and Punar has no
> such channel: M5's control plane is a mock.
>
> Therefore: **agent installs produce approvals; org restrictions produce
> denials with a named exception path, and that path is drawn dashed.** Plate
> D-010 already draws a `Request exception · Approval required` button; its
> status is honest and stated here — the button records the request locally,
> queues it per spec 55 offline behaviour, and says *"Recorded on this device.
> No channel carries this to Acme yet."* Rendering it as though an approver
> existed would be the failure spec 1.22 forbids.

### 4.5 The honest failure: not in the pinned catalog

The most common failure, and the one most likely to be papered over:

```text
PUNAR · APPLICATIONS                                          punar-desktop

Firefox is not in this release's catalog.

Punar installs from a pinned catalog, not from a live index — every
application on this machine is a version you can point to.

  Catalog     punar-catalog 0.4.2 · snapshot 2026/08/20 · 148 entries
  Searched    firefox · mozilla · browser
  Nearest     chromium        installed · ships with the image
              zen-browser     catalog · community · sandboxed

Next step
  punarctl app request firefox     records the request on this device.
                                   Nothing is sent anywhere.
```

Three properties: it names the catalog version so the statement is falsifiable;
it offers near matches with their tiers so the user can decide rather than
guess; and `request` writes to a local file and says so, because on an unenrolled
machine there is nobody to send it to and implying otherwise would be a lie
(design language §8).

The sibling failure — `snapshot`-kind entry — says the other true thing:

```text
libvirt ships in the image or not at all.

Installing it into the running slot would work today and disappear at the
next update: a Punar update replaces the whole root filesystem (ADR-003).

Next step
  punar-env       run it inside the project that needs it
  punarctl app request libvirt --image    propose it for the image
```

### 4.6 Audit

Reuses `schemas/audit/audit-event.json` unchanged. `system.install_package` is
already the schema's own example action, and the design language's approval card
already prints it — this design adopts the name that exists rather than minting
`application.install`. (Web apps keep M11's `webapp.install`; the two are
different mechanisms with different enforcement points and should not share a
row in the log.)

| `action` | `resource` | `decision` | `result` | `audit_category` |
|---|---|---|---|---|
| `system.install_package` | `<catalog id>` | `allow` / `deny` / `approval_required` | `installed` / `denied` / `noop` / `apply_failed` / `verify_failed` | `application` |
| `system.remove_package` | `<catalog id>` | `allow` / `deny` | `removed` / `denied` | `application` |
| `system.update_package` | `<catalog id>` or `all` | `allow` / `deny` | `updated` / `noop` / `apply_failed` | `application` |
| `capability.set` (existing) | `application.policy` | existing | existing | `policy` |
| `reconcile.remediate` (existing) | `application.policy` | existing | existing | `policy` |

The catalog id and the pinned commit are recorded. **No file path inside the
app, no runtime contents, no permission grant made after install** — there is no
field that could carry them, which is M8's schema-as-privacy-model applied to a
fifth domain.

### 4.7 What the command center shows

Four states, each in field-note grammar, each with the colour rule of design
language §2 (a screen with no decision to report has no colour):

```text
> install firefox

  FIREFOX                                    CATALOG · CURATED · SANDBOXED
  ─────────────────────────────────────────────────────────────────────────
  Mozilla's browser. An independent engine, kept separate from the system
  Chromium.

  Source        flathub · org.mozilla.firefox · commit 9b1c4f0a
  Update        pinned to catalog 0.4.2
  Size          88 MB download · 274 MB installed
  Reaches       the internet
                your Downloads folder
                the GPU
  Policy        Personal defaults · you install what you want

                                                    [↵] INSTALL   [ESC] CANCEL
```

- **Allowed** (above): the affirmative primary carries the ok-family fill —
  install is a commit action (design language §2 action colour). One coloured
  button on the surface.
- **Sandbox-bypassed**: the `Reaches` block leads with the warn-coloured
  sentence *"every file in your home directory"*, and the header tag reads
  `CATALOG · CURATED · SANDBOX BYPASSED` in warn. The install button stays
  ok-green — it is still the user's machine and their decision; the colour
  states the deviation, not a veto.
- **Approval raised** (agent requester): warn tag `APPROVAL · APR_…`, the live
  expiry countdown, no install button — the overlay owns the decision.
- **Denied** (managed): bad-family, the §73 five-answer block (section 7.2), the
  exception affordance drawn dashed.

---

## 5. Discovery

> **The catalog is small enough to read, so browsing it is a list and a rail,
> not an application.**

### 5.1 Decision: no new top-level surface

Two surfaces already exist and both are keyboard-first:

- **`SUPER+Space` — the command center** is the search and install path, per
  spec 12.2, which names `> install Firefox` as a worked example. Typing ranks
  catalog entries alongside everything else it ranks; selecting one opens the
  card in section 4.7. This is the fast path and the one most people will ever
  use.
- **`SUPER+S` → Applications** is the browse path. It is the section 63 taxonomy
  rail item Plate D-010 already draws as `02 · Applications`. This design adds a
  browse view to that panel; it does not add a screen to the OS.

A dedicated store application is refused in section 2.4 for the reason that
matters here: the catalog is 40–160 entries. A surface for 160 rows is a list.

### 5.2 Categories in field-note grammar

Eight, and the count is a design constraint, not an outcome: **a catalog whose
categories do not fit one screen has failed at curation.** Rendered as tracked
uppercase mono section headers over hairline rules, with a tabular count — the
masthead grammar of design language §5:

```text
PUNAR · SYSTEM CONTROL · APPLICATIONS              5 INSTALLED · CATALOG 0.4.2
────────────────────────────────────────────────────────────────────────────

EDITORS & IDES                                                            12
TERMINALS & SHELLS                                                         6
BROWSERS                                                                   4
COMMUNICATION                                                              9
GRAPHICS & DESIGN                                                          7
MEDIA                                                                      8
PRODUCTIVITY                                                              11
UTILITIES                                                                 14
```

**There is deliberately no "Development" category.** Law 5: a category by that
name is an invitation to the host-toolchain sprawl spec 16 forbids, and the
answer to a toolchain query is a project. Searching `kubectl` in the command
center returns an `env`-kind entry that resolves to guidance, not an install:

```text
> kubectl

  KUBECTL                                                  PROJECT ENVIRONMENT
  ─────────────────────────────────────────────────────────────────────────
  Kubernetes CLI. Punar keeps toolchains in projects, not on the host — the
  version that is right is a property of the repository.

  Add to this project's environment:
      toolchains:
        kubectl: "1.31"

                                            [↵] OPEN punar-env manifest
```

That is spec 16's own sentence rendered as an interaction.

### 5.3 Trust tier and permissions, before the bytes

Three rules, all of which exist to keep the word "before" true:

1. **The card renders from the catalog record and a metadata read of the ref.
   No application bytes are fetched to render it.** The permission set and the
   sizes come from the remote's summary metadata; the download starts only after
   the confirm keystroke.
2. **Confirm is a separate, explicit keystroke, and it carries a digest of what
   was shown** (`confirm_permissions_sha256`, section 4.1). There is no path
   where a permission set is displayed and a different one is installed.
3. **Containment is recomputed from the ref, not read from the record**
   (section 1.6). If the app changed what it asks for since our review, the
   install stops and says both sets.

The row grammar in the browse list carries the same two facts at a glance,
because a tier is only useful if it is visible without opening anything:

```text
  Firefox           Independent browser engine        CURATED · SANDBOXED
  Obsidian          Local markdown notes              CURATED · HOME ACCESS
  Zen Browser       Firefox-based browser             COMMUNITY · SANDBOXED
  Bitwarden         Password manager                  CURATED · SANDBOXED
```

`HOME ACCESS` is the warn-coloured rendering of `sandbox-bypassed` for the
common case, in words rather than a shield icon. Design language §2: the colour
is the deviation; the words are the explanation.

---

## 6. Updates

> **Two cadences, and the surface never pretends they are one.**

### 6.1 Root-slot apps update with the image

`image`-kind entries — everything in section 2 — are replaced wholesale when the
A/B slot swaps. Consequences, stated in both directions:

- You cannot update Chromium without taking a whole OS update. This is
  ADR-001-versus-spec-58 and M11 §7 already refused to soften it; the named
  remedy (the `punar-security` pinned-package overlay channel with its own key
  and its own rollout ring) is **DESIGN-ONLY** and drawn dashed on every
  surface that mentions it.
- You cannot permanently remove one (section 2.5).
- You cannot end up with a *drifted* one: a fresh slot is a fresh image, so the
  preinstall set is identical on every device on a given release. That is the
  compensating benefit and it is real.

`punarctl update status` already prints the browser block honestly (M11 §7.5);
the Applications surface prints `Ships with the image · <snapshot date>` on
`system` rows and links to it.

### 6.2 Flatpak apps do not

`/var/lib/flatpak` is on the shared partition. Therefore:

- **They survive an OS update.** Intended.
- **They survive an OS rollback — which means an OS rollback does not fix a bad
  app update.** This is the consequence people get wrong, so the surface says it
  where rollback is offered: *"Rolling back the OS does not roll back your
  applications. They live on the shared partition."* The right tool is
  `punarctl app rollback <id>`, which re-pins the previous commit; Flatpak keeps
  the prior deployment, so this is cheap and offline.
- **They update on the catalog's cadence, not the OS's** — `pinned` entries when
  the catalog moves, `upstream` entries when their branch head moves (section
  3.4). The card states which mode an app is in, at install and afterwards.
- **The asymmetric risk is forward, not backward.** Runtimes live in `/var` too,
  so apps keep working across an OS rollback; the case to watch is a new app
  expecting a portal interface an older slot lacks. `punarctl app doctor` reports
  it as an incompatibility rather than letting it present as a crash.

### 6.3 What triggers an update — and what must not

**No polling. Ever.** Spec 6.3, and the reason section 3.5 refuses a background
updater outright. The complete set of triggers:

| Trigger | What runs | Network? |
|---|---|---|
| `punarctl app update [<id>]` | user-invoked; the only path that fetches | yes |
| command center → *update applications* | the same typed call | yes |
| `punard-reconcile.timer` (existing) | `application.policy` **observes** installed-versus-required and classifies drift. **It performs no network I/O.** | no |

The reconcile point deserves its own sentence. `application.policy` joins the
registry as a capability alongside `security.firewall`, `system.hostname`,
`time.timezone` and M11's `browser.policy`, so `capabilities.*`,
`policy.effective`, `policy.explain`, `compliance` and the existing timer all
cover it with **zero protocol change and no new timer** — the point of having a
capability layer. But its default section 43 classification is **`alert_only`**,
not `auto_remediate`, because a package install is a slow, network-dependent,
non-idempotent act and a reconcile pass is neither the place nor the time. An
organization may set `auto_remediate`; on a personal device there is nothing to
remediate. Descriptor:

| Field | Value |
|---|---|
| `capability` | `application.policy` |
| `allowed_desired_states` | `["converged"]` (the state is a set membership, not a scalar; `capabilities.set` on it triggers one bounded convergence pass) |
| `current_state` | observed live: `converged` \| `missing_required` \| `denied_present` \| `unknown_application` |
| `requires_reboot` | `false` |
| `risk` | `medium` |
| `privilege_required` | root (punard executes; the caller need not be root — the `privilege.request` precedent) |
| `audit_category` | `application` |
| `verification` | `observed_set` |

---

## 7. Managed mode

> **Enrollment annotates the same list. It never becomes a different screen.**
> (Design language §8; Plate D-010 Sect IV.)

### 7.1 The three words, and nothing else

The surface's entire managed vocabulary is `required`, `denied`,
`allowUserInstall` — spec 46's own words — and the panel never names the
underlying package system, because spec 46 requires the semantics to survive a
change of it. Rendering:

- **Required** apps carry a `MANAGED · REQUIRED` pill citing the policy id, on
  the existing row. The list does not reorder; annotation is not restructuring.
  `apps.remove` on one is `denied` naming the policy.
- **Denied** apps are not shown as rows at all unless one is installed; a denied
  app that is *not* installed is a fact about the policy, not about the machine,
  and belongs in `punarctl app policy`.
- **`allowUserInstall: false`** turns the browse view's install affordance into
  the section 7.2 card. It does not hide the catalog: a user who cannot install
  something is entitled to know what they cannot install and why (spec 73).

### 7.2 The refusal

Section 73 asks six questions. The card answers them in order, and this copy is
binding on both `punarctl` and the shell — same capability layer, same voice:

```text
APPLICATIONS · DENIED                                          ACME · ATLAS
──────────────────────────────────────────────────────────────────────────

unsafe-package cannot be installed on this device.

Acme's application policy denies it after an upstream supply-chain
advisory. Your own installs stay allowed — this is the only application
on the denied list.

  Policy        Acme Engineering Baseline · eng-baseline-v12
                applications.denied
  Can you       No. This entry is org-pinned; user override is not
  change it     permitted.
  Approval      An exception must be approved by Acme, not on this device.

                      [V] VIEW POLICY      ┆ [R] REQUEST EXCEPTION ┆
```

The exception affordance is **dashed** (design language §7): the local record
exists, the channel to the organization does not (section 4.4). Its own copy
says *"Recorded on this device. No channel carries this to Acme yet."*

### 7.3 Enrollment and what you already installed

Plate D-010's personal card promises *"Enrolling later never uninstalls what you
chose."* That promise holds for `required` and `allowUserInstall`: enrollment
never removes an app merely because the org did not list it. `denied` is the one
case where it cannot hold silently, and leaving a denied app installed while
displaying an org compliance pill would be false protection.

**Resolution: the delta is shown before enrollment completes, not after.**
Enrollment is a user act (M5); the consent moment is the right place for the
consequence:

```text
ENROLL · ACME                                                 STEP 4 OF 5
──────────────────────────────────────────────────────────────────────────

Enrolling will remove 1 application:

  unsafe-package        Acme Engineering Baseline · applications.denied

Your other 4 applications are unaffected. Acme requires 2 applications
you do not have; they will be installed:

  1password             tailscale

                                          [↵] CONTINUE      [ESC] CANCEL
```

Denials added *after* enrollment produce a notification plus a reconcile-
classified drift at `alert_only` by default, naming the policy and the deadline
the org set. An organization may set `auto_remediate`; a silent midnight
uninstall is then the org's stated choice, and the audit event names it.

---

## 8. Honest limits

### 8.1 Catalog size versus curation quality

The arithmetic, because the tradeoff is arithmetic:

> Each `curated` entry costs roughly 15 minutes per catalog release — re-pin the
> commit, re-read the permission set, re-check the summary, run the diff. At six
> releases a year: **40 entries ≈ 60 h/yr. 160 entries ≈ 240 h/yr. 400 entries ≈
> 600 h/yr.** For a team this size, 600 hours a year of catalog re-review is not
> a plan; it is how a catalog quietly stops being reviewed while continuing to
> say it was.

Two mechanisms rather than a resolution:

1. **A catalog entry is added only when someone owns re-reviewing it every
   release.** `review.reviewedBy` is that owner, in the file.
2. **Staleness is mechanical, not aspirational.** An entry whose
   `review.reviewedForCatalogVersion` is more than one release behind renders
   `REVIEW STALE` and **is automatically demoted to `community`** by the catalog
   build — Punar keeps vouching for the pin and stops vouching for the review.
   Nobody has to remember to be honest.

Target: **~40 entries at first release, a soft ceiling of 160.** The
`community` tier is the escape valve that lets the catalog be useful past the
point where it can be reviewed, without lying about which part is which.

### 8.2 An app that leaves the source

- **A `snapshot`/`image` package disappears from a future Arch snapshot:** the
  *image build fails*. Loud, at build time, in front of a maintainer. This is
  the best failure mode in the document and it is free.
- **A Flatpak ref or commit is delisted or garbage-collected upstream:**
  installed copies keep working — they are local ostree deployments, not
  references. New installs fail, at the user, with the remote's error rendered
  in §73 voice.
- **And here is the limit we cannot engineer away:** **catalog CI has no network
  (a hard constraint of this project), so it cannot verify that any Flathub ref
  or commit still exists.** Everything CI can check offline is checked (section
  3.6); ref liveness is not among them. Detecting a delisting requires a
  networked job outside CI, which **does not exist**. Until it does, a delisted
  app surfaces as an install failure for a user rather than a review failure for
  us. Stated here rather than discovered later.

### 8.3 Permission drift, pin staleness, and the two update cadences

- A `pinned` app receives no security update until the catalog is republished,
  and in MVP the catalog is republished only inside a new image (section 3.4).
  The signed catalog-only artifact that would fix it is DESIGN-ONLY.
- Section 1.6's recompute-and-refuse turns permission drift into a visible
  refusal instead of a silent lie, but it turns it into a *refusal*: a user
  whose app legitimately added a permission is blocked until the catalog
  catches up. That is the right side to fail on and it is still a cost.
- `upstream`-mode entries are current and **not reproducible**. Both properties
  are printed. There is no mode that is both.

### 8.4 What this catalog does not claim

Explicit coverage, in the house vocabulary (design language §7 — *silence is not
support*):

| Claim | Coverage |
|---|---|
| A curated app's provenance is pinned and verified | `FULL` (once implemented) — commit pin + remote GPG key shipped in the signed image |
| A curated app has been reviewed by Punar | `PARTIAL` — review means summary, permission set, and pin. It is **not** a source audit, not a supply-chain audit, and not a claim about the app's own dependencies |
| A sandboxed app cannot reach your files | `PARTIAL` — true for `sandboxed`, false by construction for `sandbox-bypassed`, and the surface says which |
| Denied apps cannot be installed on a managed device | `PARTIAL` — `punard` refuses, and for web apps M11's root-owned Chromium policy binds. A user with a shell can still install a Flatpak by hand; `doctor` reports it. Punar reports rather than claims |
| Installed apps stay at a known version | `FULL` for `pinned`, `UNSUPPORTED` for `upstream` — and the entry says which |
| Catalog refs are known to still exist upstream | `UNSUPPORTED` — section 8.2. No offline check can establish it |
| An org can approve an install exception | `UNSUPPORTED` — section 4.4. The control plane is a mock; the affordance is dashed |
| The catalog can be updated without an OS update | `UNSUPPORTED` — DESIGN-ONLY, section 3.4 |

### 8.5 Deferred, tracked, not claimed

`flatpak override` as a typed capability (post-install permission editing);
per-app network policy joined to spec 36 project networking (M12 owns the
plumbing); an org-hosted private catalog overlay; delta updates; a catalog
signing key separate from the image key; ARM64 refs; app-level resource limits
on constrained profiles.

---

## 9. Proving it offline

The CI VM has no network, and every check below runs there:

- **Catalog CI (host, offline):** schema validation; `runtimes[] <= 3` and
  membership; category membership; id uniqueness; `persistence` matches
  `source.kind`; every `image` entry maps to a package in the image manifest and
  every image package maps to an entry; `containment` recomputed from each
  entry's recorded permission set matches the recorded `containment`.
- **In-VM (offline):** `punarctl app list` renders the image set from `pacman -Q`
  joined to the catalog; `punarctl app show firefox` renders a full card with
  **no network access** (metadata comes from the catalog record; the assertion is
  that no socket is opened); `punarctl app install firefox` fails with the
  remote-unreachable message and the right exit code; `punarctl app install
  <snapshot-kind>` produces section 4.5's second message; `punarctl app doctor`
  detects a hand-installed package; `apps.install` from an agent-attributed peer
  produces `approval_required` and exit code 4, and nothing is installed;
  `punarctl debug rpc apps.install_all` returns `unknown_method`.
- **The one real install, offline:** a **fixture Flatpak repo built at image
  build time**, exactly as M6 builds its OCI archive — a hand-assembled, ~3 MB
  runtime and one trivial app, deterministic, exported to
  `/usr/share/punar/flatpak/punar-fixture/`, added as a `file://` remote. This
  proves the whole mechanism end to end — resolve, policy, permission confirm,
  fixed argv, install, verify, audit, remove — **without ever contacting
  Flathub, at build time or at test time.** The first contact with a real remote
  is a user's own install on their own networked machine, and that fact is worth
  stating in the release notes.

---

*Punar · Field Note design language · `docs/design/app-catalog.md`*
