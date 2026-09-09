# Mail, calendar and contacts — design plan

> **Status (2026-09-09): DESIGN ONLY. Nothing here is built.** No first-party
> mail client exists, no milestone funds one, and the sections describing one
> are drawn dashed in the honesty grammar's sense: they are a claim about
> intent, not about the machine. What IS actionable today is section 2 (the
> security finding) and section 6 (the configuration-only remediation).

Origin: a person installed the Evolution Flatpak from the catalogue and its
first run presented a *"Do you want to make Evolution your default email
client?"* modal stacked on top of a seven-page account assistant, in stock
Adwaita styling, on a desktop whose entire design language is the opposite of
that. The complaint was correct and it is two complaints: the onboarding is
noise, and the application does not belong to this operating system.

This document separates what can be fixed by configuration this week from what
requires Punar to own the client, and records the measurements that decide it.

---

## 1 · What the reference gets right

The stated reference is Notion Mail, which is being shut down. What is worth
taking from it is structural and unprotectable; what is not worth taking is its
trade dress. **Never copy** its name, wordmark, logo, icon set (the compose
pencil included — icons are trade dress, information architecture is not), its
copy, or its specific colour and spacing signature.

The five ideas, abstracted:

| # | Idea | Why it matters |
|---|------|----------------|
| 1 | Saved views outrank folders | A folder is the server's idea of your mail; a view is yours |
| 2 | One list grouped by time, not a three-pane grid | Reading mail is a sequence, not a spreadsheet |
| 3 | Labels are readable chips on the row | A colour bar encodes; a word says |
| 4 | Almost no chrome; actions live where they apply | A global toolbar prices every action the same |
| 5 | Counts are present but quiet | A count is a fact, not an alarm |

Ideas 1–5 survive translation into Punar's grammar. Their *rendering* does not,
and section 5 records every conflict.

---

## 2 · The security finding, which comes first

**The Flathub Evolution build disables WebKit's sandbox for the process that
renders untrusted remote HTML email.**

The Flathub manifest replaces `/app/bin/evolution` with a wrapper script whose
body includes:

```sh
export WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1
```

Message bodies in Evolution are rendered by WebKitGTK, not by GTK widgets. The
environment variable is baked into the built ref: **no `flatpak override`, no
GSettings key and no Punar policy can undo it.** The only levers are to rebuild
the ref, or not to ship it.

This collides directly with a stated non-negotiable of this distribution. It
does not make Evolution unusable, and it is not a reason for panic — the
Flatpak sandbox still confines the process, and this is upstream's long-standing
packaging decision, not a compromise. But Punar's catalogue promises that the
card tells you what an application can reach, and "the HTML renderer's own
sandbox is off" is exactly the class of fact that promise exists to carry.

Three options, and the choice is a product decision rather than an engineering
one:

- **Disclose and keep.** Add a `disclosures` entry to the catalogue row saying
  the renderer's inner sandbox is disabled by the publisher's build. Cheapest,
  honest, and consistent with how the catalogue already handles host access.
- **Withdraw** the row until a first-party client exists. Safest, and leaves the
  device with no mail client at all, which is its own kind of failure.
- **Rebuild** the ref as a Punar-owned Flatpak without the wrapper. Weeks, and
  it forks a large upstream package whose maintenance Punar then owns.

A second, smaller fact belongs on the same card and is currently absent:
Evolution's `finish-args` carry `--talk-name=org.freedesktop.secrets`, so mail
account passwords land in the **host** gnome-keyring — the shared pot that
`security.credential_isolation` already reports as `shared`. Do **not** write
that Evolution "shares no data with the host": it is false.

---

## 3 · The engine question, measured

The client is the expensive half; the protocols are not, and Punar should not
write an IMAP stack it does not have to. Two numbers decide this.

**Stock `evolution-data-server` is not shippable.** Measured against the pinned
Arch snapshot 2026/08/20 with the image's own package set, adding the
distribution package costs **+267.5 MiB and 29 packages** — the bulk of it
`webkit2gtk-4.1`, pulled in for EDS's *interactive OAuth2 consent window*, not
for any protocol code.

**A GTK-less EDS costs one package.** EDS's OAuth2 support is split: the
protocol services for Google, Outlook and Yahoo live in `libedataserver` and
need no GTK; only the consent *prompter*
(`libedataserverui/e-credentials-prompter-impl-oauth2.c`) is GTK3 + WebKitGTK.
The full runtime dependency set of an EDS built with the GTK, GTK4, GOA,
weather, canberra and phonenumber options off — glib2, libsoup3, libsecret,
libxml2, sqlite, nss, nspr, icu, json-glib, krb5, libldap, dconf — adds
**exactly one new package to the Punar image closure: `libical`, 6.5 MiB.**
Everything else is already there. No GTK, no WebKit, no GNOME runtime.

That reframes the decision entirely, and it splits in two:

- **Calendar and contacts: use EDS, over D-Bus only.** CalDAV and CardDAV are
  well served, the daemon is designed to be spoken to over the bus, and a
  separate process that never compiles against `libecal`/`libebook` takes on no
  LGPL linking obligation — only the ordinary obligation of redistributing EDS
  itself under its own terms (EDS is LGPL-2.0-or-later per its `COPYING` and
  per-file SPDX headers; Punar is Apache-2.0).
- **Mail: do not use `libcamel`.** Prefer Rust crates in Punar's own process —
  `async-imap`, `mail-send`, `mail-parser`, `mail-builder` — which keeps the
  mail path in one memory-safe process with no GNOME runtime at all.

Rejected on measurement: Akonadi and `kimap` (size), Stalwart (a server, not a
client engine), notmuch (a local indexer, no transport), libetpan
(unmaintained). JMAP is worth having as an additional transport, never as the
foundation.

One correction to a common assumption: **the Evolution Flatpak carries its own
private EDS inside its sandbox.** Installing or not installing EDS on the host
changes nothing about it.

---

## 4 · The window question, which is the real unknown

This is the finding that most changes the cost estimate, and it is easy to miss.

**Punar has never created an application window.** All seventeen shell surfaces
are `PanelWindow`s with a `WlrLayershell` namespace and layer, plus `Lock` as a
`WlSessionLock`. Grepping the repository for `FloatingWindow`,
`ApplicationWindow`, a bare `Window {`, or `xdg_toplevel` returns nothing. A
mail client would be the first Punar surface to need an ordinary xdg-toplevel,
and also the first to need long-form body text, list virtualisation over
untrusted strings, and text-on-fill pairs the theme contrast contract does not
yet measure.

**There is also no component library.** Every visual primitive — `Meta`, `Pill`,
`KvRow`, `RowLine`, `ActionTag`, `DashedPanel`, `StateToggle`, `Entry`, `Glyph`,
`Sect` — is declared *inline* in the surface that uses it; `component Meta: Text
{ … }` appears verbatim in fifteen separate files. Only `Theme`/`ThemeContrast`,
the `Services` singletons with `DeferredSurfaceBase`, and `Shortcuts`'
`BindRow`/`ChordCap` cross a directory boundary.

**And there is no Qt/QML binding in the Rust workspace**, so "a Rust crate that
renders a staged QML tree" is not a thing this repository can do today. The
documented model for new QML surfaces is a `Scope` inside `shell/punar-shell` —
one process, no new binary — which is a poor fit for an application that should
be closable, and a good fit for nothing else that exists.

Answer the window question before designing a single screen. It is the
difference between weeks and months.

---

## 5 · Translating the reference into Punar's grammar

Punar's design language is a technical drawing, not a dashboard: *"Instrument,
not ornament."* Warm paper, near-monochrome ink, tracked uppercase mono labels,
hairline rules, and **colour reserved strictly for meaning** — green/amber/red
map 1:1 to policy decisions and compliance states and nothing else.

That last rule is the one that reshapes the reference hardest.

| # | Reference | Punar |
|---|-----------|-------|
| 1 | Views rail with coloured per-view icons | Keep the rail (D-004 already ships one: 208px, 1px border right rule, tracked-mono section heads). **No icons.** The only mark beside a view name is a status dot, and only where there is status. |
| 1b | — | **A view must print its query.** The masthead reads `MAIL · PAYMENT RECEIPT` left and `FROM:STRIPE · HAS:ATTACHMENT` right. A saved view that will not say what it selects is a folder wearing a costume. |
| 2 | Date-bucket group heads | Tracked mono, uppercase, ink-3, hairline rule under the head only — `YESTERDAY`, `LAST 7 DAYS`. |
| 2b | Reading pane | Refuse both the three-pane grid *and* an in-app reading pane. Opening a thread is a **compositor** act: it opens as a second tiled window, and the window manager already knows how to arrange two things. |
| 3 | Tinted label chips | The existing Tag/pill role, **monochrome**: Geist Mono 500–600, 9–10px, uppercase, +0.12em, 1px border, radius. |
| 4 | Header action row | Delete it. The masthead carries identity left and state right (`76 UNREAD · SYNCED 08:26`) over a 2px ink rule. Actions are keys, printed in the footer meta line. |
| 5 | Counts | Tabular mono, ink-3, no badge, no fill, no colour; **absent when zero** rather than rendered as `0`. |
| — | Unread dot *and* bold sender | Pick one: weight. Unread = Instrument Sans 500 + ink; read = 400 + ink-2. Drop the dot. |
| — | Avatar + name + email + chevron | A masthead meta row: `ALICE@EXAMPLE.COM · IMAP`. No avatar. |
| — | Compose pencil icon | Compose is a printed word and a key, never an icon. |
| — | Sidebar search row | Delete. `/` filters the current view; `PUNAR+Space` searches all mail and returns typed rows. |
| — | Settings / Refer friend / Support | Remove all of it. The rail's foot is empty; settings deep-link to System Control. |
| — | macOS traffic lights | No window furniture. Identity is a hairline and a tracked mono label. |

**Spend no colour on mail state.** Unread, flagged, has-attachment and thread
depth are *facts*, not status: render them in ink weight, a 2px ink rule, a
hairline tag, or a count. Reserve the status palette for policy.

**"Auto label" is the most consequential conflict** and the one a reviewer will
catch first. An automatic classifier reads every message. On a distribution
whose non-negotiables are security and privacy, that feature cannot be a
toolbar button whose model, locality and data flow are unstated. Either it runs
strictly on-device and the surface says so where it acts, or it does not ship.

### Keyboard grammar

Every first-party workflow MUST be fully operable without a mouse (spec §12).
The in-app layer uses **bare keys**, because every OS chord already carries the
Punar key: `J`/`K` to move, `Enter` to open, `C` compose, `R` reply, `E`
archive, `/` filter, `L` label, `V` view switcher, `Esc` out. The label chooser
and view switcher are submaps and therefore print the instrument chip in the
bar's centre zone, which is what that zone is reserved for.

A global `PUNAR + M` ("Open mail") is the right chord and **cannot be added
yet**: there is no mail client on the image and no launch command for it. It
lands with the client, not before.

---

## 6 · What ships this week, without a client

Only one lever reaches the running Evolution, and it was verified byte-for-byte
against upstream rather than guessed.

Write, per user, **before that user's first Evolution launch**:

`~/.var/app/org.gnome.Evolution/config/glib-2.0/settings/keyfile`

```ini
[org/gnome/evolution/mail]
prompt-check-if-default-mailer=false
layout=1
thread-flat=true
headers-collapsed=true
use-custom-font=true
variable-width-font='Instrument Sans 11'
monospace-font='Geist Mono 10'
buttons-hide=['calendar','tasks','memos']
prefer-symbolic-icons='yes'
```

Why this file and not the obvious alternatives:

- A **host dconf seed** under `/etc/dconf/db/*.d/` does nothing. Evolution is a
  Flatpak with no `ca.desrt.dconf` access, so GLib gives its keyfile backend
  priority 110 over dconf's 100 and the app never reads host dconf.
- **Granting `--talk-name=ca.desrt.dconf` makes it worse, not better.** It does
  let dconf outrank the keyfile backend — and the in-sandbox dconf engine then
  has no system database to read, while the change simultaneously disables the
  keyfile backend that flatpak was already feeding with real host defaults.
  Do not ship it.
- The only mechanism that works with the sandbox intact is the app's own
  keyfile, written first. Flatpak's own migration writes that path **only if it
  does not already exist**, so whoever writes first wins: seed once at account
  creation and never rewrite.

Two things to design around, stated because they are limitations rather than
details. These land as **user values, not defaults**, so the person can change
them — which is correct. And this repository has **no GSettings seeding
machinery at all**, so this is new per-user infrastructure, not a line added to
an existing seed. It belongs in `punar-onboardd` at account creation (which
already holds `/home` in `ReadWritePaths`), never in `punard`, whose unit sets
`ProtectHome=yes`.

**Deliberately not set:** `show-startup-wizard=false`. It kills the assistant,
and with it the only path to adding an account — leaving a mail client with no
mail. The stacked-modal complaint is answered by
`prompt-check-if-default-mailer` alone.

### What configuration cannot fix

The seven-page assistant on every subsequent account add. The Adwaita chrome
(GTK theming a Flatpak needs Punar's GTK3 theme shipped as an
`org.gtk.Gtk3theme.<Name>` extension). HTML message bodies, which WebKitGTK
renders outside the GTK theme entirely. And the disabled WebKit sandbox from
section 2. Those need a real client.

---

## 7 · Staging

| Stage | Deliverable | Cost |
|-------|-------------|------|
| 0 | Section 2's disclosure on the catalogue card | hours |
| 1 | Section 6's per-user GSettings seed in `punar-onboardd` | days |
| 2 | Answer the window question (§4) with a spike, not a plan | days |
| 3 | Extract the genuinely duplicated primitives into `shell/punar-shell/Ui/` — `Data` (3 sites, byte-identical) first, `Meta` (18 sites) next. Justified on its own, independent of mail. | days |
| 4 | Plate **D-018** `docs/design/mockups/mail.html`, drawn dashed throughout | days |
| 5 | GTK-less EDS package for calendar/contacts; Rust mail path | weeks |
| 6 | The client | months |

Stages 0–3 are worth doing whether or not the client is ever built. Stage 2 is
the gate: until an xdg-toplevel exists in this repository, every estimate past
it is a guess.
