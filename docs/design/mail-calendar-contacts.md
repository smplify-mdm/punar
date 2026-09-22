# Mail, calendar, reminders and contacts — product and engineering plan

> **Status (2026-09-22): COMMITTED CORE SUITE; REAL MAIL BACKEND IN PROGRESS.** A real
> xdg-toplevel window prototype exists at `shell/punar-shell/Mail/`: index,
> thread and plain-text compose all map, tile, resize and close as ordinary
> application windows. It still reads fixture data and speaks to no account,
> server or store, so the QML, launcher and hidden prototype entry are staged
> only by the dev/CI image profile and are absent from production images.
> The profile-bound `punar-pimd` crate now provides crash-durable, fixture-free
> local Calendar/Reminders records, revisions and change history plus bounded,
> strictly authorized application-protocol parsing. An unstaged encrypted
> credential-vault library now refuses non-LUKS storage and keeps values out of
> ordinary IPC. A tested unnamed one-use credential-entry channel locks its
> helper down before input exists and transfers a bounded value directly into
> the vault. A protected account-entry session now adds a separate strict
> identity/server packet before the opaque password packet, rejects extensions
> and cancellation, and completes the same verified transaction without
> exposing the password to ordinary application IPC. The helper gets a closed
> result code rather than provider text. A library-only
> coordinator now validates service-private IMAP/SMTP
> configuration, stages separately typed credentials, invokes a closed
> provider-verification interface, publishes the account only after success
> and rolls back checked failures. ADR-011 now supplies a real implicit-TLS or
> STARTTLS IMAP plus authenticated SMTP verifier with platform certificate
> validation, fixed deadlines and a 1 MiB aggregate IMAP response cap. There
> is still no fixed helper executable, sign-in UI, SMTP send path or
> crash-reconciliation proof. A bounded adapter now opens INBOX read-only,
> fetches at most twenty UIDs per transaction through the same TLS/deadline
> boundary, isolates malformed messages and commits records plus cursor
> atomically. A non-resident sync coordinator now acknowledges `sync.trigger`
> before network work, caps concurrent account jobs at two, coalesces repeated
> triggers, catches worker failure, and persists only bounded public
> online/offline/auth-required state. It has not yet passed a live-provider or
> service-runtime test.
> ADR-012 adds a separate
> descriptor-bound, crash-durable Mail record store with an 8 MiB cache,
> atomic batch/cursor commits, restart persistence, duplicate suppression,
> UIDVALIDITY replacement and account removal. The account coordinator now
> removes cached messages, Mail sync cursors, credentials, private server
> configuration and public metadata, with restart coverage. It requires a
> profile-store-bound removal permit which blocks new sync and waits a bounded
> time for existing provider work. The Settings-only `accounts.remove`
> dispatcher path now invokes this lifecycle and refuses retained local data,
> but no installed service/launcher can grant that capability yet.
> Settings-only `accounts.begin_connect` and `accounts.cancel_connect` now
> create and cancel bounded five-minute open-protocol setup sessions. They
> expose only an opaque id, admit no credential field, and keep the one-use
> helper descriptor reserved for the privileged launcher. The service-side
> root-broker exchange now transfers that endpoint exactly once with closed
> refusal codes, but the fixed broker/helper executables remain missing.
> A bounded non-resident service loop now serves application and helper control
> planes concurrently and exits after the final idle interval; it is not yet a
> systemd-activated production process.
> Store-backed `mail.list` and
> `mail.thread` now expose only parsed durable records through signed,
> revision-bound cursors, and the three apps may read non-secret account
> metadata while account lifecycle remains Settings-only. There is still no
> service listener, fixed launcher/bridge, live-provider proof or production
> image entry. A first bounded MIME ingest layer now produces only
> plain-text Mail records, explicitly blocks HTML remote content and discards
> attachment payloads. Calendar and
> Reminders remain unavailable to users. Provider-neutral account metadata and
> service-private server configuration now survive restart and the former
> backs `accounts.list`, but the protected helper is not launchable from a user
> interface yet, so there is still no complete sign-in workflow.
> No part of this status may be shortened to “Mail is built” until the runtime
> gates in section 9 pass.

Origin: a person installed the Evolution Flatpak from the catalogue and its
first run presented a *"Do you want to make Evolution your default email
client?"* modal stacked on top of a seven-page account assistant, in stock
Adwaita styling, on a desktop whose entire design language is the opposite of
that. The complaint was correct and it is two complaints: the onboarding is
noise, and the application does not belong to this operating system.

On 2026-09-22 the product decision changed from “is a first-party client worth
building?” to **“Mail, Calendar and Reminders are default first-party apps.”**
Contacts is shared address-completion data in the first release, not a fourth
headline app. The generic names are deliberate: users should not need to know
which toolkit or protocol implements an operating-system basic.

This document now owns both the already-measured decisions and the staged path
from the honest prototype to real account-backed applications.

---

## 0 · Product contract

### 0.1 What ships

- **Mail** — multiple accounts, inbox and saved views, search, threads,
  attachments, plain-text compose, labels, archive/delete, drafts and send.
- **Calendar** — local and synced calendars, agenda plus adaptive day/week
  grid, invitations, availability, time zones and recurring events.
- **Reminders** — local lists, Today, Upcoming, projects, recurrence, notes,
  completion history and CalDAV `VTODO` where the provider supports it.
- **Contacts data** — address completion and attendee lookup shared by Mail and
  Calendar. A standalone Contacts app is a later decision, not implied by this
  plan.

All three applications are installed by default only after they operate on
real local data. Before that, prototypes remain dev/CI-only,
`NoDisplay=true`, own no MIME type, and never enter a production image or
appear as an installed consumer feature.

### 0.2 What does not ship

- no sample inbox, calendar, people, reminders, accounts, sync success or
  activity on a production image;
- no forced cloud account in OS onboarding — account setup is an optional
  first-desktop action and remains available later in System Control;
- no remote classifier reading every message, no AI training claim, and no
  “smart” feature whose locality and data flow are unstated;
- no embedded provider web view. OAuth uses the user's governed browser with
  PKCE, state/nonce validation and an exact callback;
- no direct network access from QML windows. A bounded per-user service owns
  transport, sync, parsing and durable state.

### 0.3 Architecture boundary

`punar-pimd` is the proposed shared per-user service. It is event-driven and
starts on first use; it does not become another always-resident desktop
process merely because the image contains these apps.

The first implementation slice is intentionally below that service boundary:
[`pim-local-store.md`](../development/pim-local-store.md) documents the local
Calendar/Reminders store and why it is compiled and tested without installing
or activating a daemon. That sequencing prevents a filesystem socket plus
same-UID checks from accidentally becoming the authorization design.

```text
Mail / Calendar / Reminders QML windows
                  │ typed local IPC · no credentials · no arbitrary SQL
                  ▼
        punar-pimd (one per Linux profile/uid)
        ├─ account metadata + sync cursors
        ├─ local mail/calendar/task indexes
        ├─ MIME and iCalendar parsing
        ├─ provider/transport adapters
        └─ notifications + bounded change stream
                  │ opaque credential handles only
                  ▼
        profile-scoped credential storage
```

The first storage implementation relies on full-disk encryption for content at
rest. Its separately reviewed credential path now exists as an unstaged
library: each record is XChaCha20-Poly1305 encrypted with bound context, and
vault open requires kernel-observed LUKS2 backing. The current `punar-secrets`
daemon is a short-lived, non-persistent agent
credential broker; silently turning it into an OAuth vault would invalidate
its “no state directory” security promise. Persistent account credentials are
governed by
[`ADR-008`](../architecture/adr/ADR-008-pim-account-credentials.md): a
service-private per-profile vault owned by the socket-activated PIM service,
never a new state directory for `punar-secrets`. The record-level negative
tests and the helper-to-vault one-use transfer now pass; fixed-launcher/UI
integration, account transactions and hostile runtime proof remain
prerequisites for any provider sign-in.

One Linux profile/uid owns one PIM service and one data root. Personal and work
profiles therefore do not share account metadata, indexes, notifications or
credential handles. A managed policy may allow or require provider types and
configuration, but content and credentials never enter Smplify inventory or
audit. Device-level disk encryption protects the volume beneath every profile;
profile-level keys may narrow it later and never replace that foundation.

### 0.4 Provider model

The data model is provider-neutral. The transport layer is replaceable:

| Capability | Open-standard adapter | Provider adapter |
|---|---|---|
| Mail | IMAP + SMTP; JMAP when advertised | Gmail API / Microsoft Graph where policy or server capability requires it |
| Calendar | CalDAV | Google Calendar API / Microsoft Graph |
| Reminders | local + CalDAV `VTODO` | Google Tasks / Microsoft To Do APIs |
| Contacts | CardDAV | Google People / Microsoft Graph |

Both routes are required for the finished product. ADR-008 selects **open
standards first**: local Calendar and Reminders, then one complete
IMAP/SMTP + CalDAV/CardDAV account vertical slice. Google and Microsoft follow
against the same typed model and remain release gates. This order proves the
provider-neutral, self-hostable path before provider registrations,
tenant-policy handling and production OAuth custody can shape the common
schema.

### 0.5 Security and privacy floor

- message bodies are parsed as untrusted input; malformed MIME/iCalendar data
  must not crash the sync service or UI;
- remote images and other remote body content are blocked by default and the
  message states that fact where it occurred;
- version one composes `text/plain`; HTML mail is displayed only after a
  separately sandboxed, networkless renderer and sanitizer pass adversarial
  fixtures;
- attachments open through the ordinary execution-trust/quarantine path, not
  by MIME-triggered process launch;
- sync uses TLS with certificate validation, bounded responses, backoff and no
  retry loop; offline is a normal state and never destroys cached data;
- apps receive rendered records and opaque ids, never refresh tokens,
  passwords or provider client secrets;
- notification contents are user-controlled per account/view and respect the
  active profile; lock-screen previews default to sender plus subject only
  after the user opts in;
- AI assistance is absent by default. A future local model or explicit remote
  service must declare exactly what leaves the device for each action.

### 0.6 Shared interaction grammar

The suite inherits Field Note rather than Notion's trade dress: warm paper or
panel mood, hairline structure, Instrument Sans content, Geist Mono metadata,
and user identity colour only on user data. The shared rail contains accounts,
views/lists/calendars and sync truth; the main plane contains the work. Counts
are quiet facts. Status colour remains reserved for actual policy/sync state.

Mail keeps the current prototype's decisive choice: opening a thread creates a
second ordinary window and lets the compositor tile it. Calendar changes from
agenda on a narrow tiled window to the largest usable 1/3/5/7-day grid on a
wide window. Reminders uses one dense list with Today/Upcoming/Projects in the
rail; opening details creates a document window rather than squeezing a third
pane into the list.

Cross-app actions are explicit and local: “Make reminder” from a message and
“Insert availability” from compose create a reviewable draft in the target
app. Nothing silently copies message contents or sends invitations.

---

## 1 · What the reference gets right

The stated reference is Notion Mail. [Notion's own help
center](https://www.notion.com/help/notion-mail-inbox-is-going-away-what-to-do-next)
says its inbox shuts down on **2026-09-22**; the Homebrew cask still describes
and distributes the final desktop build. It is therefore an interaction
reference, never a dependency or long-term platform choice. What is worth
taking from it is structural and unprotectable; what is not worth taking is its
trade dress.
**Never copy** its name, wordmark, logo, icon set (the compose pencil included
— icons are trade dress, information architecture is not), its copy, or its
specific colour and spacing signature.

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
  mail path in one memory-safe process with no GNOME runtime at all. The first
  piece now pins `mail-parser` 0.11.9 behind the bounded, plain-text-only
  conversion in ADR-010. ADR-011 selects `async-imap`, `mail-send` and Rustls
  for the open-protocol authentication boundary. ADR-012 selects redb 2.6.3
  for descriptor-bound durable Mail records. A bounded initial/incremental
  INBOX adapter now joins those two boundaries, but live-provider/runtime
  proof, searchable indexing and message building remain open.

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
| 0 | Evolution disclosure and first-run suppression | **complete** |
| 1 | Ordinary xdg-toplevel spike with stable app identity | **complete** |
| 2 | Responsive Mail index, thread and plain-text compose on explicit fixture data | **complete prototype; hidden from shipping launcher** |
| 3 | Open-standards-first sequence + persistent-credential ADR | **decision complete in ADR-008; implementation proof open** |
| 3b | Versioned typed PIM IPC/schema, ownership/pagination/change cursors/offline/conflict negative fixtures | **contract, deadline-bound authorized channel runner, durable signed cursors, bounded stable-page cache, read-only Mail dispatch and async sync admission complete; remaining dispatcher methods open** |
| 4 | `punar-pimd` local-only store with empty account state, local Calendar and Reminders, restart/offline/migration tests | **durable library core complete; process/runtime proof open** |
| 5 | First real account vertical slice: connect, initial sync, incremental sync, send/create/update/complete, disconnect and delete-local-data | weeks |
| 6 | Replace every fixture binding in Mail; build Calendar and Reminders inside the adopted app grammar | weeks |
| 7 | Second provider family plus managed configuration, profile-isolation and recovery tests | weeks |
| 8 | Dual-architecture image, resource, malformed-input, OAuth, offline and real-provider acceptance | weeks |

The old window-cost uncertainty is closed. The gating unknowns are now
persistent credential custody, provider registration, protocol correctness and
hostile-content handling — all security boundaries, none safely replaceable by
more fixture UI.

---

## 8 · Application-specific first views

### Mail

The current rail + time-grouped list remains the base. With no account, the
main plane contains one honest empty state: `NO MAIL ACCOUNTS` plus a working
`CONNECT ACCOUNT` action. With an account but no cached messages it says
whether sync has not started, is offline, failed with a named next step, or
completed with an empty inbox. Those states never collapse to the same blank.

### Calendar

The default is Agenda in a narrow/tiled window and the derived 1/3/5/7-day grid
when space permits. The rail groups calendars by account, then local calendars.
The first action is `NEW EVENT`; selecting a time range opens an event document
window. Month remains out of version one until it can represent partial sync
honestly.

### Reminders

The first view is Today, not an analytics dashboard. A single-line quick
capture sits at the list boundary; parsing dates happens locally and previews
the interpretation before save. Each row has a real checkbox, title, due/repeat
metadata and list name. Overdue is a word and ordering state, not red decoration.
Completed items move to a quiet, collapsed history and remain searchable.

---

## 9 · Definition of done

The suite is not a product claim until all of these pass on both x86_64 and
ARM64 images:

1. Production image boots with no accounts and shows no synthetic person,
   message, event, reminder, count, sync timestamp or success state.
2. Connect, cancel, OAuth denial, revoked token, MFA/tenant refusal and network
   loss each produce a distinct recoverable state with no secret in logs.
3. Initial and incremental sync survive restart, duplicate delivery, clock
   change, pagination, malformed content and server conflict without data loss.
4. Mail can receive, search, open, reply, draft, send, archive and delete;
   Calendar can create/edit/delete/respond and handle recurrence/time zones;
   Reminders can create/edit/complete/recur and sync where supported.
5. Remote body content is blocked by default; the renderer has no network;
   attachments traverse quarantine/execution trust; adversarial fixtures pass.
6. Personal and work profiles cannot see each other's accounts, data,
   notifications, OAuth callbacks or search results. Managed inventory contains
   configuration/compliance only, never content or credentials.
7. Every action is keyboard-operable, screen-reader named, contrast-gated,
   localizable and usable in the compositor's side-by-side minimum sizes.
8. UI windows have no direct network authority. Typed IPC is bounded, peer
   checked, versioned, negative-tested and carries no credential values.
9. Idle RAM/CPU/write budgets are measured with the service stopped and with a
   representative synced account; sync work is bounded and backoff is proven.
10. Account removal revokes authorization when possible, stops sync, removes
    local credentials and offers an explicit, separately confirmed local-data
    deletion path.
