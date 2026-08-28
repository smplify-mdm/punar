# Punar Onboarding and the Local Account Model — technical notes

> **Flow superseded on 2026-08-26.** The binding product and interaction
> contract is now [`onboarding-flow.md`](onboarding-flow.md): one account card,
> three user-provided values, then a compact recovery receipt. The longer
> seven-stage flow and any remaining full-name/theme/privacy/enrollment prompts
> below are retained only as technical research for the identity backend; they
> must not be implemented as first-run UI.

**Status:** Design (proposed) · 2026-08-26 · **Owners:** `punard` (the account
record, the typed methods), `punar-shell` (the OOBE surface), the installer
(the seam in §4)
**Spec authority:** §65 (first-boot UX), §66 (installation), §49 (enrollment
chain), §47 (identity graph), §48 (just-in-time privilege), §44.2 (LUKS2,
recovery flow, no recovery material in logs), §39 (state sources and
precedence), §41 (capability registry), §12 (keyboard-first), §60 (hard
safety constraints), §61 (local IPC security), §53 (audit), §54 (telemetry),
§73 (every restriction explains itself), §1.22 (honesty), §5.1/§5.3 (target
hardware), §6.2/§6.3 (budgets).
**Binding prior contracts:**
[`ADR-003`](../architecture/adr/ADR-003-ab-slots-over-snapper.md) (A/B root
slots; `/var` and `/home` shared and never rolled back),
[`update-and-rollback.md`](../development/update-and-rollback.md) §3.6 (the
`/etc` rule, the identity-on-`/var` rule, the N-1 state rule),
[`milestone-9.md`](../development/milestone-9.md) §4.4/§5.1/§7 (the approval
engine, human-only resolution, self-resolution, the JIT grant),
[`milestone-13.md`](../development/milestone-13.md) §5 (the OOBE layer, the
marker, `system.keymap`, and the deferrals this document now un-defers),
[`theme-system.md`](theme-system.md) §5/§6.1/§7.3 (the shipped set and why
theme is *not* a capability), [`wallpapers.md`](wallpapers.md) (the desktop
field is deliberately kept out of onboarding),
[`execution-trust.md`](execution-trust.md) (the `/home`-and-`/var` split it
depends on), [`DESIGN_LANGUAGE.md`](DESIGN_LANGUAGE.md) §7 (stroke and
coverage), §8 (unmanaged-first),
[`mockups/first-boot.html`](mockups/first-boot.html) (**Plate D-008 — the
acceptance reference**), [`mockups/boot-greeter.html`](mockups/boot-greeter.html)
(Plate D-002), [`mockups/identity-elevation.html`](mockups/identity-elevation.html)
(Plate D-012).
**Written alongside, not duplicated:** `installer.md` (disk, LUKS, A/B
layout, ESP — the seam is §4.3) and `platform-sso.md` (directory identity —
the seam is §6.5).

> **A machine that autologins a user called `punar` with the password `punar`
> has no account model; it has a placeholder. The question this document
> answers is not "how do we create a user" — `useradd` answers that — but
> *what a person is on a Punar device*: a username that appears on the lock
> screen, a credential that is not ambient authority, a record that survives
> an A/B swap because it was never on the root slot, and a shape that a
> directory identity can later attach to without a rewrite.**

Per DESIGN_LANGUAGE §7 the stroke rule applies to prose: a **solid** claim is
an operating path today, a *dashed* claim is designed and unshipped, and
`NEVER` is a refusal rather than a roadmap item.

---

## 0. Claim register (spec §1.22 · design language §7)

**Almost nothing in this document is implemented.** This register exists so
that no sentence below can be read as a description of the running system.

| # | Mechanism | Stroke | Where it stands (2026-08-26) |
|---|---|---|---|
| 01 | The M9 approval engine, JIT grants, self-resolution, real expiry | **solid** | Shipped. `m9-check.sh` step 11 already drives the exact loop this document makes the default: a **non-root** user requests, resolves their own request, mutates a capability, and loses the grant on expiry. |
| 02 | Filesystem admission on `/run/punard` — `0660 root:punar` | **solid** | Shipped (M3). Group `punar` is already the "may ask" gate; this document names it as such rather than inventing a second one. |
| 03 | `system.hostname` as a typed capability with RFC-1123 validation | **solid** | Shipped (M3), including the validation bypass an adversarial audit found and closed. Onboarding writes the hostname through it and adds nothing. |
| 04 | `time.timezone` capability | **solid** | Shipped (M3). |
| 05 | `system.keymap` capability | *dashed* | Proposed by M13 §5.3, unbuilt. Onboarding stage 01 depends on it and does not re-argue it. |
| 06 | The OOBE surface as a layer inside `punar-shell`, gated on a marker | *dashed* | M13 §5.2's decision, unbuilt. This document extends it with the account stage M13 deferred and changes nothing else about it. |
| 07 | `identity.local-account` capability + the `identity.*` typed methods (§1.12) | *dashed* | **New here.** No code, no IPC section allocated. |
| 08 | Accounts materialised from `/var` through `systemd-userdbd` / `nss-systemd` | *dashed*, **and unverified** | §1.11. The whole account-survives-an-update property rests on it. Spike **V1** in §9 can invalidate it; the fallback is designed in the same section. |
| 09 | The D-002 QML greeter | *dashed* | Never implemented; `greetd` autologins. §5 changes M13's deferral verdict and says exactly why the premise moved. |
| 10 | Disk encryption, the LUKS passphrase, the disk recovery key | *dashed*, **and installer-owned** | §44.2 design exists; no installer exists. This document places one requirement on it (§4.4) and otherwise stays out. |
| 11 | TPM-assisted unlock removing the second password prompt | **blocked** | `user-blocked.md` item 2 — needs physical hardware. §4.5 states the two-prompt reality instead of designing around it. |
| 12 | A verified human identity at enrollment | **blocked** | `user-blocked.md` item 5. M5 enrolls a *device*. Stage 06 says so on the stage (§2.6), and §6 makes sure the local record can accept one later. |
| 13 | Protection against a local attacker who has the user's password and the machine | `NEVER` | §8. JIT privilege narrows ambient authority; it does not defeat someone who is already you. |
| 14 | The `self_service` capability flag and the fourth line in M9's human path (§1.6.1) | *dashed* | **New here, and it changes a shipped code path.** M9 §5.1's human path is three lines today and this proposes a fourth. Not accepted by `ipc.md` or `milestone-9.md`; §9 records it as open. |
| 15 | A recovery path when `punard` itself will not start | *dashed*, **and it does not exist** | §1.6.2. Layer 2 (`punar-recover`) is unbuilt, and on a fresh install slot B is empty, so A/B rollback has no target either. §8 limit 10. |

---

## 1. The account model

### 1.1 What the person provides

Three values, one screen, in this order:

```text
Username          alice                 ← permanent; /home/alice
Password          ••••••••••••          ← confirm below; reveal is explicit
Confirm password  ••••••••••••          ← verification, not a fourth value
Device name       Alice's ThinkPad
                  Network name: alices-thinkpad
```

That is the whole account stage. No email. No security questions. No "hint".
No full-name prompt. No account type radio — because §1.6 removes the
question. Password confirmation verifies the password and is never stored as
a separate value.

Each value has a job, and the job decides the rules:

| Value | Its job | Mutable later? |
|---|---|---|
| **Username** | The POSIX identity: `uid` owner, home directory, socket admission, group membership, container subuid ranges | **No** — see §1.3 |
| **Password** | The authenticator, and the thing standing between a stranger at your desk and a JIT grant | **Yes**, and no rotation is ever forced |
| **Device name** | What the greeter masthead says and what the network hears | **Yes** — both halves |

### 1.2 Why there is no full-name prompt

The first useful identity on a developer machine is the username: it names the
home directory, terminal prompt, file ownership, audit actor, lock card, and
local socket admission. Asking for a second personal name before the desktop
is useful creates work without creating access.

The account record therefore starts with `realName: null`; every surface falls
back to the username and derives a one-letter monogram. A human-readable
display name remains editable later in System Control and a directory identity
may provide one after enrollment. Neither possibility adds a first-run field.

### 1.3 Username — rules and the fact that it is permanent

**The rule, exactly:**

```text
^[a-z][a-z0-9_-]{0,31}$      and must not end in '-'
```

Lowercase-first (not `[a-z_]`) because a leading underscore is the
conventional marker for system accounts on the platforms Punar's users came
from, and a person should not be able to make an account that reads as one.
32 characters is the `utmp` ceiling; Punar does not offer 33.

**Refused in addition to the pattern:**

| Refused | Reason |
|---|---|
| Any name already in the passwd database | Collision. Named in the message: *"`alice` is taken by an account on this device."* |
| `root`, `nobody`, `greeter`, `punard`, `punar` | Real collisions with the shipped system, and `punar` additionally is the dev-image name this document exists to delete |
| Anything matching `punar-*` | Reserved namespace for Punar service accounts, stated on the screen rather than discovered later |
| Anything that would land below uid 1000 | Not reachable through this path anyway; asserted because a validator that only checks strings is not a validator |

Punar does not generate the username from another field and never appends a
digit to resolve a collision. The person enters the identifier they want; a
collision is named and the field waits. The focused field explains its purpose
in one line: *“Your home folder and terminal name.”*

**And it is permanent.** Renaming a POSIX user after the home directory,
file ownership, subuid ranges, container storage, systemd user units and
`/run/user/<uid>` exist is not a rename, it is a migration. Punar does not
offer one and does not pretend to. The screen says so at the moment of
choosing, in the §73 voice:

```text
Username    alice
            This one is permanent — it names your home folder and
            everything in it. Your display name and device name can
            change later.
```

An OS that tells you which of three values is irreversible, *before* you
commit it, is doing the one thing that distinguishes a designed form from a
generated one.

### 1.4 Password — a real policy, and a refusal rather than a warning

**The policy, in full:**

| Rule | Value | Why |
|---|---|---|
| Minimum length | **10 characters** | Length is the only factor that reliably buys strength. NIST SP 800-63B sets 8 as the floor for a general secret; this account can request privilege, so Punar asks for two more |
| Maximum length | 256 bytes accepted, none of it truncated | yescrypt does not care; bounding the input is an input-validation courtesy, not a security control |
| Composition rules | **None** | No "must contain a symbol". Composition rules produce `Passw0rd!` and a sticky note |
| Forced rotation | **Never** | Rotation without evidence of compromise is a mechanism for producing predictable increments |
| Blocklist | **Yes, offline** | The top ~10 000 breached and common passwords, shipped as a file (§1.4.2) |
| Context check | **Yes** | The username, device name, and `punar` — case-insensitive, as substrings |
| Character set | Every printable Unicode character including spaces | A passphrase must be typable as a sentence |
| Hash | **yescrypt** (libxcrypt default on the pinned substrate) | Not chosen, inherited — and stated so nobody has to read the source to find out |

**What happens to a weak one: it is refused.** Not warned, not accepted with
a shrug.

The three-way choice is real and the answer is not obvious, so here is the
argument rather than the verdict alone:

- **Accept with a warning** is what most systems do, and it is the option
  that is dishonest by construction. A warning the OS will step past is a
  warning the OS did not mean, and Punar's whole posture (§1.22) is that we
  do not stage decisions we have already made.
- **Accept with a stated consequence** — "this password is weak, so JIT
  elevation is disabled on this account" — is coherent and was seriously
  considered. It is rejected because it produces a device that is subtly
  crippled in a way the user will meet weeks later, at the worst moment, and
  because the consequence is unenforceable in the direction that matters: a
  weak password does not stop *the person at the keyboard*, which is exactly
  who the threat is.
- **Refuse** is what ships. This account is the elevation seed (§1.7) and the
  only local authority on the device. A four-character password does not make
  JIT privilege weaker in some measurable percentage; it makes the entire
  §48 story theatre, because the reason-plus-approval ceremony is worthless
  when the approval can be produced by anyone who guesses `1234`.

The refusal is written in the §73 voice — what happened, why, and the next
step — and the next step is a real one:

```text
That password is too short.

Punar asks for 10 characters and nothing else — no symbols, no
digits, no capitals. Three ordinary words beat eight clever
characters, and you can type them.

Policy: Punar local account floor (this device; no organization
        is involved)
```

Two more decisions inside this one:

- **The strength meter is refused.** A coloured bar that says "Strong" is a
  promise no local estimator can keep, and the DESIGN_LANGUAGE §2 rule is
  that colour is spent on status, not on encouragement. What the screen shows
  instead is one line stating the floor and whether it is met.
- **zxcvbn-class entropy estimation is refused**, with a reason: it is a
  dependency and a heuristic, it produces a number users read as a
  guarantee, and its dictionary is a network-era artefact we would then have
  to ship, version and update on a device that must work offline. Length +
  blocklist + context is cheaper, explicable in one sentence, and honest
  about being a floor rather than a score.
- **Empty is refused absolutely**, and "no password on this machine" is not
  offered as an option, because the account can request privilege.

**Entry mechanics.** Typed twice, or typed once with the reveal control
focused — the reveal is a normal Tab-reachable control, not a hidden chord,
and revealing removes the confirm field rather than adding to it. Mismatch is
the only per-field error the flow can produce that is not about the value
itself, and it clears both fields rather than one.

#### 1.4.1 Where the hash goes, and where it never goes

`yescrypt` hash → `/var/lib/punar/identity/shadow` (or the `privileged`
section of the user record, §1.11), `0600 root:root`, on the shared
partition.

It **never** appears in: the account record's public section, the desired-state
document, `punarctl policy explain` output, any audit event, any `punarctl`
output in any mode including `--json`, the greeter projection (§5.2), the
journal, or a check artifact. §44.2's *"no recovery material in logs"* is
generalised here to *no authenticator material leaves the store, ever*, and
§7's assertion set proves the negative by grepping the artifacts for `$y$`.

This is also why the password is **not** part of the account capability's
desired state — see §1.12.

#### 1.4.2 The blocklist is a file, because the CI VM has no network

`/usr/share/punar/identity/common-passwords.txt` — newline-separated,
lowercased, deduplicated, sorted, shipped in the image. ~10 000 entries at
~9 bytes each is under 100 KB uncompressed, which is inside every budget in
§6 and needs no daemon, no service and no lookup process: the check is a
binary search over a sorted file, performed once, by the process that already
has the password in memory.

Refreshing it is an image-build input, not a runtime update. A device that
cannot reach the network still enforces the floor, which is the entire point.

### 1.5 Device name → hostname, through the capability that already exists

The person types a device name in natural language. Punar derives the
hostname and **shows it on the same screen as a consequence line**, never as
a surprise discovered later by someone reading a router's client list:

```text
This device      Alice's ThinkPad
                 on the network: alices-thinkpad
```

Derivation: NFKD → ASCII → lowercase → every run of disallowed characters to
a single `-` → trim leading/trailing `-` → truncate to 63. The result is
then validated against the *existing* backend rule verbatim —
`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`, `crates/punard/src/backends/hostname.rs`
— and if it fails or empties, the hostname field becomes directly editable
and the natural-language field is kept as the display name.

**The write is the existing typed capability and nothing else:**

```text
punarctl capabilities set system.hostname alices-thinkpad
```

Which means onboarding inherits, for free: validation (twice — the server
validates and the backend re-validates as defence in depth), the atomic
`/etc/hostname` write plus the kernel write, `verify` re-reading both, the
audit event, drift detection, `policy explain`, and — the one that matters
for ADR-003 — **the desired value living in punard's effective document on
`/var`, re-applied at every boot reconcile.** A slot swap resets `/etc` to
vendor content and the hostname comes back because it was never `/etc`'s to
own. That is update-and-rollback §3.6's rule paying its rent on the first
screen a user ever sees.

**The display name (`"Alice's ThinkPad"`) is stored on `/var`, not in
`/etc/machine-info`,** in `/var/lib/punar/identity/device.json`. This is a
deliberate scope refusal: the moment Punar writes `/etc/machine-info` it owes
that file a capability (update-and-rollback §3.6's `/etc` rule), and the only
consumers today are Punar's own surfaces, which can read `/var` through the
FileView mechanism they already use. A `system.device-name` capability is
*dashed* in §9 with the shape it must take, and ships when something outside
Punar needs to read the pretty name.

### 1.6 Privilege — the decision, argued

**Decision: the first account is a standard user who elevates just in time.
There is no permanent local administrator on a Punar device, and `wheel` is
not used.**

The lazy version of this decision reads as security theatre — the same person
approves their own request seconds later, so what was gained? The honest
version is narrower and worth stating precisely, because overclaiming here
would be exactly the §1.22 failure the rest of the repo has avoided.

**What the JIT posture actually buys:**

1. **Privilege stops being ambient.** On an Ubuntu/macOS-shaped device, the
   first account is in `sudo`/`admin` for the life of the machine; any
   process running as that user is one password prompt — often one cached
   timestamp — from root. On Punar, the same process finds `capabilities.set`
   returning exit 3 with a §73 message, because M9's human path is
   `uid == 0` → allow, live grant → allow, **otherwise deny**. A stolen shell
   is not a root shell. That is a real difference in the default state of the
   machine, not a difference in how hard it is for the owner to do things.
2. **Every privileged change has a named human, a written reason, and a
   clock.** §47 asks that every privileged event be attributable through the
   identity graph and §53 asks for an audit record worth having. A grant
   carries `grant_id`, the capability, the reason, the requester, the
   resolver's uid/pid/cgroup, and an `expires_at` — and the audit event for
   the mutation carries `details.grant_id`, so the record answers *why* and
   not only *what*. `sudo` produces a line saying a command ran.
3. **A grant is one capability, never a shell.** §60 forbids a generic root
   RPC for agents; the JIT posture extends the same discipline to humans.
   There is no `--all`, no wildcard, and no grant for a capability that is
   not in the registry. `sudo -i` is the exact thing this architecture spent
   nine milestones not building, and handing it to the first account by
   default would have made the constraint decorative.
4. **The same mechanism already refuses AI agents.** `privilege.request` from
   inside a `punar-agent-*.scope` is refused (`agent_privilege_refused`),
   before any uid check. A device whose humans elevate through the same typed
   path that agents are structurally excluded from has one privilege story,
   not two.

**What it does not buy, said plainly:**

- It does not stop someone who has your password and your machine. They can
  request, approve, and elevate exactly as you can. §8 restates this as a
  refusal.
- It does not make the grant window safe. punard authorises by **uid**, not
  by pid — so for the duration of a grant, *any* process running as that user
  can set *that one capability*. A 15-minute grant is 15 minutes of that
  narrow authority for that uid. This is why the default duration should be
  the smallest that completes a task and why the shell shows a live countdown
  chip (M9 §7, Plate D-012).
- It does not survive an attacker who is already root by another route. It is
  a default-state property, not a boundary.

**Why not simply put the first user in `wheel` as well, "for emergencies"?**
Because a permanent administrator that exists for emergencies is a permanent
administrator, and every one of the four properties above evaporates the
moment `sudo -i` is one password away. §48's sentence — *avoid permanent
local admin as the default developer solution* — is not satisfied by
providing both and calling JIT the recommended one. Punar is in the unusual
position of having actually built the alternative (M9 shipped it, and
`m9-check` step 11 drives it end to end from a non-root account); declining
to use it as the default would be the strangest possible outcome.

`sudo` remains installed — it comes with the substrate and removing it would
be a deep fork of the base package set for no benefit — but Punar authors no
rule in `/etc/sudoers.d/`, grants `wheel` to nobody, and §7 assertions B-6 and B-7
prove both.

**Two things this decision creates that §1.6 alone does not answer**, both
found by walking a real first hour rather than by reasoning about the posture:
the ceremony cost of routing *every* mutation through the grant path
(**§1.6.1**), and the fact that locking root makes `punard` the only privilege
path on the device, so a `punard` that will not start is a device with no
local administrative authority at all (**§1.6.2**). Neither reverses §1.6.
Both are conditions on shipping it.

### 1.6.1 The first hour — and the self-service set that keeps JIT from becoming a prompt storm

*(Added 2026-08-26 after a hard-nosed walk of a real first hour. §1.6's
posture survives the walk; this section is what it costs and what it needs.)*

§1.6 is correct about the **default state of the machine**. It is not, on its
own, a complete answer, because M9's human path today is exactly three lines —

```text
uid == 0                              → allow
live grant for (uid, capability)      → allow
otherwise                             → deny
```

— and if *every* mutating operation a person performs in their first hour goes
through that path, the ceremony is `request` → `resolve` → `set` → `expire`
**per operation**. Walked concretely on a fresh personal device:

| First-hour task | Under §1.6 alone | Verdict |
|---|---|---|
| **Install an application** | `apps.install` is already specified by `app-catalog.md` §14 as a **typed method open to any connected peer**, with only agent-attributed peers gating to approval. No grant, no ceremony. | **Fine already** — and it is the precedent this section generalises |
| **Change the timezone** | `time.timezone` is a registry capability, so: request, self-resolve, set, expire. Three commands, two audit events and an approval card to change a clock. | **Prompt storm.** Unacceptable as a default |
| **Change the keyboard layout** | `system.keymap` (dashed, M13 §5.3) — same shape, same three commands | **Prompt storm** |
| **Join a Wi-Fi network** | **Undesigned.** No `network.*` capability exists, no polkit policy is authored, and `iwd`/NetworkManager are not in the image. Whatever ships must not land in the grant path: a person who cannot reach a network without an approval ceremony will route around Punar on day one | **Open, and load-bearing** |
| **Set the hostname** | Onboarding itself does this **as root, from the OOBE surface, before the account can be used** — so the first-hour case is *changing* it later, which is genuinely rare and genuinely consequential | **Grant path is right** |
| **Disable the firewall** | Grant path | **Grant path is right** |

**The decision: the registry gains a `self_service` boolean, and the human
path gains one line before the deny.**

```text
uid == 0                                        → allow
live grant for (uid, capability)                → allow
capability.self_service AND peer is in group    → allow, audited with
  `punar` AND the device is unmanaged              details.self_service: true
otherwise                                       → deny
```

Four properties make this a narrowing of the ceremony rather than a widening
of authority:

1. **It is a property of the capability, declared in the registry and shipped
   inside the signed image** — not a runtime setting, not a user preference,
   and not something the person at the keyboard can flip. Adding a capability
   to the set is a release, reviewed like any other registry change.
2. **The agent path is untouched.** Step 2 of M9 §5.1 still runs first, so an
   agent-attributed peer calling a self-service capability still takes the AI
   authority path and still gates to approval. `self_service` is a statement
   about *humans at their own machine*, and §60 is unaffected.
3. **Policy can revoke it, and never grant it.** An organisation's policy
   layer may set `self_service: false` for any capability; it may not set it
   `true` for one the image shipped as `false`. The merge is one-directional
   on purpose — otherwise an org could quietly hand out standing authority
   that the JIT design exists to refuse.
4. **It is still audited, still typed, still one capability.** The audit event
   carries `details.self_service: true` instead of `details.grant_id`, so the
   trail distinguishes the two paths rather than blurring them.

**The set that ships, and the rule that bounds it:** a capability is
`self_service` only if it is (a) `risk: low`, (b) reversible by the same
person through the same surface, and (c) something whose *absence* would be
felt within the first hour of owning the machine.

| Capability | `self_service` | Why |
|---|---|---|
| `time.timezone` | **yes** | Low risk, self-reversible, and you moved |
| `system.keymap` *(dashed)* | **yes** | Same, and stronger: a wrong keymap is a device you cannot type on |
| `system.hostname` | **no** | It is what the network sees; changing it is rare and consequential |
| `security.firewall` | **no** | The exemplar of a capability that must cost something |
| `identity.local-account` | **no** | It is the elevation seed (§1.7) |
| `session.autologin` *(dashed, §5.4)* | **no** | It weakens authentication; §5.4 |
| `apps.install` / `apps.remove` | n/a | Already a typed method, not a capability — `app-catalog.md` §14 |
| Anything `risk: high` | **no**, structurally | The validator refuses `self_service: true` on a `high`-risk descriptor |

**Networking is named as an open question rather than answered here**, because
no network capability exists to answer it about. The constraint this document
places on whoever designs it: *joining a network must not require an approval
ceremony on a personal device* — either it is a `self_service` capability by
the rule above, or it is a per-user operation that never reaches punard at
all. Recorded in §9 as an open item.

**What this does not change.** No account is in `wheel`. Root stays locked.
There is no `sudo -i`, no wildcard grant, and no standing authority over any
`high`-risk capability. The three properties §1.6 claimed — privilege is not
ambient for anything consequential, every consequential change carries a named
human and a reason, and a grant is one capability and never a shell — all
survive verbatim. What changes is that the ceremony is spent where it buys
something.

### 1.6.2 The lockout that the JIT posture creates, and the recovery it therefore owes

Walking the fourth leg of the first hour — *recovering when something breaks* —
surfaces a failure mode §1.6 does not survive on its own, and it is worth
stating as sharply as it deserves:

> **Root is locked. No account is in `wheel`. Punar authors no sudoers rule.
> Therefore `punard` is the *only* path to privilege on a Punar device — and
> if `punard` does not start, the device has no local administrative authority
> at all.**

That is not hypothetical. `punard` is first-party code that ships in the root
slot and is replaced wholesale by every update. A regression that keeps it
from starting is an ordinary software defect with an extraordinary blast
radius.

Two mitigations exist on paper and exactly one of them works today:

| Mitigation | Does it cover the case? |
|---|---|
| **A/B rollback (ADR-003)** — boot the other slot | **Yes, after the first update. No, on a fresh install**, where `installer.md` §10.2 assertion I17 requires slot B to be *zero-filled with no UKI*. A device whose very first boot cannot start `punard` has no slot to roll back to |
| **§1.8 Layer 2** — the `punar-recover` boot entry | **It is the right answer and it does not exist.** `installer.md` §6.4 requirement 5 reserves the ESP room and declines to build the artefact, so §1.8 Layer 2 is *dashed* |
| Layer 1 (the account recovery code) | **No.** It is redeemed *through punard*, at the greeter |
| Layer 3 (reinstall) | Yes, at the cost of everything on the disk |

**The consequence, and the recommendation this document makes to the
programme:** on the MVP as currently designed, a `punard` that fails to start
on a freshly installed device is recoverable only by reinstalling. That is a
worse outcome than the dev image it replaces, where `RootPassword=punar` was a
console away — which is a genuinely uncomfortable sentence and is exactly why
it is written down rather than discovered.

So: **§1.8 Layer 2 is not a nice-to-have, it is the mitigation the JIT posture
owes.** This document upgrades it from *deferred* to *blocking for the first
release that ships a locked root* — not blocking on the design, which is
`installer.md`'s to build, but blocking on the claim. Until `punar-recover`
exists, §8 carries limit 10 and every surface that says "Punar has no
permanent administrator" must be able to answer *"then how do I get in when
the daemon is broken?"* with something other than silence.

The cheap interim, if the recovery UKI slips: the installer blesses slot B
with the **same** image it wrote to slot A. It costs 8 GiB that are already
allocated and nothing else, it makes the firmware's own boot menu a working
recovery path from the first boot rather than the second, and it removes the
"no rollback target on a fresh install" row above entirely. Recorded as a
recommendation to `installer.md` §4.1, not a decision taken here.

### 1.7 The bootstrap rule

A device where nobody can ever elevate is a brick. The bootstrap rule is
therefore explicit, and it is a rule about *the right to ask*, not the right
to do:

> **The first account created by onboarding is a member of group `punar`.
> Group `punar` is the filesystem admission gate on `/run/punard`
> (`0660 root:punar`, shipped since M3). Membership grants the ability to
> *reach* punard and therefore to raise a `privilege_request`. It grants no
> capability by itself.**

The full posture of the first account:

| Property | Value | Reason |
|---|---|---|
| `uid` | **allocated once from a persistent on-disk map** (`/var/lib/punar/identity/uid-map.json`), lowest free ≥ 1000; normally 1000, and nothing may assume it | Below 60000 — see §6.3. Allocated-then-permanent, and **never derived** from the username, an email or a directory object id: `platform-sso.md` §6 rules 1 and 2, which this row exists to satisfy. Deriving a uid from a name is the one-way door that makes later directory binding irreversible |
| primary group | `<username>` (per-user group) | Standard, and it makes `0700` homes and `umask 002` both safe |
| supplementary groups | `punar`, `video`, `input` | `punar` = may ask (above). `video`/`input` are the direct-DRM safety net the dev image already grants; logind normally supplies them and they are belt-and-braces |
| **not** in | `wheel`, `uucp`, `docker`, `storage` | `wheel` per §1.6. `uucp` was a dev-image debugging convenience and does not ship. The others are the classic "group that is silently root" set |
| shell | `/bin/bash` | The substrate's shell; §65 requires that the user *not need* it, not that it be absent |
| home | `/home/<username>`, `0700` | On `/var` per ADR-003 |
| `subuid`/`subgid` | `100000:65536` | Rootless podman, as the dev image already does — but for the created user, not for `punar` |
| root account | **locked** (`!` in the hash field), no password | There is no ambient root login. This replaces `RootPassword=punar` |

And the closing rule, which is what makes the whole thing safe to ship:

> **The elevation-capable set is never empty.** punard refuses any
> `identity.local-account` apply that would leave zero enabled accounts that
> are members of group `punar` and have a usable authenticator. The refusal
> is a §73 message naming which account would have been the last one.

This is the "last administrator" invariant every multi-user OS needs and most
implement as a special case in a GUI. Here it lives in the capability's
`validate`, which means the CLI, the shell and any future org policy all hit
it, and the check proves it (assertion B-8).

### 1.8 Recovery — three layers, and an honest floor

The rule the layers exist to satisfy: **a person who owns the device must be
able to get back into it; a person who does not, must not.** On an encrypted
device those two sentences meet at the disk secret, and the design says so
rather than inventing a fourth path around it.

**Layer 1 — the account recovery code.** Generated at onboarding, shown
**once**, on its own row of the account stage. 6 groups of 5 Crockford-base32
characters (~150 bits with the checksum, ambiguity-free to transcribe). Only
a salted hash reaches disk, in `/var/lib/punar/identity/recovery.json`
(`0600 root:root`). Redeemed at the greeter — *"I can't sign in"* — through
the typed method `identity.recovery.redeem`, which performs exactly two
fixed repairs: set a new password, and restore group `punar` membership. It
is **single-use**; redeeming rotates it and the new code is shown once. It is
rate-limited with a growing delay and every attempt is audited — and the
audit event contains the *outcome*, never the code (assertion F-2).

Covers: forgotten password, a group membership broken by a bad edit, an
account disabled by mistake. That is the overwhelming majority of real
lockouts and it needs no media, no network, and no second machine.

**Layer 2 — physical presence at the boot menu.** A recovery boot entry that
runs a fixed-menu tool, `punar-recover`, offering: list accounts, reset an
account password, restore group membership, rotate the recovery code. **Not a
root shell** — the same §60 discipline applied to the recovery surface, so
that "recovery mode" never becomes the generic root RPC the architecture
refuses everywhere else.

Its authority is the disk: on an encrypted device the entry cannot proceed
until the disk is unlocked, which requires the LUKS passphrase or the disk
recovery key. That is not a weak gate bolted onto a strong one — it *is* the
device's floor of local authority, and there is nothing below it that is not
a backdoor.

This entry is a fourth UKI on the ESP. ADR-003 sizes the 1 GiB ESP for three
(A, B, and the retained last-known-good) at ~360 MB used; a fourth is
~120 MB and fits, but **the ESP layout is `installer.md`'s to own** — §4.4
records this as a requirement placed on it, not a decision taken here.

*(Answered 2026-08-26: `installer.md` §6.4 requirement 5 reserves the room and
declines to build the artefact, so **Layer 2 is dashed**. §1.6.2 argues that
this is more serious than one missing recovery layer, because with root locked
`punard` is the only privilege path on the device; `installer.md` §12.1 is
that document's response and recommends blessing slot B with the same image as
slot A so a fresh device has a rollback target from its first boot. That is an
interim, not a substitute: it recovers a device whose **software** is broken,
not one whose owner has forgotten a password, which is what Layer 2 is for.)*

**Layer 3 — reinstall, stated rather than avoided.** With neither the account
recovery code nor the disk secret, the data is unreachable. That is the
correct behaviour of an encrypted device and Punar says it out loud at the
moment the recovery code is displayed:

```text
Write this down.

If you forget your password, this code is how you get back in.
If you lose both, nothing on this disk can be recovered — not by
you, not by us. That is what "encrypted" means.
```

**Not offered, and why:** a security-question fallback (a second, weaker
password made of public facts); a Smplify-held escrow on a personal device
(the §8 unmanaged-first line — a personal device holds no vendor key); a
"reset via email" path (there is no email in this account model, §1.1). On an
**enrolled** device whose organization requires it, the installer generates a
separate disk recovery key on-device and escrows only its tenant-wrapped form
to Smplify. This is automatic and does not expose the key to the end user, but
the fact and the organization that can recover the disk remain visible and
audited. The mechanism and its trust boundary belong to `installer.md` §5.3;
the local account model never handles that key.

### 1.9 What is stored, where, and what an update must never lose

ADR-003's shared partition is what makes this table possible; §3.6's rules
are what make it mandatory.

| Datum | Location | Mode | On `/var`? | Lost by an A/B swap? |
|---|---|---|---|---|
| Account record (`accountId`, username, uid, `realName`, groups, home, shell, `identity: null`) | `/var/lib/punar/identity/accounts/<accountId>.json` | `0600 root:root` | yes | **no** |
| Authenticator (yescrypt hash) | `/var/lib/punar/identity/shadow` | `0600 root:root` | yes | **no** |
| Recovery code hash + salt + attempt counter | `/var/lib/punar/identity/recovery.json` | `0600 root:root` | yes | **no** |
| Device display name | `/var/lib/punar/identity/device.json` | `0644 root:root` | yes | **no** |
| Home directory and everything in it | `/home/<username>` | `0700` | yes (bind or subdir) | **no** |
| Hostname | *desired state* in punard's effective document on `/var`; **materialised** to `/etc/hostname` + kernel at every boot reconcile | — | yes | no — re-applied |
| Timezone, keymap | same shape | — | yes | no — re-applied |
| Theme pointer | `~/.config/punar/theme.json` | `0600` user | yes (in `/home`) | **no** |
| First-boot marker | `~/.local/state/punar/first-boot.json` | `0600` user | yes | **no** |
| Install seed (§4.3) | `/var/lib/punar/install/seed.json` | `0644 root:root` | yes | **no** |
| `machine-id`, device id, enrollment token, `policy.d`, audit log, ledger | already specified by update-and-rollback §3.6 | — | yes | **no** |
| Greeter projection (§5.2) | `/run/punar/greeter.json` | `0644 root:root` | **no** — tmpfs | regenerated at boot |

**The rule this table encodes, stated as one sentence:** *no file under `/etc`
is ever the authority for an account, a password, a recovery secret, or a
device name.* `/etc` holds materialisations, and a materialisation that
disappears is regenerated at the next boot reconcile by the daemon that owns
it. The dev image today gets this right *by accident* — user `punar` is baked
identically into both slots — and a real device must not depend on an
accident (update-and-rollback §3.6 says exactly this).

**Schema versioning.** Every file above carries `"v": 1` and obeys the N-1
rule: release N must read what release N-1 wrote. The account record is the
highest-stakes instance of that rule in the system, because a rollback that
produces a device nobody can log into is worse than any bad release it was
rolling back from.

### 1.10 Keeping accounts off the root slot — the mechanism, and its spike

`/etc/passwd` and `/etc/shadow` are on the root slot. Accounts must not be.
Something has to bridge that, and the bridge is the single riskiest technical
assumption in this document, so it is designed with its fallback and a named
verification spike rather than asserted.

**Chosen (dashed, unverified): JSON user records served by
`systemd-userdbd`, resolved by `nss-systemd`.**

- punard owns the records at `/var/lib/punar/identity/accounts/`.
- At boot, a punard oneshot **materialises** them into `/run/userdb/` — the
  tmpfs drop-in location userdbd already scans. `/etc` is never touched, so
  the `/etc` rule is not merely satisfied, it is not engaged.
- `nss-systemd` provides the `passwd`, `group`, `shadow` and `gshadow`
  databases for those records, serving the `privileged` section — where the
  hash lives — only to root. `pam_unix` therefore authenticates through the
  ordinary `getspnam()` path with no Punar PAM module.
- Ordering: the materialise unit must complete before `systemd-userdbd`
  answers, before `systemd-user-sessions.service`, and before `greetd`.

**Why this and not `systemd-homed`:** homed is a bigger, more opinionated
system (per-user LUKS home images, its own PAM module, its own migration
story) and it puts a second encrypted volume inside an already-encrypted
disk. It solves a problem — portable homes — that Punar does not have in the
MVP, at the cost of a mechanism nobody on this project has exercised.

**Fallback if the spike fails (V1, §9):** punard materialises the Punar-owned
lines into `/etc/passwd`, `/etc/shadow`, `/etc/group`, `/etc/subuid` and
`/etc/subgid` at boot, as the apply side of `identity.local-account`. Vendor
system users are supplied by `systemd-sysusers`, which is idempotent,
additive, and already runs on the substrate — so a new release's new system
users appear without Punar owning them. This fallback **re-engages** the
`/etc` rule and **satisfies** it, because those files then are exactly what
the rule demands: verified capability output whose desired value lives on
`/var`. It is uglier and it works, which is why it is the fallback and not
the plan.

Either way the observable property is identical, and it is the property the
check tests (assertion E-7): **reset `/etc` to vendor content and the person
can still log in.**

### 1.11 The one new capability, and the typed methods beside it

Following M9's precedent that `credential.request` and `privilege.request`
are *typed methods, not capabilities* (M9 §2), this document adds one
capability and a small method group, and refuses to add more.

**`identity.local-account` — a typed capability (§41 shape).**

```json
{
  "capability": "identity.local-account",
  "risk": "high",
  "verification": "userdb+nss",
  "audit_category": "identity",
  "requires_reboot": false,
  "state_schema": { "type": "array", "items": { "$ref": "account-record" } }
}
```

- **observe** — the materialised accounts, normalised. Reports
  `hasAuthenticator: true|false`. **Never the hash.**
- **apply** — create, modify (`realName`, groups, shell, enabled), disable.
  Never rename, never delete a home directory.
- **verify** — the record matches what NSS resolves. Compares the record, not
  the secret.
- **validate** — the §1.3 username rules, the uid-range rule (§6.3), and the
  §1.7 last-elevator invariant.

**The `identity.*` typed methods — write-only, no observable state:**

| Method | Who may call | Notes |
|---|---|---|
| `identity.set_password` | uid 0, or the owning uid for its own account | Enforces §1.4 including the offline blocklist. Returns `ok` or a typed refusal. The secret is never echoed, never logged, never audited beyond `action: "identity.set_password"` + outcome |
| `identity.recovery.rotate` | uid 0, or the owning uid | Returns the new code **once** |
| `identity.recovery.redeem` | the greeter's own privileged path only | Rate-limited, audited, single-use |

**Why the password is not part of the capability's desired state**, argued
because it is the tempting design: desired state is a *document* — it is
merged through §39's ladder, printed by `policy explain`, diffed by
reconcile, and carried in the effective document on `/var`. Putting an
authenticator there would put a credential into a structure whose entire
purpose is to be read, explained and compared. The split is a security
decision first; §6.2 shows it is also the reason directory binding is later
additive rather than a rewrite.

**Explicitly not added:** `system.device-name` (§1.5 — deferred, dashed),
`session.autologin` (§5.4 — the feature does not exist on a production image,
which is stronger than a setting defaulted off), and any capability for the
theme (theme-system §6.1 already settled it, and this document does not
reopen a decision it agrees with).

---

## 2. The onboarding sequence

Plate D-008's seven stages, §65's ordering, M13 §5.2's mechanism (a
`WlrLayershell` layer inside `punar-shell`, gated on
`~/.local/state/punar/first-boot.json`, every side effect a fixed-argv
`punarctl` call through `Quickshell.execDetached`). This document changes
exactly one thing about M13's design — stage 03 becomes real — and adds two
rows elsewhere (§3).

### 2.0 The invariants

Five rules that hold across every stage, and that the check tests as rules
rather than per-stage:

1. **No shell command is shown, required, or suggested.** §65's rule, taken
   literally. The *user* types nothing at a prompt; the *surface* issues
   typed calls.
2. **No skip ever turns something on.** Every default reachable by pressing
   Enter through the flow is the quieter one: no relay, no telemetry (there
   is none), no enrollment, no autologin, personal mode.
3. **Exactly one stage cannot be skipped** — stage 03. A device with no
   account is a device nobody can use, and the alternative is the dev
   convenience this document exists to delete.
4. **Nothing requires a network.** The entire personal path completes
   offline, which is both a product property (§55) and the reason the
   check can run in a `-nic none` VM.
5. **Nothing guesses.** Timezone is not inferred from an IP address; the
   locale is not inferred from a keyboard layout; the username is not
   invented. A stage that would have to guess asks, or defaults to the
   inert value and says which.

### 2.1 Stage 01 — Welcome: language · keyboard · timezone · contrast

| Field | Writes | Through | If skipped |
|---|---|---|---|
| Language | *nothing in v1* | — | `English (US)`, the only entry, with M13 §5.2's dashed `OTHER LOCALES · NOT IN THIS BUILD` row and its reason |
| Keyboard | keymap desired state on `/var`, materialised to Hyprland drop-in + `/etc/vconsole.conf` | `punarctl capabilities set system.keymap <layout>` *(dashed — M13 §5.3)* | `us` |
| Timezone | timezone desired state on `/var`, materialised to `/etc/localtime` | `punarctl capabilities set time.timezone <tz>` **(shipped)** | `UTC`, and the clock says `UTC` rather than pretending |
| **Higher contrast** | `~/.config/punar/theme.json` | `punarctl theme set contrast` | off — the `paper` default |

The contrast row is here and not at the end. Reasoning in §3.1.

Seeds: if `/var/lib/punar/install/seed.json` exists (§4.3), keyboard and
language arrive pre-selected with the label `from install` — visible, not
silent, and overridable in place.

### 2.2 Stage 02 — Network

Unchanged from M13 §5.2: read-only interface presence via `ip -j link`, no
credential entry, no picker, because the CI VM has no NIC and a Wi-Fi picker
built against a NIC that does not exist is a mockup shipped as a feature.
D-008 already draws the offline state and its own line — *setup continues
offline too; the organization path simply stays closed until a network
exists* — so the plate is followed honestly rather than softened.

**Writes:** nothing. **If skipped:** offline; stage 04's organization card is
present but disabled with the reason on the card; every other stage is
unaffected.

A real network stage arrives with the Wi-Fi work spec §77 already lists. This
document does not design it and does not pretend it is close.

### 2.3 Stage 03 — Account (**the stage M13 deferred, and the reason it can now ship**)

M13 deferred account creation with a good argument: *"a password field in a
QML surface is a credential surface, and this project's own rule is that
secrets do not pass through the shell."* That rule is right and this design
keeps it — by not passing the secret through the shell in the sense the rule
means.

**The mechanism:** the OOBE layer collects the four values of §1.1 and hands
the password to punard through the typed `identity.set_password` method over
the existing admitted socket, in one call, from a process the user owns. The
secret is never written to a file the shell controls, never placed on a
command line (fixed argv, value on stdin), never held after the call returns,
and never reaches the QML property tree — the field's buffer is the only copy
and it is zeroed on stage exit. What M9 §6's rule forbids is the shell
*storing*, *brokering* or *displaying* secrets; typing one into the field
that exists to receive it, and handing it once to the daemon that owns the
store, is what every credential surface in every OS does and is the only
alternative to a text-mode prompt that §65 forbids.

The remaining half of M13's argument — *"doing it properly means PAM, a
policy for password quality, and a recovery story"* — is exactly what §1.4,
§1.8 and §1.10 are. The premise moved because the work was done, not because
the standard dropped.

| Value | Writes | Through |
|---|---|---|
| Full name, username, groups, uid, home | account record on `/var`, materialised to userdb | `identity.local-account` apply *(dashed)* |
| Password | `/var/lib/punar/identity/shadow` | `identity.set_password` *(dashed)* |
| Device name | `device.json` on `/var` | `identity.local-account` apply |
| Hostname (derived) | punard effective document → `/etc/hostname` + kernel | `punarctl capabilities set system.hostname <name>` **(shipped)** |
| Recovery code | hash only, `recovery.json` | `identity.recovery.rotate` *(dashed)* |

**If skipped: it cannot be.** Enter with an incomplete stage re-focuses the
first unsatisfied field and states what is missing. There is no back door,
no `punar` fallback account, and no "set this up later" — the flow does not
reach the desktop without an account, because the desktop is that account's.

**What the stage promises, and keeps:** D-008's own copy —
*No email. No cloud sign-up. This user exists only on this machine.* Every
word of that is true of this design, which is why it is quoted rather than
softened.

### 2.4 Stage 04 — The fork: personal or organization

Unchanged from D-008 and M13, which are already correct and already the
acceptance reference. Personal is pre-selected and carries the only `DEFAULT`
tag in the flow; choosing it **writes nothing anywhere**, which is
unmanaged-first expressed as an absence of files rather than as a claim
(DESIGN_LANGUAGE §8; M5's assertion that `policy.d` is empty before
enrollment).

**One line this document adds to the organization card,** because the account
model makes it necessary and §1.22 makes it mandatory:

```text
Enrolling registers this device. It does not yet verify who you
are — the account you just made stays local, and stays yours.
Directory sign-in arrives later.
```

That is `user-blocked.md` item 5 stated on the surface where a user would
otherwise assume the opposite, and it is the sentence §6 exists to keep true.

**Why the account comes before the fork**, given that a future directory
identity might supply the account: because personal is the default and must
feel complete (§8), and asking *who do you work for* before *who are you*
makes the organization path read as the main path. The local account is also
not wasted work when binding arrives — that is the entire content of §6.

**If skipped:** personal. Skipping *is* choosing, and the choice it makes is
the thesis.

### 2.5 Stage 05 — Privacy defaults

Unchanged from D-008 and M13 §5.2: the private-relay toggle carrying its
dashed `SIMULATED · M12` tag (or `NOT IN THIS BUILD` rather than a dead
toggle if M12 has not landed), telemetry rendered as a **fact block** —
*Community edition has no telemetry. There is nothing to opt out of* — rather
than as a pre-checked consent, and the M8 ledger retention (14 d) stated.

This document adds nothing here. The account model creates no new privacy
decision, and a stage that has nothing new to say should say nothing new.

**If skipped:** relay off; telemetry remains a fact; retention default.
Invariant 2 holds.

### 2.6 Stage 06 — Organization (org branch only)

Unchanged: the §49 chain as a progress register — discovery, authentication,
registration, attestation, desired state, provision — with
`Attestation · SIMULATED · VM` dashed and the mocked control plane's fixtures
named rather than a live service invented. Ends on the employee-facing
promise, not the corporate one: *enrolled means you see everything they see*
(§24.2).

**If skipped:** the branch does not exist on the personal path.

### 2.7 Stage 07 — Ready: light or dark, then the desktop

Two theme cards, `paper` and `panel`, and the handoff. Reasoning in §3.1.

| Field | Writes | Through | If skipped |
|---|---|---|---|
| Light / dark | `~/.config/punar/theme.json` | `punarctl theme set paper\|panel` | `paper` |
| — | `~/.local/state/punar/first-boot.json` `{v, completed_at, mode}` | FileView `atomicWrites` (M13 §5.6) | written on arrival regardless |

`ENTER DESKTOP` performs D-008 §V.03's 450 ms first-light handoff — one
opacity+scale transition as the bar and desktop chrome are exposed, once per
install, never replayed. The footer states which path was taken and, on the
personal path, *Nothing left this machine*.

**The marker records the mode, not the answers** (M13 §5.6). Every answer is
state Punar already owns — a capability, an account record, a theme pointer,
enrollment state — and a second copy of any of them in the marker would be a
drift source.

### 2.8 The unattended path — how a headless VM completes all seven stages

The check cannot press Enter, so the flow must be drivable without a human,
and that path must be as honest as the interactive one.

`/var/lib/punar/install/oobe-answers.json`, dropped by the installer, by
`mkosi.extra` in a check profile, or by a kernel argument pointing at a file.
Consumed once and then renamed to `.consumed` — never deleted, so an
operator can see what a machine was provisioned with.

```json
{
  "v": 1,
  "keymap": "us",
  "timezone": "Europe/Berlin",
  "account": {
    "realName": "Alice Nguyen",
    "username": "alice",
    "deviceName": "Alice's ThinkPad",
    "passwordSource": "hash",
    "passwordHash": "$y$j9T$…"
  },
  "mode": "personal",
  "theme": "paper"
}
```

**`passwordSource` is `"hash"` or `"prompt"`, and there is no third option.**
A plaintext password in a file on disk is a plaintext password on disk; this
design refuses to accept one and says why in the schema's own description.
CI uses a pre-generated fixture hash. A real unattended enterprise
provisioning uses `"prompt"`, which completes every other stage and stops on
stage 03 with the account fields focused — the machine arrives configured and
the human arrives with a password.

The answer file **cannot** set: `autologin` (does not exist, §5.4), any
group beyond the §1.7 set, the recovery code (it is generated, never
supplied), `wheel`, or `self_service` on any capability (§1.6.1 — it is a
property of the signed registry, not of a provisioning artifact). An answer file that could hand out permanent admin
would be a permanent-admin feature with extra steps.

---

## 3. Personalisation beyond identity

Onboarding fatigue is real and §65's list is already seven steps. So the rule
for this section is: **first boot adds no stage for personalisation.** It adds
one row to stage 01 and one row to stage 07, and refuses everything else.

### 3.1 Theme — two at the end, and one at the beginning

The shipped set is seven entries (theme-system §5). Onboarding shows **two**.

**Stage 07 shows `paper` and `panel`** — the same palette at its two moods,
which is the only theme question a person actually has on day one: *light or
dark*. `graphite`, `oxide`, `nocturne` and `ember` are taste, and taste
belongs in the picker one keystroke away, chosen by someone who has seen the
system, not extracted from someone who has seen six screens of setup.

**Stage 01 carries `contrast`, as an accessibility row, not a theme card.**
This is the decision worth arguing: putting the high-contrast theme in the
taste stage is a category error, because *the person who needs it cannot read
stage 01*. An accessibility option offered at the end of a flow that was
unreadable from the start is not an accessibility option. So stage 01 — the
first screen, the one that already asks about language and keyboard — carries
one row, `Higher contrast · off`, which applies immediately and persists.

Consequence to handle explicitly: if `contrast` was chosen at stage 01, stage
07's two cards must **not** silently overwrite it. Stage 07 renders with
neither card selected and a line reading *Higher contrast is on — keeping
it*, and Enter changes nothing. Assertion D-3 tests exactly this, because it
is the kind of interaction that works in the mockup and breaks in the build.

**Mechanism:** `punarctl theme set <id>` — theme-system §6.2's sequence,
writing `~/.config/punar/theme.json` with the validation receipt. Not a
capability, per theme-system §6.1's argument, which this document accepts
without reopening.

### 3.2 Wallpaper — real, deliberately kept out of first run

The shell now has the finite catalog specified by `wallpapers.md`, but
onboarding still does not offer a picker. Username, password, and device name
are the three values required to make the machine usable; visual preference is
not. Stillpoint is the safe shipped default, the Command Center exposes all
five choices after handoff, and the existing Field vector remains the
theme-derived constrained-machine option. No wallpaper daemon was added.

### 3.3 Avatar — initials, and no photograph

The greeter shows a monogram, derived from the full name:

```text
"Alice Nguyen"  → AN
"Ada"           → A
"李雷"           → 李        (first grapheme cluster)
""              → ·          (a dot, never a "?")
```

First grapheme cluster of the first and last whitespace-delimited tokens,
uppercased where the script has case, at most two. Plate D-002 already draws
`AL` in exactly this position.

**No photo, and this is a decision rather than a shortfall.** A photo means a
camera permission or a file picker at first boot, an image decoder inside the
greeter's trust boundary, a per-user blob to store, size, roll forward and
project into `/run` for the greeter to read — for two letters' worth of
value. The avatar *is* the initials.

### 3.4 What else is not asked, and why

| Not asked | Reason |
|---|---|
| Accent colour | The palette has one accent and it is load-bearing (DESIGN_LANGUAGE §2: colour is status). A user-chosen accent would compete with the one hairline that carries meaning |
| Font size / scaling | A real accessibility need, and a real subsystem (Wayland scaling, Hyprland, the token set). Deferring it is honest; faking it with a QML zoom is not |
| Sounds | Punar ships none |
| Cloud account, email, "sync" | There is nothing to sync to. D-008's promise is *no email, no cloud sign-up*, and this is what keeping it looks like |
| Autologin | §5.4 — the feature does not exist on a production image, and a security-weakening option offered at the moment of least context is a dark pattern |
| Analytics opt-in | §54 — there is nothing to opt into, and stage 05 says so as a fact |

---

## 4. Where onboarding lives

### 4.1 The three models

| Model | Where the account is created | Its real failure |
|---|---|---|
| **Ubuntu** — installer owns onboarding | Before first boot, by whoever ran the installer | Binds the machine's identity to the person holding the USB stick. An IT technician imaging 200 laptops creates 200 accounts named after themselves, or creates a generic one everybody then shares |
| **macOS** — first boot owns onboarding | On first boot, by the person who opened the lid | Requires the shipped image to contain no user at all, which is a constraint on the image pipeline rather than a flaw |
| **Split** | Installer owns the disk; first boot owns the person | Requires a defined seam, or the two halves ask the same question twice |

### 4.2 The decision

**Split, with the seam at *what the disk needs* versus *who the person is*.**

- **The installer owns:** target disk, the ADR-003 A/B partition layout with
  fixed PARTUUIDs, `/var` and `/home`, the ESP and its UKIs, LUKS2 and the
  disk recovery key, writing the first slot, and **no user account
  whatsoever**.
- **First boot owns:** every one of §65's steps 2–7 — language, keyboard,
  timezone, network, the account, the fork, privacy, arrival.

Three arguments, in the order of how much they matter:

1. **§65's list is a first-boot list.** It begins at *boot* and ends at
   *reach graphical desktop*; it does not contain the word install. And its
   ordering puts **network (3) before account (4)** — an ordering the
   installer cannot honour, because an installer frequently has no network
   and does not need one. Putting the account in the installer inverts the
   spec's own sequence.
2. **The imaged-fleet case, which is the enterprise case.** An organisation
   images 200 machines from one artifact and ships them to 200 people. Under
   the split, every one of those machines arrives at a clean first boot and
   the person who opens it is the person the account belongs to. Under the
   Ubuntu model, the fleet arrives pre-populated with the technician.
3. **The two secrets belong to two people at two moments.** The LUKS
   passphrase and disk recovery key are *disk* secrets, set by whoever owns
   the disk, at install. The account password and account recovery code are
   *personal* secrets, set by the user, at first boot. On a fleet those are
   genuinely different humans. Collapsing them into one screen would either
   hand the technician the user's password or hand the user the disk key —
   and §1.8's whole layering depends on them being distinct.

And the constraint that settles the other direction: **disk encryption cannot
move to first boot**, because you cannot encrypt the volume you are running
from. Physics decides that half.

### 4.3 The seam — one file, read as a hint and never as authority

`/var/lib/punar/install/seed.json`, written by the installer, `0644
root:root`:

```json
{
  "v": 1,
  "locale": "C.UTF-8",
  "keymap": "us",
  "installedAt": "2026-08-26T09:14:03Z",
  "imageVersion": "punar-0.1.0-…",
  "diskEncrypted": true,
  "diskRecovery": { "mode": "personal_copy" }
}
```

First boot uses it to **pre-select**, labelled `from install` on the stage, and
treats it as advisory in every case: a missing, malformed or unreadable seed
degrades to the §2.1 defaults with no error shown to the user, because a
person opening a new laptop should not be shown a parser's opinion.

`diskEncrypted` and `diskRecovery.mode` are read for one purpose: stage 03's
recovery copy must be true for this device. `personal_copy` says the disk owner
received a key; `organization_escrow` says the named organization can recover
the disk; `none` accompanies an unencrypted install. First boot never reads or
receives recovery material. If the disk is **not** encrypted, "nothing on this
disk can be recovered" is false and Punar does not print it.

The installer writes **nothing else** first boot depends on, and first boot
writes nothing back into `install/`.

### 4.4 What this places on `installer.md`, and what it does not

Requirements this document places on the installer, to be honoured there
rather than restated here:

1. Ship an image containing **no login-capable user account** — no `punar`,
   no autologin, root locked with no password.
2. Create `/var` and `/home` per ADR-003, with `/var/lib/punar` present and
   `0700 root root` before first boot.
3. Write `seed.json` (§4.3), or write nothing.
4. Own the disk secret and disk recovery key entirely. On a personal install,
   display the recovery key once; on an enrolled escrow-required install,
   wrap and escrow it without displaying it. First boot never shows, stores or
   asks for recovery material in either lane.
5. Reserve ESP room for the §1.8 Layer-2 recovery entry as a **fourth** UKI,
   or record explicitly that Layer 2 does not exist yet — in which case §1.8
   Layer 2 becomes dashed and §8's honest-limits list gains a line.
6. Accept `oobe-answers.json` (§2.8) as a passthrough artifact it writes and
   never interprets.

Not this document's business, and deliberately absent from it: partitioning,
sizing arithmetic, the bootloader, UKI generation, LUKS parameters, TPM
enrolment, mirror selection, and the installer's own UI.

### 4.5 Two passwords at boot — the friction Punar chooses on purpose

On an encrypted machine with no usable TPM, the person types the LUKS
passphrase at the Plate D-002 unlock stage and then their account password at
the greeter. Two secrets, every boot. That is real friction and the design
does not hide it.

The tempting fix — **make the account password the LUKS passphrase** — is
refused, for two reasons that are both about the day it goes wrong:

1. Changing your account password would then have to re-key the LUKS volume.
   A password change that can fail halfway and leave a disk that will not
   unlock is not a password change.
2. Forgetting your password would become an unbootable disk rather than a
   Layer-1 recovery. The two secrets have different recovery paths precisely
   because they protect different things, and merging them merges the failure
   modes into the worse one.

The real fix is TPM-assisted unlock (§44.2), which removes the *first* prompt
on hardware that has a TPM — and that is `user-blocked.md` item 2, needing
physical hardware nobody on this project currently has. So the honest
position is: two prompts today, one prompt on real hardware when item 2
unblocks, and no clever merge in between.

---

## 5. The greeter

### 5.1 M13 deferred it, correctly, on a premise this document removes

M13 §5.4's reasoning was: *"a greeter authenticates, and authentication is
the surface deferred above. A greeter that only decorates an autologin is
theatre, and this repo has spent twelve milestones not shipping theatre."*

That is right, and it is conditional. It was true **because** account
creation was deferred. §2.3 un-defers account creation, so there is now a
real password on a real account, and a greeter authenticates something. The
premise moved; the verdict follows it.

### 5.2 What ships: a real greeter, scoped to one screen

- **Mechanism:** `greetd` with a Quickshell/QML front-end consuming
  `punar-tokens.json`, authenticating through greetd's own PAM conversation.
  **No new PAM module and no new authentication code** — greetd already does
  the PAM work, and the account resolves through §1.10's NSS path like any
  other user.
- **What it shows** (Plate D-002 §III, unchanged): masthead with the device
  display name and, when enrolled, the trust state — *the employee sees what
  the organization sees* (§24.2); the clock; the account card with the
  person's **full name** and **avatar initials**; one password field; one
  green primary. Failed unlock behaves as D-002 §IV.03 already specifies in
  words: shake and `TRY AGAIN`, bad-red on the third attempt.
- **What it reads:** `/run/punar/greeter.json` — a non-sensitive projection
  written by punard at boot, `0644 root:root` on tmpfs, containing
  `[{accountId, username, realName, initials}]` plus the device display name
  and enrollment/compliance state. No hashes, no uids, no record. The greeter
  runs as user `greeter` and must never be able to read
  `/var/lib/punar/identity/`; the projection is what makes that possible, and
  it is the same FileView-fed pattern `status.json` and `alerts.json` already
  use.
- **Recovery entry point:** one quiet row, *I can't sign in* → the Layer-1
  code redemption of §1.8.

### 5.3 What does not ship, named rather than implied

User switching UI (one account is the shipped case; multi-user is §9's open
question), a session picker (there is one session), a power menu beyond what
D-002 draws, and any second authentication factor. Each of those is a
surface with its own states, and shipping a greeter is not an invitation to
ship all of them.

### 5.4 Autologin: the feature does not exist on a production image

Not *a setting defaulted to off* — **absent**. `/etc/greetd/config.toml` on a
production image has no `[initial_session]` stanza at all, and there is no
Punar control that adds one.

Why absent beats defaulted-off: a setting defaulted off is a setting, and a
setting that bypasses authentication needs a policy path, an enforcement
story, an org override, a `/etc` capability (per update-and-rollback §3.6),
and a screen to live on. That is a meaningful amount of machinery for a
convenience nobody has yet asked for on a device that is already unlocking a
LUKS volume at every boot.

The dev image keeps its autologin, in the `desktop` mkosi profile, where it
already is. The line that matters is that the profile is a dev profile and
the check proves the production path does not have it (assertions E-3,
E-4).

*Dashed, for whoever needs it later:* `session.autologin` as a typed boolean
capability, because it mutates an `/etc` file and because an organisation
must be able to pin it false. It earns capability status by exactly the test
theme-system §6.1 laid out and the theme failed: it is consequential, it is
rare, and it is genuinely enforceable — the user cannot rewrite
`/etc/greetd/config.toml` without elevating, and that elevation is audited.

---

## 6. Identity-bound accounts, later

`platform-sso.md` designs directory identity. This section's only job is to
ensure the local account model does not **preclude** it — to name the fields
reserved now, at zero cost, so that binding is a migration rather than a
rewrite.

The test of success is one sentence: **`punarctl identity bind` must attach a
directory identity to the existing account — same `accountId`, same uid, same
home, same files — and never create a second one.** Every decision below
exists to make that sentence achievable.

### 6.1 The join key: `accountId`, and not the two obvious candidates

Every account record carries, from creation:

```json
"accountId": "acct_9f3c1a02b7e4d5c6"
```

Opaque, stable, generated locally, never reused, never shown to the user, and
**never** derived from the username or the uid.

- **Not the username**, because a human chose it, a directory may disagree
  with it (`alice` locally, `alice.nguyen@acme.com` upstream), and §1.3 makes
  it permanent precisely so it can be a filesystem fact rather than an
  identity.
- **Not the uid**, because it is a small integer in a space a directory also
  wants to allocate from, and joining on it is how collisions become
  security incidents.

This is the single most important forward-compatibility decision in this
document and it costs sixteen bytes.

### 6.2 Fields reserved now, unset in v1

| Field | v1 value | What it becomes |
|---|---|---|
| `identity` | `null` | `{provider, issuer, subject, upn, boundAt, lastVerifiedAt}` — where `subject` is the IdP's immutable subject claim (OIDC `sub`, Entra `oid`), **never the email**, which is a display attribute that changes |
| `realNameSource` | `"local"` | `"directory"` once bound — so the first directory sync neither silently overwrites what the person typed nor silently refuses to update it. The ambiguity is resolved by a field that exists before the ambiguity does |
| `auth.kinds` | `["password"]` | `["password", "oidc"]` — the authenticator is a *list*, so binding **adds** a kind rather than replacing the record's notion of how one signs in |
| `groups.local[]` | `["punar", "video", "input"]` | unchanged |
| `groups.fromDirectory[]` | `[]` | populated by sync, and **never merged into `groups.local`** — so unbinding is a truncation, not a diff |
| `homeDirectory` | `"/home/alice"` | an explicit field from day one, never derived from the username, because `alice.nguyen@acme.com` is not a path |
| `uidSource` | `"local"` | `"directory"` — see §6.3 |

The §1.11 split — record and authenticator in different stores — was made for
a security reason. This is its second dividend: adding an authentication kind
touches the authenticator side only, and the record that everything else
joins on does not move.

### 6.3 uid ranges, decided now because it costs nothing and later costs everything

```text
1000  – 59999    local accounts        (uidSource: "local")
60000 – 4294966  directory-mapped      (uidSource: "directory")
```

The classic failure is a directory user landing on a uid a local user already
owns, discovered when file ownership silently transfers. Splitting the ranges
before any directory exists costs one validation rule in
`identity.local-account`'s `validate`. Splitting them afterwards costs a
migration of every file on the device.

### 6.4 What binding would change, and why it is all additive

| Change | Additive? | Note |
|---|---|---|
| PAM stack gains an OIDC/Kerberos module | Yes | `pam_unix` stays for the local authenticator, and offline login keeps working — which matters because §55 says enrollment must not silently downgrade |
| The greeter gains a second path | Yes | A field or a browser hand-off beside the password field. The projection (§5.2) gains `authKinds[]` and nothing else |
| A credential cache with a staleness policy | New, and genuinely new | *"How long may this device accept a directory password with no network?"* is a policy question `platform-sso.md` owns |
| The account record | **Unchanged in shape** | Reserved fields become populated |
| uid, home, files, `accountId` | **Untouched** | This is the whole point |

### 6.4a Two PSSO rules this document must state, not merely not violate

`platform-sso.md` §6 places eleven rules on whatever creates the first
account. Nine of them are decided above and can be read off §1.3, §1.7, §1.10,
§1.11, §6.1 and §6.3. Two are rules about *everything else in the repository*
rather than about the account model, so they are stated here explicitly and
carry their own assertions rather than being satisfied by accident:

- **Rule 9 — user preferences never enter the user record.** The account
  record is org-facing: a bound device will hand it to a directory, and a
  directory has no business knowing which theme somebody picked. Theme,
  contrast, layout and app choices live in `~/.config` and
  `~/.local/state` (§1.9's table already puts them there); the record carries
  identity, POSIX facts and group membership and nothing else. Assertion
  **A-8**.
- **Rule 10 — nothing reads `/etc/passwd` directly.** Every enumeration —
  product code, check scripts, fixtures, `mkosi.finalize`, the greeter
  projection builder — goes through `getent passwd` / `getent group` /
  `userdbctl`. This is not a style preference: on §1.10's chosen path the
  account *is not in `/etc/passwd` at all*, so a direct reader sees a machine
  with a missing user and fails in the least debuggable way available. It is
  enforceable in CI today, offline, for free, and it is cheapest to enforce
  before there is anything to migrate. Assertion **A-9**.

The one place this document deliberately keeps a direct `/etc` read is the
*negative* assertions — E-5 and E-6 grep `/etc/subuid` and `/etc` for the dev
user precisely to prove that nothing Punar owns is there. Proving a file's
absence is not enumerating accounts.

### 6.5 The seam with `platform-sso.md`

This document owns: the local account record's schema, the reserved fields
above, the uid-range split, the record/authenticator split, and the
guarantee that binding never creates a second account.

`platform-sso.md` owns: the providers, the protocol, the token handling, the
offline-credential policy, the group-mapping rules, what happens when a
directory account is disabled upstream, and the enrollment-time user
authentication that `user-blocked.md` item 5 currently blocks.

The two meet at `identity`, `auth.kinds`, `groups.fromDirectory` and
`uidSource` — four fields, named in both documents, defined in this one.

---

## 7. Verification

### 7.1 The check and its constraints

`os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/onboarding-check.sh`,
committed **0755**, renamed to the adopting milestone's `mNN-check.sh`
convention at implementation time and wired the same way `m9-check` and
`m13-check` are.

Constraints it must respect, all of them already binding on this repo:

- **No network.** Every assertion runs in a `-nic none` VM. The blocklist is
  a file; the account is local; the personal path never dials.
- **No `diffutils`.** String comparison is `test "$a" = "$b"`; file
  comparison is `sha256sum` piped to `test`. No `diff`, no `cmp`.
- **No polling.** The check waits on unit state and marker files, never in a
  `sleep`-loop except where an expiry is being *proved* (assertion B-5,
  which is M9's existing pattern).
- **Deterministic and replayable.** Fixtures are fixed strings; `qs ipc call
  firstboot open` forces the layer without clearing the marker (M13 §5.6).
- **Artifacts, not just exits.** Each group writes a named artifact so the
  run is reviewable without a VM (M13 §4.4's discipline).

### 7.2 The assertions

**A · An unattended onboarding produces the named user**

| # | Assertion | Artifact |
|---|---|---|
| A-1 | With `oobe-answers.json` present and no marker, the flow completes headless; `~alice/.local/state/punar/first-boot.json` exists with `mode: "personal"` and a valid `v` | `oobe-marker.json` |
| A-2 | `getent passwd alice` → uid ≥ 1000 and < 60000, home `/home/alice`, shell present; `/home/alice` is `0700 alice` | `oobe-passwd.txt` |
| A-3 | The account record matches `accountId ~ ^acct_[0-9a-f]{16}$`, `realNameSource == "local"`, `identity == null`, `groups.fromDirectory == []`, `uidSource == "local"`, `auth.kinds == ["password"]` | `oobe-record.json` |
| A-4 | `realName` renders: `punarctl --json identity show` prints `Alice Nguyen`, and the greeter projection `/run/punar/greeter.json` carries `realName` and `initials: "AN"` | `oobe-identity.json` |
| A-5 | **Negative:** no artifact from this group contains `$y$`, the fixture password, or the recovery code | `oobe-redaction.txt` (counts only) |
| A-6 | Idempotence: re-running with the marker present creates no second account — exactly one record file | — |
| A-7 | Offline password policy: `identity.set_password` with `password` (blocklisted) → refused; with `alice2026` (contains the username) → refused; with a 9-character novel string → refused; with a 10-character novel string → accepted. All four with no network | `oobe-password-policy.txt` |
| A-8 | **PSSO rule 9:** the account record contains no preference key — `grep -c` for `theme`, `contrast`, `wallpaper`, `layout` over the record → 0; the theme pointer is in `~alice/.config` and nowhere else | `oobe-record.json` |
| A-9 | **PSSO rule 10:** no shipped script, unit or fixture reads `/etc/passwd` or `/etc/group` directly — a repository-wide grep for `/etc/passwd` outside the *negative* assertions of group E returns zero product hits, and every in-guest enumeration in this check uses `getent` or `userdbctl` | `oobe-getent.txt` |

**B · The privilege posture, and that JIT works for the created account**

| # | Assertion | Artifact |
|---|---|---|
| B-1 | As `alice`: `punarctl capabilities set time.timezone Europe/Berlin` → **exit 3**, message names `punarctl privilege request` | `oobe-privilege.txt` |
| B-2 | `punarctl privilege request --capability time.timezone --reason "onboarding check" --duration 1` → an `apr_` | same |
| B-3 | `punarctl approvals resolve <apr_> --decision approved` **as alice** → succeeds (M9 §4.4 rule 2 — self-resolution by the routed user) | same |
| B-4 | The same `capabilities set` **now succeeds**; `readlink /etc/localtime` changed; the audit event carries `details.grant_id` | `oobe-grant.json` |
| B-5 | After expiry: grant gone, `privilege.expire` audited, `capabilities set` fails with exit 3 again | `oobe-privilege.txt` |
| B-6 | `id -nG alice` contains `punar`; **does not contain** `wheel`, `uucp`, `docker`, `storage` | `oobe-groups.txt` |
| B-7 | `getent group wheel` does not list alice; `/etc/sudoers.d/` contains no Punar-authored file (`ls -1 \| wc -l` → 0, or only vendor entries enumerated by name) | same |
| B-8 | **Last-elevator invariant:** removing alice from `punar` while she is the only member → refused with a §73 message; `id -nG alice` unchanged afterwards | `oobe-last-elevator.txt` |
| B-9 | An `oobe-answers.json` requesting `wheel` → the group is not granted, and the refusal is recorded | — |
| B-10 | **The self-service path (§1.6.1):** as `alice`, `punarctl capabilities set time.timezone Europe/Berlin` succeeds **with no grant and no approval**; the audit event carries `details.self_service: true` and **no** `details.grant_id`. The same call for `system.hostname` still returns exit 3, and the same call for `security.firewall` still returns exit 3 | `oobe-self-service.txt` |
| B-11 | **Self-service is not a widening:** an agent-attributed peer calling `capabilities set time.timezone` still takes the M9 AI path and gates to approval (exit 4), never the self-service line; and a descriptor with `risk: high` and `self_service: true` is **refused by the registry validator** at load | same |
| B-12 | **Policy may revoke and never grant:** a policy layer setting `self_service: false` for `time.timezone` takes effect; a policy layer setting `self_service: true` for `security.firewall` is refused and named in `policy explain` | same |

**C · The hostname was set through the capability**

| # | Assertion | Artifact |
|---|---|---|
| C-1 | `punarctl --json capabilities get system.hostname` → `alices-thinkpad`, state `compliant` | `oobe-hostname.json` |
| C-2 | `/proc/sys/kernel/hostname` and `/etc/hostname` both equal it (the backend's own verify contract) | same |
| C-3 | The audit log contains a `capability.set` for `system.hostname` from the OOBE's typed call | `oobe-audit.txt` |
| C-4 | The desired value is present in punard's effective document **on `/var`** — i.e. `/etc/hostname` is a materialisation, not the authority | same |
| C-5 | Derivation fixture: `"Preetham's ThinkPad"` → `preethams-thinkpad`, exact `test "$a" = "$b"` | `oobe-derivation.txt` |
| C-6 | Rejection fixture: a device name deriving to an invalid label leaves the hostname field editable and sets nothing | same |

**D · The theme applied**

| # | Assertion | Artifact |
|---|---|---|
| D-1 | `~alice/.config/punar/theme.json` exists, mode `0600`, `active` ∈ the shipped ids, and `punarctl theme status` does not report `MODIFIED SINCE VALIDATED` | `oobe-theme.json` |
| D-2 | Skipping stage 07 in a second fixture yields `paper` | same |
| D-3 | Choosing `contrast` at stage 01 and then skipping stage 07 leaves the pointer at **`contrast`**, not `paper` (§3.1's interaction) | `oobe-theme-contrast.json` |

**E · No dev conveniences remain** — the group this document exists for

| # | Assertion |
|---|---|
| E-1 | `getent passwd punar` → **absent** |
| E-2 | root is locked: the shadow entry's hash field is `!`, `!!` or `*`; `passwd -S root` reports `L` |
| E-3 | `/etc/greetd/config.toml` contains **no** `[initial_session]` stanza (`grep -c` → 0) |
| E-4 | No console autologin drop-in: `getty@tty1.service.d/` and `serial-getty@ttyS0.service.d/` contain no `autologin` unit fragment |
| E-5 | `/etc/subuid` and `/etc/subgid` name `alice`, and do not name `punar` |
| E-6 | The literal string `punar:punar` appears nowhere under `/etc` |
| E-7 | **The A/B property:** with `/etc` reset to vendor content (the check's proxy for a slot swap — stated as a proxy, per §7.3), `getent passwd alice` still resolves and a PAM authentication of alice still succeeds |

**F · Recovery**

| # | Assertion |
|---|---|
| F-1 | A wrong recovery code → refused, rate-limit delay observed, attempt audited |
| F-2 | The audit event for F-1 does **not** contain the code (`grep -c` over the audit artifact → 0) |
| F-3 | The correct code → password reset succeeds and the account authenticates with the new password |
| F-4 | Single-use: a second redeem of the same code → refused |
| F-5 | `recovery.json` contains only a salt, a hash, a counter and a version — the literal code appears nowhere on disk |

**G · Honesty labels**

| # | Assertion |
|---|---|
| G-1 | Every stage that must carry a dashed label does: stage 01's `OTHER LOCALES · NOT IN THIS BUILD`, stage 02's offline line, stage 05's relay `SIMULATED · M12` (or `NOT IN THIS BUILD`), stage 06's `Attestation · SIMULATED · VM`, stage 04's *"registers this device, not who you are"* line (§2.4) |
| G-2 | The captured OOBE stage text contains **no shell command** anywhere (§65's rule, tested as a rule) |

### 7.3 What the check structurally cannot prove

Stated before anyone reads a green run as more than it is:

1. **E-7 is a proxy, not a slot swap.** Resetting `/etc` to vendor content
   demonstrates the same property a swap would, on a VM that has one root
   filesystem today (the A/B layout is ADR-003's, unbuilt). The real
   assertion belongs in the update check's group A once slots exist, and this
   document's §10 checklist says so.
2. **PAM authentication in the check is not the greeter.** The check drives
   PAM directly; it does not prove the QML greeter's field, focus handling or
   failure states. Those are screenshot-set territory (M13 §10.1's pattern).
3. **The password policy is proven against fixtures, not against users.** A
   10-character floor with no composition rules is a defensible policy and an
   untested one; the check proves it is enforced, not that it is right.
4. **Nothing here proves resistance to a local attacker** (§8). The check
   demonstrates the default state of the machine.
5. **`identity.set_password` handling the secret correctly in memory** is
   asserted by design and by code review, not by the check — a shell script
   in a VM cannot observe a QML property tree's zeroing.

---

## 8. Honest limits and refusals

| # | Claim Punar does **not** make | Why |
|---|---|---|
| 01 | That JIT privilege protects you from someone with your password and your machine | They can request, self-approve and elevate exactly as you can. What changes is that they must do so explicitly, once per capability, into an audit log — not that they cannot |
| 02 | That a grant is scoped to a process | punard authorises by **uid**. For the window's duration, any process running as that user can exercise that one capability. Narrow durations are the mitigation and the only one |
| 03 | That the account model resists a local root | It does not, and nothing in userspace does |
| 04 | That refusing weak passwords makes accounts strong | It removes a floor of failure. A 10-character password is not a strong password; it is a password that is not on a list |
| 05 | That the recovery code is recoverable | It is shown once and stored as a hash. Losing it and the disk secret means the data is gone, and §1.8 says so on screen |
| 06 | That enrollment verifies who you are | M5 enrolls a device (`user-blocked.md` item 5). Stage 04 says this on the stage |
| 07 | That the greeter is a security boundary against physical access | It is an authentication surface on top of disk encryption. The encryption is the boundary |
| 08 | That accounts survive an update **today** | They will, by §1.9 and §1.10, on the A/B layout ADR-003 accepted and the installer has not yet built. Until then, assertion E-7 is a proxy |
| 09 | That `sudo` has been removed | It ships with the substrate. Punar authors no rule for it and grants `wheel` to nobody, which is a different and provable statement |
| 10 | That a device with a broken `punard` is recoverable without reinstalling | §1.6.2. Root is locked, nobody is in `wheel`, and every privilege path runs through `punard`. On a **freshly installed** device slot B is zero-filled (`installer.md` I17), so there is no rollback target either, and §1.8 Layer 2 does not exist. Until `punar-recover` ships, this is Layer 3 or nothing — and it is a **worse** recovery story than the dev image this document deletes |
| 11 | That the self-service set (§1.6.1) is a security boundary | It is a **ceremony** decision, not an authority decision. It says which low-risk, self-reversible capabilities a human at their own unmanaged machine may set without an approval card. Someone who is already that uid could have obtained a grant anyway by self-resolving; what changes is how many keystrokes it took, and what the audit event is called |
| 12 | That Punar has a network-configuration story | It does not. No `network.*` capability exists, no polkit policy is authored, and no Wi-Fi manager is in the image. §1.6.1 states the constraint the future design must respect and does not pretend to have designed it |

---

## 9. Open questions and verification spikes

**V1 — `nss-systemd` shadow resolution (§1.10): mechanism verified
2026-08-26; boot ordering remains an implementation gate.** On the pinned
systemd 261.2 / PAM 1.7.2 / libxcrypt 4.5.2 substrate, a test account existed
only as `/run/userdb/punarv1.user` (`0644`) plus the separate
`punarv1.user-privileged` (`0600`) and numeric-UID symlinks. `getent passwd`,
`getent group`, and root's `getent shadow` resolved it through `nss-systemd`;
neither `/etc/passwd` nor `/etc/shadow` contained the account. Starting from
uid 65534, `su`/`pam_unix` accepted the correct password, entered uid/gid
61111, and rejected a wrong password. The same unprivileged process could
resolve the public passwd row but could neither read the privileged companion
nor obtain a shadow row. This follows systemd's documented split-file contract:
the public `.user` record must not contain `privileged`, while the root-only
`.user-privileged` contains that section exclusively.

The preferred `/var` → `/run/userdb` design therefore survives the mechanism
spike; the `/etc` fallback is not selected. The implementation must still prove
that its materializer completes before `systemd-user-sessions` and `greetd` in
the booted production image. Until that ordering assertion passes, V1 is not
fully closed.

**V2 — greetd + QML front-end PAM conversation.** Confirm greetd's PAM
conversation drives a Quickshell client cleanly, including the failure and
retry states D-002 specifies in words.

**V3 — yescrypt parameters: algorithm verified 2026-08-26; target-hardware
timing remains open.** The pinned substrate declares `ENCRYPT_METHOD YESCRYPT`.
Five random-password `chpasswd -c YESCRYPT` samples produced `$y$j9T$` hashes
and averaged 122 ms in the local amd64 container. That is a plumbing result,
not a hardware claim: the container ran through the development machine's
amd64 translation layer. Record the same distribution on the §5.1 minimum
x86_64 target and Raspberry Pi before choosing or overriding the inherited
cost — a login that takes two seconds on an 8 GB laptop is a product defect.

**Open — multi-user.** This design creates one account and does not forbid a
second; `identity.local-account` takes an array. But the greeter ships
single-user (§5.3), and the questions a second account raises (who may create
one, does the creator's grant extend to it, per-user theme and workspace
isolation) are unanswered. Named, not designed.

**Open — joining a network without a ceremony (§1.6.1).** No `network.*`
capability exists, so this document cannot decide it; it can only bind whoever
does. The rule: *on a personal device, joining a Wi-Fi network must not
require an approval card.* Either the capability is `self_service` by
§1.6.1's three-part test, or network selection is a per-user operation that
never reaches punard. Anything else produces a device people route around on
day one, and it is the single most likely place for the JIT posture to
acquire a bad reputation it did not earn.

**Open — the `self_service` registry field (§1.6.1).** It adds one boolean to
`schemas/capability/capability-descriptor.json`, one line to M9 §5.1's human
path, one `details` key to the audit event, and one validator rule (`risk:
high` may never be `self_service: true`). None of that is designed in
`ipc.md` or `milestone-9.md` yet, and both owners have to accept it. If they
decline, §1.6.1's walk stands and the answer has to come from somewhere else —
but the walk itself does not go away.

**Open — password change UI.** `identity.set_password` exists; the surface
that calls it after first boot belongs to System Control and is not designed
here.

**Open — `system.device-name`.** Dashed in §1.5. Ships when something outside
Punar needs `/etc/machine-info`.

**Open — the recovery boot entry.** §1.8 Layer 2 depends on `installer.md`
accepting requirement 5 of §4.4. If it does not, Layer 2 becomes dashed.

---

## 10. Acceptance checklist for the adopting milestone

1. `identity.local-account` backend beside `firewall.rs` / `hostname.rs` /
   `timezone.rs`, with `validate` enforcing §1.3's username rules, §6.3's uid
   ranges and §1.7's last-elevator invariant.
2. The `identity.*` typed methods (§1.11), allocated an `ipc.md` section at
   merge time, with the password never entering desired state, audit, or any
   `punarctl` output.
3. The offline blocklist shipped at
   `/usr/share/punar/identity/common-passwords.txt`.
4. V1 (§9) run **before** the account stage is built, with the result — and
   the branch taken — recorded in this document.
5. Stage 03 built inside M13's OOBE layer, with the four fields, the derived
   hostname consequence line, the permanence line on the username, and the
   recovery code shown exactly once.
6. Stage 01 gains the contrast row; stage 07 gains the two theme cards and
   the §3.1 interaction with contrast.
7. `oobe-answers.json` schema, with `passwordSource` admitting only `"hash"`
   and `"prompt"`.
8. The greeter: greetd + QML front-end, the `/run/punar/greeter.json`
   projection, full name and initials, the recovery entry point.
9. Production image: no `punar` user, root locked, no `[initial_session]`, no
   console autologin, `subuid`/`subgid` for the created user.
10. `onboarding-check.sh`, committed **0755**, offline, no `diffutils`, all
    seven assertion groups, artifacts written.
11. `installer.md` updated to acknowledge §4.4's six requirements, or this
    document updated to record which were declined and what became dashed as
    a result.
12. `platform-sso.md` cross-referenced at the §6.5 seam, naming the same four
    fields.
13. `user-blocked.md` unchanged — this document adds no new blocked item, and
    depends on items 2 and 5 only for claims it does not make.
14. The `self_service` field accepted (or declined) by `ipc.md` and
    `milestone-9.md`, with `risk: high` → `self_service: true` refused at
    registry load, and assertions B-10 → B-12 wired. **If it is declined, §1.6
    is not shippable as written** — the first-hour walk in §1.6.1 is the
    evidence, not an opinion.
15. `installer.md` §6.4 requirement 5 revisited against §1.6.2: either
    `punar-recover` ships in the first release with a locked root, or the
    installer blesses slot B with the same image it wrote to slot A so that a
    fresh device has a rollback target from its first boot.
