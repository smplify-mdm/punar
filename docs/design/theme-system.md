# Punar Theme System — "a theme is a token set, not a reskin"

**Status:** Proposed (2026-08-25) · **Binding on adoption by a milestone** ·
**Parent:** [`DESIGN_LANGUAGE.md`](DESIGN_LANGUAGE.md) (this document adds to it and
amends exactly one line of it — §9.5, recorded in §4.4 below)
**Token contract:** [`shell/theme/punar-tokens.json`](../../shell/theme/punar-tokens.json)
**Wire contract:** [`docs/api/ipc.md`](../api/ipc.md) · **Policy model:** spec §39, §46
**Sibling designs:** [`app-catalog.md`](app-catalog.md) ·
[`execution-trust.md`](execution-trust.md). The three are one product
proposal and share one budget line; the combined arithmetic against spec §6.2
and ADR-003 lives in [`execution-trust.md`](execution-trust.md) §13.3. This
document's share of it is *"two `FileView`s and 14 KB of JSON"*, which is the
strongest reason to ship it first.

> **A theme may change what Punar is made of. It may never change what Punar
> means.**

---

## 0. Claim register (spec §1.22 · design language §7)

Punar's stroke semantics apply to prose too: a solid claim is an operating
path; a dashed claim is a mechanism that is designed but not shipped. Nothing
in this document is implemented today.

| # | Mechanism | Stroke | Where it stands (2026-08-25) |
|---|---|---|---|
| 01 | Token file consumed at runtime by the shell (`Theme.qml`, `FileView`, `blockLoading`) | **solid** | Shipped since M1. `shell/punar-shell/Theme/Theme.qml` already reloads on file change and has typed fallbacks. |
| 02 | Design-language colour semantics (`ok`/`warn`/`bad` = allow / approval_required / deny) | **solid** | Shipped; §2 of the design language, `color.semantics` in the token file. |
| 03 | `themes/` directory, per-theme documents, active pointer | *dashed* | Specified here (§3). No files exist. |
| 04 | `punarctl theme validate` and the contrast gate | *dashed* | Specified here (§4), including the exact arithmetic. No code exists. |
| 05 | The seven shipped themes | *dashed* | Palettes exist as data in §5 and every one of them passes the §4 gate as computed. They are not installed anywhere. |
| 06 | Switching without restart (pointer → `FileView` → repaint) | *dashed* | The mechanism is the one the shell already uses for `status.json`/`alerts.json`; the theme wiring is not written. |
| 07 | Derived terminal / border / background / wallpaper output | *dashed* | Derivations are specified in §7 and were computed for all seven themes. `foot.ini` and `punar-look.conf` still carry hand-transcribed v0 values. |
| 08 | Managed pinning via a desired-state `appearance` block | *dashed* | Schema shape proposed in §8; `schemas/desired-state/desired-state.json` does not model it yet. |
| 09 | An org pin as a *security* control | **never** | Refused by construction. A pinned theme is a configuration control on a user-owned session, and this document says so in §8.3 rather than implying otherwise. |

---

## 1. The argument

**Punar can ship a dozen themes precisely because it refuses to ship a dozen
design languages.**

Omarchy is right about the user need and wrong about the unit. Its themes are
loved because switching is instant, the set is curated, and every theme reaches
every surface at once — terminal, editor, borders, wallpaper. That is a real
product quality, not a toy, and a distro that answers "no themes, we have taste"
cedes it for nothing.

But the naive version of that answer would destroy Punar. Punar's surfaces are
legible because the *grammar* is fixed: tracked mono labels are always labels,
sans statements are always statements, a dashed stroke always means "not shipped
yet", and green always means the policy said allow. A theme that ships its own
type scale, its own radius, its own idea of what amber means is not a theme —
it is a fork of the design language, and after four of them Punar's screens no
longer teach the user anything transferable.

The resolution is to name the unit correctly.

- A **palette** is nineteen colours. It carries mood, warmth, temperature,
  time of day, and personal taste. It is exactly the layer where variety is
  valuable and where variety costs nothing.
- The **grammar** is everything else: type roles and tracking, the 8px spacing
  rhythm, the 10px/6px radii, the motion curve, the meta-row idiom, the
  hairline rules, the stroke semantics, the four-part menubar slot rule, and
  the *meaning* of `ok`/`warn`/`bad`. It is the part a user learns once. It is
  not a preference and it is not shippable per theme.

A Punar theme is therefore a **token set**: nineteen hex values, a name, an
intent line, and a default mood. It is not a stylesheet, it cannot carry code,
it cannot carry a font, and it cannot carry an opinion about what a colour
means.

This is a stronger position than a pile of skins, for three reasons that are
worth stating plainly:

1. **Every theme inherits every future surface.** When M12 draws a new panel,
   it draws in the grammar and consumes tokens, so all seven themes support it
   the day it lands. Skin sets rot; token sets do not.
2. **Themes become checkable.** Because the contract is nineteen values with
   named roles, a machine can prove that a theme is legible before a human
   ever sees it (§4). No distro ships that check today. It is the thing that
   makes "many themes" *safe* rather than merely popular.
3. **The honesty rules survive.** A denial stays red-family, a pending
   approval stays amber-family, an unshipped mechanism stays dashed, and a
   screen with nothing to report still contains no colour — in every theme,
   because none of those are palette decisions.

The rest of this document is that position made exact.

---

## 2. The invariant grammar — what a theme may never define

**A theme is refused, not sanitised, if it touches any of this.** The validator
(§4) rejects unknown keys rather than ignoring them, because silently dropping
a key teaches theme authors that the contract is negotiable.

| Domain | Owner | Why it is not a theme's business |
|---|---|---|
| Font families, fallbacks, licences | `punar-tokens.json` `font.*` | Two OFL families are vendored into the image; a theme cannot reference a font that is not installed, and font choice is a type-role decision (design language §1). |
| Type scale, weights, tracking (`trackingDisplayEm`, `trackingLabelEm`, `labelSizePx`, `metaSizePx`) | `font.*` | The tracked-mono-label idiom *is* the design language. Change it and mastheads stop reading as mastheads. |
| The mono/sans role split | `font.rules` | "Labels and data are mono, statements and prose are sans" — never swapped, never per theme. |
| Radii (`shape.radiusPx` 10, `shape.radiusTagPx` 6), hairline width | `shape.*` | Shape carries the instrument register. A 20px radius is a different product. |
| Motion curve and durations (`motion.*`) | `motion.*` | Spec §13.4: fluid, not decorative. Duration is a perception budget, not a taste. |
| Shadow recipe | `shadow.*` | Warm, restrained, and *derived from the ink base*, not per theme. |
| The **meaning** of `ok` / `warn` / `bad` (`color.semantics`) | `color.semantics` | Green = allow/compliant/active, amber = approval_required/remediating/expiring, red = deny/non_compliant/blocked. Learned once; never lies. A theme picks *which* green — never what green says. |
| The action-colour rule (one coloured button per surface; destructive = ghost) | design language §2 | A button rule, not a colour. |
| Stroke semantics (solid = operating, dashed = outside the production claim) | design language §7 | This is spec §1.22 drawn. A theme cannot dash or undash anything. |
| The meta-row idiom, plate registers, coverage vocabulary | design language §5, §7 | Layout and language. |
| ANSI terminal slots, window-border colours, wallpaper marks, portal colour-scheme | **derived** (§7) | Deriving them is what keeps "the whole system follows the theme" true without letting a theme author invent a fourth semantic colour in the terminal. |

And what a theme **may** define, exhaustively:

| Block | Tokens | Count |
|---|---|---|
| `color.paper` | `surface`, `ink`, `ink2`, `ink3`, `muted`, `raise2`, `border`, `inputBorder`, `status.ok`, `status.warn`, `status.bad` | 11 |
| `color.panel` | `surface`, `fg`, `ink2`, `ink3`, `edge`, `status.ok`, `status.warn`, `status.bad` | 8 |
| `meta` | `id`, `name`, `intent`, `defaultMood` (+ bookkeeping: `version`, `grammar`, `author`) | 4 (+3) |

**Nineteen colours and four strings.** That is the whole surface area.

Two notes on the asymmetry, because it is deliberate:

- **The panel block has no `muted`/`raise2`.** On panel surfaces elevation is
  stated with an edge, not a fill (design language §3: "prefer edges to
  shadows"). There is therefore no text-on-raised-panel pair in the system and
  none is measured in §4.
- **The action colours are not authored.** `color.action.paper.bg` =
  `paper.status.ok`; `.fg` = `paper.surface`; `color.action.panel.bg` =
  `panel.status.ok`; `.fg` = `panel.surface`; `destructive.*` =
  `status.bad` of the same block. Deriving them makes the design language's
  promise structural: the affirmative button is coloured *because it is a
  decision*, using the same green the decision itself uses.

### 2.1 Mood is the second axis, and it is orthogonal

The design language already declares both surface systems first-class (§6:
"a user may run all-panel (dark)"). That preference is now named:

- **`mood: paper`** — shell bar, command center, System Control, approvals, AI
  panel, privacy panel, notifications, greeter render on the theme's `paper`
  block.
- **`mood: panel`** — those same surfaces render on the theme's `panel` block.

What mood never changes: the terminal, code editors, plates/diagnostics and OSD
overlays are **always** panel (design language §6). That is why every theme must
define both blocks even if the user only ever sees one of them: a paper-mood
user still has a panel terminal.

A theme declares `meta.defaultMood`; the user may override it per selection
(`punarctl theme set oxide --mood panel`). Seven shipped entries × two moods =
fourteen coherent looks from six palettes.

---

## 3. The theme contract

### 3.1 Files and layout

`punar-tokens.json` keeps its current role and its current bytes: it is the
**grammar file**, and its `color` block doubles as the **built-in fallback
palette** (identical to the `paper` theme). A system with no `themes/`
directory therefore behaves exactly as the shipped image does today — the
theme system is additive, and its absence is not a failure mode.

```text
shell/theme/
  punar-tokens.json              # grammar + fallback palette (unchanged shape)
  punar-tokens.css               # unchanged; CSS consumers keep the fallback palette
  themes/
    paper.theme.json             # ── the shipped set, one file per theme
    panel.theme.json
    graphite.theme.json
    oxide.theme.json
    nocturne.theme.json
    ember.theme.json
    contrast.theme.json
    default.json                 # ── the shipped pointer: {"active":"paper",...}
```

Installed layout (image pipeline stages `shell/theme/` exactly as it does now):

| Path | Owner | Mode | Role |
|---|---|---|---|
| `/usr/share/punar/theme/punar-tokens.json` | root | `0644` | grammar + fallback palette |
| `/usr/share/punar/theme/themes/*.theme.json` | root | `0644` | shipped themes (read-only) |
| `/usr/share/punar/theme/themes/default.json` | root | `0644` | shipped pointer |
| `/etc/punar/themes/*.theme.json` | root | `0644` | site- or org-delivered themes |
| `/etc/punar/theme.json` | root | `0644` | system pointer — greeter/lock screen (*dashed*, §6.6) |
| `~/.config/punar/themes/*.theme.json` | user | `0600` | user-authored themes |
| `~/.config/punar/theme.json` | user | `0600` | **the user pointer** — the file a switch writes |

### 3.2 A theme document

Strict: `additionalProperties: false` at every level. All nineteen colours are
required. Hex only, `^#[0-9A-F]{6}$`, uppercase, sRGB — no `rgba()`, no `hsl()`,
no alpha (translucency in Punar is a scrim recipe in the grammar, not a token),
no colour names, no references to other tokens.

```json
{
  "$schema": "https://schemas.punar.dev/v1alpha1/theme/theme.json",
  "kind": "PunarTheme",
  "meta": {
    "id": "graphite",
    "name": "Graphite",
    "intent": "The field palette with the warmth taken out — cool neutral greys.",
    "author": "punar",
    "version": "1.0.0",
    "grammar": "0.1.0",
    "defaultMood": "paper"
  },
  "color": {
    "paper": {
      "surface": "#F7F8F9",
      "ink": "#0A0C0E",
      "ink2": "#303439",
      "ink3": "#61666D",
      "muted": "#F0F2F4",
      "raise2": "#E7EAEE",
      "border": "#DEE2E6",
      "inputBorder": "#868C93",
      "status": { "ok": "#1F6B3A", "warn": "#8A5410", "bad": "#A81D33" }
    },
    "panel": {
      "surface": "#0B0D10",
      "fg": "#EFF1F4",
      "ink2": "#A5ABB4",
      "ink3": "#79808B",
      "edge": "#23272E",
      "status": { "ok": "#7FE0A8", "warn": "#F0C48A", "bad": "#FF8095" }
    }
  }
}
```

| Field | Rules |
|---|---|
| `kind` | `const: "PunarTheme"`. |
| `meta.id` | `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`, ≤ 24 chars. Must equal the filename stem. |
| `meta.name` | 1–24 chars. Rendered in the picker in the *sans* face — it is a name, not a label. |
| `meta.intent` | One sentence, ≤ 96 chars, no trailing period rules imposed. Rendered as the picker's second line. Required: a theme that cannot say what it is for does not belong in the set. |
| `meta.version` | semver of the theme itself. |
| `meta.grammar` | the `meta.version` of `punar-tokens.json` this theme was authored against. Drives §9.2 migration. |
| `meta.defaultMood` | `"paper"` \| `"panel"`. |
| `color.*` | The nineteen values above. Missing → refusal naming the token. Extra → refusal naming the key. |

**No inheritance, no cascade, no partial themes.** A theme document is complete
or it is invalid. `paper` and `panel` ship as two complete documents with an
identical `color` block and different `defaultMood` — that duplication is the
point: it demonstrates that mood is orthogonal to palette, and it keeps every
file readable on its own without a resolver in the reader's head.

### 3.3 The pointer

```json
{
  "$schema": "https://schemas.punar.dev/v1alpha1/theme/pointer.json",
  "kind": "PunarThemePointer",
  "active": "graphite",
  "mood": "default",
  "validated": {
    "at": "2026-08-25T11:04:07Z",
    "grammar": "0.1.0",
    "digest": "sha256:5f2c…",
    "minText": 4.79,
    "minNonText": 3.19
  }
}
```

- `mood` ∈ `"default" | "paper" | "panel"`; `"default"` defers to
  `meta.defaultMood`.
- `validated` is the **receipt** of the check that passed at selection time.
  The shell does not re-run the arithmetic (§6.3 keeps the shell dumb and
  cheap); `punarctl theme status` compares the digest to the file on disk and
  reports `MODIFIED SINCE VALIDATED` when a user has hand-edited their own
  theme afterwards. That is a report, not a revocation — on a personal device
  the user owns the file (design language §8), and pretending otherwise would
  be theatre.

### 3.4 Resolution order

The active theme id is the first of:

1. the org pin, when enrolled and pinned (§8);
2. `~/.config/punar/theme.json`;
3. `/etc/punar/theme.json` (system pointer, if present);
4. `/usr/share/punar/theme/themes/default.json` (ships `paper`);
5. the built-in fallback palette compiled into `Theme.qml`.

The theme *document* for that id is the first of `~/.config/punar/themes/`,
`/etc/punar/themes/`, `/usr/share/punar/theme/themes/` — **except** that when
an org pin is in force, or `allowUserThemes` is false, `~/.config/punar/themes/`
is not searched at all. Otherwise an allowlist by id could be defeated by
shadowing a shipped id with a local file, and an allowlist that can be defeated
by a filename should not be advertised as one.

---

## 4. Validation as a feature

**Punar refuses to select a theme it cannot prove is legible, because a theme
that hides a denial is a safety problem, not a taste problem.**

This is the load-bearing part of the design. Contrast is not an accessibility
afterthought in an OS whose surfaces exist to explain restrictions: if
`status.bad` is unreadable on `raise2`, the user does not see *why* something
was blocked. So the gate is not advice and not a lint warning — it sits in the
selection path.

### 4.1 The arithmetic (WCAG 2.1, stated so it can be re-implemented)

For each 8-bit channel `C ∈ {R,G,B}` of an sRGB hex value:

```text
c      = C / 255
c_lin  = c / 12.92                     if c ≤ 0.04045
       = ((c + 0.055) / 1.055) ^ 2.4   otherwise
L      = 0.2126·R_lin + 0.7152·G_lin + 0.0722·B_lin
ratio  = (max(L1,L2) + 0.05) / (min(L1,L2) + 0.05)
```

Comparison is at full double precision; **reporting** is to two decimals. A
pair computing 4.497 fails a 4.5 floor and prints `4.50` alongside the word
`FAIL` — the validator never lets rounding pass a pair.

Hue, saturation and lightness for the status rules are plain HSL over sRGB.
Perceptual separation uses CIE ΔE*76 over CIELAB with a D65 white point
(`Xn,Yn,Zn = 0.95047, 1.0, 1.08883`); chroma is `C* = √(a*² + b*²)`.

All of it is integer-and-float arithmetic over local files: **no network, no
fonts, no display, no daemon**. It runs in the CI VM offline, which is a hard
constraint here, and it runs in ~1 ms per theme.

### 4.2 The measured pairs and their floors

Twenty-four pairs per theme. The list is part of the contract: a first-party
surface that introduces a new text-on-fill combination must add its pair here
in the same change.

| # | Pair | Floor | Why that floor |
|---|---|---|---|
| 1 | paper · `ink` on `surface` | **7.0:1** | The ink is the system's anchor mark — display type, assertions, primary buttons, focus rings. AAA, deliberately above AA. |
| 2 | paper · `ink` on `raise2` | 7.0:1 | Same role, on a raised card. |
| 3 | paper · `ink2` on `surface` | **4.5:1** | Body prose, 16px regular — WCAG 2.1 AA normal text. |
| 4 | paper · `ink2` on `muted` | 4.5:1 | Body in a code/quote block. |
| 5 | paper · `ink3` on `surface` | **4.5:1** | Tracked mono labels and meta rows — see §4.3. |
| 6 | paper · `ink3` on `muted` | 4.5:1 | Labels on the first raise. |
| 7 | paper · `ink3` on `raise2` | 4.5:1 | Labels on the second raise — in practice the tightest pair in the whole system. |
| 8–13 | paper · `status.{ok,warn,bad}` on `surface` and on `raise2` | 4.5:1 | Status words are text; the approval card puts them on a raised fill. |
| 14 | paper · action `fg` on action `bg` (= `surface` on `status.ok`) | 4.5:1 | The one filled affirmative button. |
| 15 | paper · `inputBorder` on `surface` | **3.0:1** | WCAG 2.1 §1.4.11 non-text contrast: an input boundary is a UI component boundary. |
| 16 | paper · focus ring (`ink`) on `surface` | 3.0:1 | §1.4.11 again; keyboard operability is spec §12. |
| 17 | panel · `fg` on `surface` | 7.0:1 | Anchor mark, panel side. |
| 18 | panel · `ink2` on `surface` | 4.5:1 | Panel body. |
| 19 | panel · `ink3` on `surface` | 4.5:1 | Panel labels/meta. |
| 20–22 | panel · `status.{ok,warn,bad}` on `surface` | 4.5:1 | Status words on panel. |
| 23 | panel · action `fg` on action `bg` | 4.5:1 | Panel affirmative button. |
| 24 | panel · focus ring (`fg`) on `surface` | 3.0:1 | §1.4.11. |

Non-pair rules, all refusals:

| Rule | Test | Rationale |
|---|---|---|
| **R1 shape** | required keys present, no unknown keys, `kind`/`id` correct | A theme that tries to set `font`, `shape`, `motion`, `terminal` or `semantics` is refused naming the key — §2 enforced, not requested. |
| **R2 format** | `^#[0-9A-F]{6}$` | No alpha, no functions, no references. |
| **R3 contrast** | the 24 pairs above | §4.2. |
| **R4 status hue windows** | `ok` ∈ [70°,170°), `warn` ∈ [20°,70°), `bad` ∈ [330°,360°)∪[0°,20°); saturation ≥ 25% for all three, on both blocks | This is the semantic promise made checkable. A theme may pick any green; it may not make "allow" blue, and it may not grey a status out until it stops reading as a decision. |
| **R5 status separation** | pairwise ΔE*76 ≥ 25 between `ok`/`warn`/`bad`; ≥ 20 between each status and `ink3` of the same block | Three statuses must be told apart at a glance, and a status word must not read as a label. |
| **R6 neutral chroma cap** | `C* ≤ 14` for every non-status token in both blocks | "Near-monochrome by default" (design language §2) as a number. Warm paper (`#FAF9F6`, C* 1.6) and the warmest shipped neutral (`ember` `ink3`, C* 12.1) both fit; a lilac "surface" does not. |
| **R7 elevation order** | `contrast(raise2, surface) ≥ contrast(muted, surface)`; both **strictly less than** `contrast(border, surface)`; `contrast(border, surface) ≥ 1.15`; `contrast(panel.edge, panel.surface) ≥ 1.15` | Raises must stack in the right direction, hairlines must be visible, and the wallpaper marks (derived from `muted`/`raise2`, §7.3) must stay quieter than a window border — the rule Plate D-015 already states, now enforced. |
| **R8 derived terminal legibility** | every derived ANSI slot 1–15 ≥ 4.5:1 on `panel.surface` | Slot 0 (`black` = `panel.edge`) is exempt: it is the structural/dim slot by terminal convention, which is exactly why it is bound to the edge token. |
| **R9 grammar compatibility** | `meta.grammar` MAJOR equals the installed grammar MAJOR | §9.2. |

### 4.3 The rule for the tracked mono labels

The labels are the hard case: Geist Mono 500, **10–12px**, uppercase, +0.12em.
They are small text, and there is a temptation to claim the WCAG "large text"
exemption because tracking and uppercase make them look airier.

**Punar claims no exemption.** The floor for `ink3` is 4.5:1, the same as body
prose. Tracking increases letter separation; it does not increase luminance
contrast, and WCAG grants no credit for it. Inventing a credit would be exactly
the kind of unearned claim §1.22 exists to prevent.

What Punar does instead is fix the *other* variables in the grammar, where a
theme cannot reach:

1. label weight ≥ 500 (never 400 mono at 10px);
2. label size ≥ 10px, and the 10px size is reserved for meta rows — section
   headers are 12px;
3. `ink3` is a **label and meta** role only. Prose never uses it. A theme that
   wants quieter labels must move `ink3` *darker*, because the floor binds from
   below and there is nowhere else to go.

Consequence for theme authors, stated once so it is not discovered by failure:
on a light surface `ink3` lands around `#5E–#6E` grey; on a dark surface around
`#75–#AB`. There is no legible theme with pale-grey labels on white, and the
validator will say so by name.

### 4.4 One amendment to the design language

`DESIGN_LANGUAGE.md` §9.5 read "panel-ink-3 reserved for ≥14px labels".
Measured, `#7B8290` on `#08090A` is **5.16:1** — it clears AA for small text at
any size. That caveat was written before the ratio was computed. This document
replaces it with the numeric floor in §4.2 (pair 19), which is stricter in the
general case (it binds *every* theme, not just the shipped one) and honest in
this one.

**Applied 2026-08-25.** `DESIGN_LANGUAGE.md` §9.5 now carries the measured
ratio and cites §4.2–§4.4 here, so the binding document and this one no longer
disagree. A design document that claims to amend a binding document, while the
binding document still says the old thing, is a contradiction with a date on
it — the amendment is made or it is not proposed.

### 4.5 The validator, as a command

`punarctl theme …` — client-side only. No new IPC method, no daemon round-trip,
no audit event (see §6.1 for why).

| Verb | Behaviour | Exit |
|---|---|---|
| `punarctl theme list` | D-014 table: `ID · NAME · MOOD · SOURCE · MIN TEXT · STATE`. State ∈ `OK` / `REVALIDATE` / `DERIVED n` / `DENIED BY POLICY`. | 0 |
| `punarctl theme show <id>` | Full palette, then all 24 measured pairs with ratios and floors, then the derived outputs (§7). `--json` prints the machine record. | 0 |
| `punarctl theme validate <id\|path>` | Runs R1–R9 and prints every failing rule. `--json` emits `{"pass":false,"failures":[{"rule":"R3","pair":"paper · ink3 on raise2","fg":"#8A8A8A","bg":"#EDEAE2","measured":3.24,"floor":4.5}]}`. | 0 pass / **6** fail |
| `punarctl theme set <id> [--mood paper\|panel]` | validate → refuse or write the pointer atomically → return. | 0 / 6 refused / **3** denied by policy |
| `punarctl theme reset` | Drops the user pointer; resolution falls through to the system/shipped pointer. | 0 |
| `punarctl theme status` | Active id, mood, source of the decision (`user preference` / `<org policy id>`), and `MODIFIED SINCE VALIDATED` when the digest no longer matches. | 0 |
| `punarctl theme render <id> --target foot\|hypr\|wallpaper\|portal [--out PATH]` | Prints or writes a derived artefact (§7). Exists so the derivations are inspectable, and so the CI check can diff them. | 0 |

Exit codes extend the D-014 set additively: `0` success · `1` runtime · `2`
usage · `3` denied · `4` approval_required · `5` daemon unreachable · **`6`
theme refused (contract or contrast failure)**. `6` is new and is reserved
here; it is deliberately *not* `3`, because a refusal is not an authorization
decision and must not be read as one by a script.

### 4.6 The refusal, in the §73 voice

```text
PUNAR · THEME                                            REFUSED · MOSS
────────────────────────────────────────────────────────────────────────
moss does not meet the contrast floor. It was not selected; the active
theme is unchanged.

  RULE  PAIR                            MEASURED   FLOOR
  R3    paper · ink3 on raise2            3.24:1   4.50:1
  R3    paper · status.warn on raise2     3.98:1   4.50:1
  R4    panel · status.ok hue 208°        —        70°–170°

Two of 24 measured pairs fail, and the panel "ok" colour is blue, which
would make an allowed action look like information.

Punar refuses themes whose text cannot be read or whose status colours do
not mean what they say, because these surfaces exist to explain
restrictions — a theme that hides a denial is a safety problem, not a
taste problem.

Policy: theme contract — docs/design/theme-system.md §4 (not an
organization policy; this floor applies on every Punar device).
Next step: darken paper.ink3 to #5F5F5F or darker, darken
paper.status.warn to #7E5200 or darker, and move panel.status.ok into the
green window. Then:
  punarctl theme validate ~/.config/punar/themes/moss.theme.json --json
```

Note what the message does: names the failing pair, gives the measured and
required numbers, names the *fix* in the same units as the input, cites the
rule's home, and — because this is a personal device — explicitly says the
floor is not an organization's doing. That last line is design language §8: on
an unmanaged device, authority still has a named source, and the source here is
the OS itself.

### 4.7 CI

A check (`theme-check`, alongside the existing per-milestone checks) runs, offline:

1. every shipped theme passes R1–R9;
2. every shipped theme's *derived* artefacts (§7) regenerate byte-identically
   to what is staged in the image — so a hand-edited `foot.ini` cannot drift
   from the tokens;
3. `paper`'s palette is byte-identical to the `color` block of
   `punar-tokens.json` — the fallback and the default may never disagree;
4. the pair list in this document has the same length as the validator's
   (24) — the spec and the code fail together or not at all.

---

## 5. The shipped set

Six palettes, seven entries, every one passing §4 as computed on 2026-08-25.
`paper` and `panel` are the field palette at its two moods; the other five are
distinct palettes.

| id | Name | Intent | Default mood |
|---|---|---|---|
| `paper` | **Field Paper** | The reference palette: warm paper, black ink, panel terminal. | paper |
| `panel` | **Field Panel** | The same palette with every shell surface on panel — the all-dark desk. | panel |
| `graphite` | **Graphite** | The field palette with the warmth taken out — cool neutral greys for anyone who reads warm paper as yellow. | paper |
| `oxide` | **Oxide** | Drafting linen: older paper, ink-brown panel, the archival mood. | paper |
| `nocturne` | **Nocturne** | Blue-black night with cool inks — the low-light desk. | panel |
| `ember` | **Ember** | Warm and low-blue-light: amber-tinted ink on near-black, for late sessions. | panel |
| `contrast` | **High Contrast** | Accessibility first: every text pair ≥ 7.5:1, every non-text pair ≥ 7:1, pure black and white grounds. | paper |

### 5.1 `color.paper` — all seven

| theme | surface | ink | ink2 | ink3 | muted | raise2 | border | inputBorder | ok | warn | bad |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `paper` | `#FAF9F6` | `#000000` | `#333333` | `#666666` | `#F4F2EC` | `#EDEAE2` | `#E6E4DE` | `#8C8880` | `#2E6B21` | `#8A5A00` | `#A31F2C` |
| `panel` | `#FAF9F6` | `#000000` | `#333333` | `#666666` | `#F4F2EC` | `#EDEAE2` | `#E6E4DE` | `#8C8880` | `#2E6B21` | `#8A5A00` | `#A31F2C` |
| `graphite` | `#F7F8F9` | `#0A0C0E` | `#303439` | `#61666D` | `#F0F2F4` | `#E7EAEE` | `#DEE2E6` | `#868C93` | `#1F6B3A` | `#8A5410` | `#A81D33` |
| `oxide` | `#F6F1E5` | `#17130C` | `#3A3226` | `#6B6153` | `#F0EADB` | `#E8E0CD` | `#DFD6C0` | `#8E8474` | `#3D6B1E` | `#8A5200` | `#A32222` |
| `nocturne` | `#F4F6FA` | `#0A0E17` | `#2E3542` | `#5E6675` | `#EDF0F6` | `#E3E8F1` | `#D9DFEA` | `#848B99` | `#1F6B4A` | `#845600` | `#A31F3C` |
| `ember` | `#FBF4E9` | `#1A1208` | `#3C3225` | `#6E6250` | `#F5EDDF` | `#EEE4D2` | `#E5DAC5` | `#918676` | `#456B14` | `#8A5000` | `#A32418` |
| `contrast` | `#FFFFFF` | `#000000` | `#141414` | `#303030` | `#F5F5F5` | `#EAEAEA` | `#B0B0B0` | `#595959` | `#0F5219` | `#5E3A00` | `#960014` |

### 5.2 `color.panel` — all seven

| theme | surface | fg | ink2 | ink3 | edge | ok | warn | bad |
|---|---|---|---|---|---|---|---|---|
| `paper` | `#08090A` | `#F2F3F5` | `#A8ADB6` | `#7B8290` | `#26282E` | `#A3E047` | `#F2BE85` | `#FF7A7A` |
| `panel` | `#08090A` | `#F2F3F5` | `#A8ADB6` | `#7B8290` | `#26282E` | `#A3E047` | `#F2BE85` | `#FF7A7A` |
| `graphite` | `#0B0D10` | `#EFF1F4` | `#A5ABB4` | `#79808B` | `#23272E` | `#7FE0A8` | `#F0C48A` | `#FF8095` |
| `oxide` | `#12100D` | `#F3EFE6` | `#B0A895` | `#847C6C` | `#2B2721` | `#B4DC5A` | `#EFC183` | `#FF8A80` |
| `nocturne` | `#070A10` | `#E8EDF5` | `#A2ABBC` | `#757F92` | `#1E2430` | `#79E0B0` | `#EDC183` | `#FF8098` |
| `ember` | `#0E0A08` | `#F5EDE4` | `#B7ABA0` | `#8A7F74` | `#2B2320` | `#B7D24A` | `#F0BE7C` | `#FF8A75` |
| `contrast` | `#000000` | `#FFFFFF` | `#D6D6D6` | `#ABABAB` | `#6E6E6E` | `#6BE86B` | `#FFC14D` | `#FF8F8F` |

### 5.3 Measured result (validator output, 2026-08-25)

| theme | min text pair | min non-text pair | pairs | R4 hues (paper ok/warn/bad) | R5 min ΔE | R6 max C* | fails |
|---|---|---|---|---|---|---|---|
| `paper` | 4.78:1 | 3.35:1 | 24 | 109° / 39° / 354° | 43 | 8.4 | **0** |
| `panel` | 4.78:1 | 3.35:1 | 24 | 109° / 39° / 354° | 43 | 8.4 | **0** |
| `graphite` | 4.79:1 | 3.19:1 | 24 | 141° / 33° / 351° | 43 | 6.8 | **0** |
| `oxide` | 4.60:1 | 3.27:1 | 24 | 96° / 36° / 0° | 37 | 12.0 | **0** |
| `nocturne` | 4.70:1 | 3.16:1 | 24 | 154° / 39° / 347° | 51 | 11.5 | **0** |
| `ember` | 4.73:1 | 3.27:1 | 24 | 86° / 35° / 5° | 33 | 12.1 | **0** |
| `contrast` | **7.57:1** | **7.00:1** | 24 | 129° / 37° / 352° | 43 | 0.0 | **0** |

The tightest pair in the whole set is `paper · ink3 on raise2` (a tracked mono
label on a second-elevation card) — 4.78:1 in the default theme, 4.60:1 in
`oxide`. That is the pair theme authors will fail first, and it is why §4.3
tells them where `ink3` has to live.

### 5.4 Every measured pair, for the default theme

| pair | fg | bg | measured | floor |
|---|---|---|---|---|
| paper · ink on surface | `#000000` | `#FAF9F6` | 19.95:1 | 7.0:1 |
| paper · ink2 on surface | `#333333` | `#FAF9F6` | 12.00:1 | 4.5:1 |
| paper · ink3 on surface | `#666666` | `#FAF9F6` | 5.45:1 | 4.5:1 |
| paper · ink2 on muted | `#333333` | `#F4F2EC` | 11.29:1 | 4.5:1 |
| paper · ink3 on muted | `#666666` | `#F4F2EC` | 5.13:1 | 4.5:1 |
| paper · ink3 on raise2 | `#666666` | `#EDEAE2` | 4.78:1 | 4.5:1 |
| paper · ink on raise2 | `#000000` | `#EDEAE2` | 17.47:1 | 7.0:1 |
| paper · status.ok on surface | `#2E6B21` | `#FAF9F6` | 6.15:1 | 4.5:1 |
| paper · status.ok on raise2 | `#2E6B21` | `#EDEAE2` | 5.39:1 | 4.5:1 |
| paper · status.warn on surface | `#8A5A00` | `#FAF9F6` | 5.63:1 | 4.5:1 |
| paper · status.warn on raise2 | `#8A5A00` | `#EDEAE2` | 4.93:1 | 4.5:1 |
| paper · status.bad on surface | `#A31F2C` | `#FAF9F6` | 7.15:1 | 4.5:1 |
| paper · status.bad on raise2 | `#A31F2C` | `#EDEAE2` | 6.26:1 | 4.5:1 |
| paper · action fg on action bg | `#FAF9F6` | `#2E6B21` | 6.15:1 | 4.5:1 |
| paper · inputBorder on surface | `#8C8880` | `#FAF9F6` | 3.35:1 | 3.0:1 |
| paper · focus ring on surface | `#000000` | `#FAF9F6` | 19.95:1 | 3.0:1 |
| panel · fg on surface | `#F2F3F5` | `#08090A` | 17.95:1 | 7.0:1 |
| panel · ink2 on surface | `#A8ADB6` | `#08090A` | 8.84:1 | 4.5:1 |
| panel · ink3 on surface | `#7B8290` | `#08090A` | 5.16:1 | 4.5:1 |
| panel · status.ok on surface | `#A3E047` | `#08090A` | 12.63:1 | 4.5:1 |
| panel · status.warn on surface | `#F2BE85` | `#08090A` | 11.84:1 | 4.5:1 |
| panel · status.bad on surface | `#FF7A7A` | `#08090A` | 7.89:1 | 4.5:1 |
| panel · action fg on action bg | `#08090A` | `#A3E047` | 12.63:1 | 4.5:1 |
| panel · focus ring on surface | `#F2F3F5` | `#08090A` | 17.95:1 | 3.0:1 |

### 5.5 The default is `paper`, and why

1. **It is what the system already is.** The `color` block of
   `punar-tokens.json` is this palette; every mockup (D-001…D-016), every
   plate, and the installed `foot.ini` and `punar-look.conf` were drawn
   against it. Making anything else the default would silently restyle a
   system that people have already seen.
2. **It has the highest anchor contrast in the set** — 19.95:1 ink on surface.
   The default should be the one that asks the least of the display.
3. **Unmanaged-first means the default must assert the least** (design
   language §8). Warm paper with no status colour on it is the calmest ground
   Punar has; a dark default reads as a statement about the user's taste that
   the OS has not earned.

`contrast` is not the default. A high-contrast theme is a genuine accessibility
answer, not a better everyday one — pure white grounds are fatiguing for long
reading, and defaulting to it would be choosing on the user's behalf. It is one
row in the picker, one `punarctl theme set contrast` away, and it is where the
system points anyone who reports that labels are hard to read.

---

## 6. Switching

### 6.1 Selection is a user preference, not a typed capability

**Decided: no new mutating typed capability.** Theme *selection* writes one
user-owned file. Theme *constraint* is a policy path in the merge punard
already computes (§8), exposed read-only through the existing
`policy.effective` / `policy.explain`.

Argued against §39's layered model, because this is exactly the kind of call
that model exists to make:

1. **§39 is about which value wins, not about who executes.** Its ladder ranks
   *sources*. A path can be ranked and explained without its write side being
   privileged. `ui.theme` sits in the ladder at rank 5 (`local_user_preference`)
   on a personal device and is outranked by rank 2 when an org pins it — same
   merge, same `policy.explain` output, no new machinery.
2. **Typed capabilities exist to keep privileged operations narrow and
   audited** (spec §60). `capabilities.set` is root-only. Modelling a palette
   as one would mean `sudo` — or a JIT grant with a written reason (§48) — to
   change your colours. That is absurd on its face, and worse, it would push
   users to edit the pointer file directly, defeating the validation gate that
   is the entire point. A gate people route around is not a gate.
3. **The audit log is for consequential acts** (spec §53). A live preview that
   moves through seven themes would emit seven audit events per keypress
   session. Filling the record that exists to show who approved what with
   colour changes degrades the only artefact the security story depends on.
4. **The RSS and idle-CPU budgets get nothing back for the cost.** No new
   daemon, no new socket, no new resident state; the shell gains two inotify
   watches and ~1.5 KB of parsed JSON. The combined daemon RSS gate (spec §6.2,
   under 100 MB, currently ~4 MB) is untouched, and idle CPU stays at zero
   because nothing polls.
5. **Honesty forbids the implied claim.** A typed, audited capability would
   suggest that a pinned theme is *enforced*. It is not and cannot be: the
   session belongs to the user (§8), who can run any compositor config they
   like. Building enforcement-shaped machinery around a non-enforceable
   control is precisely the §1.22 failure mode.

One additive contract change follows from point 5, and it is worth having:
`policy.effective` / `policy.explain` entries gain an optional
`"enforcement": "enforced" | "advisory"` field (absent ⇒ `"enforced"`, so every
existing path is unchanged). `ui.theme` is the first `advisory` path. This makes
"we merge and explain this, and we do not enforce it" a structural statement
rather than a footnote — and `punarctl policy explain ui.theme` prints it:

```text
Effective     graphite
Source        Acme Engineering Baseline (eng-baseline-v12)
Override      Not permitted
Enforcement   Advisory — Punar applies this and reports it, but the session
              is yours; this is a configuration control, not a boundary.
```

### 6.2 What happens on `theme set`

```text
punarctl theme set nocturne
  1  resolve nocturne through the §3.4 search path
  2  validate R1–R9                       → refuse (exit 6) and stop, or
  3  check the org pin, if enrolled        → deny (exit 3) and stop, or
  4  write ~/.config/punar/theme.json atomically (tmp + rename, 0600)
  5  render the derived artefacts (§7) into the user's config
  6  hyprctl reload   (one shot; not a daemon, not a loop)
  7  print the D-014 verdict line
```

Steps 1–4 take under a millisecond of arithmetic and one small write. Nothing
in the sequence contacts a daemon, so it works identically on an unenrolled
laptop with no network — which is also why it works in the CI VM.

### 6.3 How surfaces update without restart

The mechanism already exists and is the one the shell uses for `status.json`,
`agents.json`, `ledger.json` and `alerts.json`: `FileView` over inotify,
event-driven, **no polling** (spec §6.3).

`Theme.qml` today holds one `FileView` on the grammar file and a `tok()`
accessor whose every derived `readonly property` re-evaluates when
`root.tokens` changes. Theming adds:

```text
FileView  ~/.config/punar/theme.json          → pointer  (active id + mood)
FileView  <resolved>/<id>.theme.json          → palette  (19 colours)
FileView  /run/punar/status.json  (existing)  → appearance block, if enrolled
```

and changes `tok()` to read the palette first and the grammar's `color` block
as fallback. Because every consumer already binds through `Theme.*`, a pointer
change repaints every surface in the session — bar, command center, approval
overlay, AI panel, notifications — with **no restart, no relaunch, and no
re-instantiation of any surface**. Target: under one frame (16 ms) from
inotify event to repaint; the parse is ~1.4 KB of JSON.

Three deliberate refusals in the visual behaviour:

- **The swap is instant. No crossfade.** Motion in Punar explains a change in
  *system state* (design language §4). A theme change is the observer changing
  their mind; animating it would be decoration, and decoration is the one thing
  the motion rule forbids.
- **No per-surface theming.** There is no "dark terminal, light editor"
  matrix beyond the mood switch. One theme, one mood, whole session.
- **No automatic time-of-day switching in this design.** It is an obvious
  future (`mood: "auto"` is reserved in the pointer schema for it) but it needs
  a clock source and a location story, and adding a timer to a system whose
  idle CPU budget is ~0 requires its own argument. Reserved, not shipped —
  and therefore drawn dashed in the picker's footer.

### 6.4 The command-center action

`SUPER+Space` → type `theme` → the picker is a normal command-center result
set, not a special panel:

```text
PUNAR · COMMAND                                          THEME · 7 AVAILABLE
────────────────────────────────────────────────────────────────────────────
> theme

  ▸ FIELD PAPER            paper   ▪▪▪ ▪▪▪   The reference palette: warm
    active                                    paper, black ink, panel terminal.

    GRAPHITE               paper   ▪▪▪ ▪▪▪   The field palette with the warmth
                                              taken out — cool neutral greys.

    OXIDE                  paper   ▪▪▪ ▪▪▪   Drafting linen: older paper,
                                              ink-brown panel.

    NOCTURNE               panel   ▪▪▪ ▪▪▪   Blue-black night with cool inks.

    EMBER                  panel   ▪▪▪ ▪▪▪   Warm, low-blue-light: amber ink
                                              on near-black.

    HIGH CONTRAST          paper   ▪▪▪ ▪▪▪   Every text pair ≥ 7.5:1.
                                              MIN TEXT 7.57:1

╌╌ TIME-OF-DAY SWITCHING · NOT SHIPPED ╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌
  ↑↓ move · M mood · ⏎ apply · esc cancel        VALIDATED · 24/24 PAIRS
```

Anatomy, all of it grammar you have already seen:

- Masthead meta row, middle dot, right-aligned count; closed by a rule.
- Theme names in **tracked mono** in the list (they are labels here), intents
  in **sans** (they are prose) — the mono/sans split does not bend for a
  picker.
- The swatch triad is the theme's `surface`/`ink`/`ink3` followed by its
  `ok`/`warn`/`bad`: exactly what the theme controls, in the order the contract
  lists it. It is the only place in the shell where colour appears without a
  status meaning, and it is legitimate because here the colour *is* the datum.
- The `MIN TEXT` figure prints only when it exceeds the floor materially
  (`contrast`), because a number that is always the same is noise.
- The footer strip is **dashed** — the unshipped time-of-day feature named
  honestly in the surface that would host it (design language §7).
- Under an org pin, the row set is filtered and one appended meta line reads
  `PINNED · ACME ENGINEERING BASELINE (eng-baseline-v12)`. On a personal
  device that line does not exist — no "your organization could restrict
  this", no upsell (design language §8).

**Live preview:** moving the highlight sets an in-memory override in
`Theme` and repaints the session immediately. It writes nothing. `esc` clears
the override and the previous look returns; `⏎` runs the real
`punarctl theme set`, and the resulting pointer change makes the preview
permanent through the ordinary `FileView` path. Preview is free; commitment
goes through the gate.

### 6.5 The keyboard path

**No new global chord.** `SUPER` chords are a scarce, curated resource
(`docs/development/keyboard-grammar.md`) and a palette switch has not earned
one; the command center is the universal path and is one keystroke away
already. Within the picker: `↑`/`↓` move, `M` toggles the previewed mood, `⏎`
applies, `esc` cancels. From a terminal, `punarctl theme set <id>` does the
same thing with the same validation. Two paths, one gate, same voice — spec
§10's "same capability layer, same voice" applied to a preference.

### 6.6 The greeter and lock screen (*dashed*)

The greeter runs before login, as another user, so it cannot read
`~/.config/punar/theme.json`. It reads the **system pointer**
`/etc/punar/theme.json`, written by `sudo punarctl theme set <id> --system`.
That is an ordinary root-owned config file written by root — not an IPC method,
not a capability, and specifically not a generic root RPC (spec §60): punarctl
is running *as* root at that point, and no daemon is asked to act on anyone's
behalf. Deferred: the value of matching the greeter to the desktop is real but
small, and it can land after the session path works.

---

## 7. Scope — everything follows the theme, and nothing is authored twice

**A theme author writes nineteen colours. Everything else in the system is
computed from them.** This is what makes "the whole desktop changes" true
without letting seven authors invent seven terminal palettes.

`punarctl theme render` produces each artefact; `theme set` writes them; the CI
check regenerates and diffs them.

### 7.1 Terminal palette (foot)

| Slot | Derivation |
|---|---|
| `background` | `panel.surface` |
| `foreground` | `panel.fg` |
| `cursor` | `panel.surface` under `panel.status.ok` (text-under-cursor, then block) |
| `regular0` black | `panel.edge` — structural/dim slot, exempt from R8 |
| `regular1` red | `panel.status.bad` |
| `regular2` green | `panel.status.ok` |
| `regular3` yellow | `panel.status.warn` |
| `regular4/5/6` blue/magenta/cyan | `LCh(L* = L*(panel.ink2), C* = 18, h = 271° / 302° / 214°)` → sRGB, gamut-clamped |
| `regular7` white | `panel.fg` |
| `bright0` | `panel.ink3` |
| `bright1…6` | `mix_sRGB(regular_n, panel.fg, 0.28)` |
| `bright7` | `#FFFFFF` |

The three non-semantic slots are hue rotations at fixed chroma around the
theme's own secondary ink, which is how the scheme stays near-monochrome with a
single accent in *every* theme rather than only in the one that was hand-tuned.
`punar-tokens.json` already labels its `terminal` block "v0 draft — pending
Milestone 1 tuning"; this derivation **is** that tuning, and it supersedes the
draft. Derived for the default theme:

| slot | derived | v0 draft | Δ |
|---|---|---|---|
| blue | `#9BAECD` | `#8FA3C4` | rotated/rechromatised |
| magenta | `#B1A8C8` | `#B0A8C4` | ~1 |
| cyan | `#81B5BE` | `#8FBCC4` | rotated/rechromatised |
| brightRed | `#FB9C9C` | `#FF9B9B` | ~4 |
| brightGreen | `#B9E578` | `#BCEA75` | ~5 |
| brightYellow | `#F2CDA4` | `#F7D2A8` | ~5 |

Minimum ANSI legibility across the shipped set (R8, slots 1–15 on
`panel.surface`): `paper` 5.16:1 · `graphite` 4.89:1 · `oxide` 4.60:1 ·
`nocturne` 4.91:1 · `ember` 5.04:1 · `contrast` 9.14:1.

This derivation **is** the "v0 draft, pending M1 tuning" that
`DESIGN_LANGUAGE.md` §6 promised, and §6 now points here for it.

Delivery: `~/.config/foot/foot.ini`, generated. foot loads the *first* config it
finds and a user file fully replaces the system one, so the generated file is
complete, carries a `# generated by punarctl theme — do not edit` header, and
is regenerated from the same template on every switch. **Honest limit:** already
running terminals keep the palette they started with unless foot re-reads its
config on a signal; whether foot 1.27 does so is *unverified here* and must be
confirmed at implementation. Until it is, the contract says only what is true —
new terminals carry the new palette.

### 7.2 Window borders, groupbar and desktop background (Hyprland)

Compositor configs cannot read JSON, so `punar-look.conf` is already the
project's one permitted transcription layer. Theming adds a *generated* sibling
sourced after it, `~/.config/hypr/punar-theme.conf`, containing only the values
that vary:

| Hyprland key | Derivation (`M` = the active mood's block) |
|---|---|
| `general:col.active_border` | `M.ink` (paper) / `M.fg` (panel) — the strongest mark the mood has. Focus is stated with contrast, never with hue. |
| `general:col.inactive_border` | `panel.edge` — the quiet instrument edge, on either mood |
| `group:col.border_active` / `_inactive` | same two values |
| `group:col.border_locked_active` | `M.ink2` — locking is quieter ink, never a status hue |
| `groupbar:text_color` | `M.ink` / `M.fg` |
| `groupbar:text_color_inactive` | `M.ink3` |
| `groupbar:col.active` (indicator) | `M.ink` / `M.fg` |
| `groupbar:col.inactive` | `M.border` (paper) / `M.edge` (panel) |
| `misc:background_color` | `M.surface` |

`border_size`, `rounding`, gaps, bezier and animation timings are **not**
generated — they are grammar (§2) and stay in `punar-look.conf`. Applied with a
single `hyprctl reload` at switch time; no watcher, no daemon, no per-frame
cost. **`TO VERIFY`:** that `hyprctl reload` re-reads a `source`d sibling file
and re-colours already-mapped windows without a restart. It is expected to —
`reload` re-parses the whole config chain — but the acceptance checklist item 5
must assert it rather than assume it, and it is the same class of unverified
claim as the `foot` reload question above.

### 7.3 Wallpaper — the two variants

`docs/design/assets/punar-wallpaper-{paper,panel}.svg` are token-only drawings
that use exactly three colours each: field, hairline, emphasis. They become
templates with three substitutions:

| Variant | field | hairline | emphasis |
|---|---|---|---|
| paper | `paper.surface` | `paper.muted` | `paper.raise2` |
| panel | `panel.surface` | `mix(panel.surface, panel.edge, 0.55)` | `panel.edge` |

Everything else in those files — the 1600×1000 viewBox, the dial at (1152, 500),
radius 208, the overscanned flat field that makes letterboxing invisible, the
60-slot Morse rim — is geometry, and geometry is grammar. A theme cannot move
the dial.

The R7 rule exists for exactly this asset: the watermark marks must stay
strictly quieter than a window border, so the wallpaper never competes with the
one hairline that carries meaning. Measured on the shipped set (paper variant,
`muted` / `raise2` / `border` contrast against the field):

| theme | muted | raise2 | border (must exceed both) |
|---|---|---|---|
| `paper` | 1.063 | 1.142 | **1.208** |
| `graphite` | 1.055 | 1.135 | **1.225** |
| `oxide` | 1.065 | 1.166 | **1.283** |
| `nocturne` | 1.055 | 1.136 | **1.237** |
| `ember` | 1.064 | 1.153 | **1.267** |
| `contrast` | 1.119 | 1.271 | **2.169** |

**Historical limit, superseded by `wallpapers.md`:** Punar still ships no
wallpaper daemon, but the existing shell now owns one background layer and a
finite static catalog. The derivation above remains live for the Field vector
and for the deliberate flat-colour failure mode. Raster choices do not change
theme grammar and only the active asset is decoded.

### 7.4 Portal colour scheme (best effort, *dashed*)

`mood: paper` → `prefer-light`; `mood: panel` → `prefer-dark`, exported through
the desktop portal preference and the GTK settings file. That is the whole
claim. Punar does **not** assert that third-party GTK/Qt/Electron applications
follow the theme — they follow their own rules, and saying "system-wide
theming" would be false (§9.1).

---

## 8. Managed mode

### 8.1 Yes, an organisation may pin or restrict — via the shape §46 already uses

`schemas/desired-state/desired-state.json` gains an `appearance` section beside
`applications`, and it deliberately mirrors it (`required`/`denied`/
`allowUserInstall` → `pinned`/`allowed`/`denied`/`allowUserThemes`), because an
admin who has learned one section should be able to read the other:

```json
{
  "spec": {
    "appearance": {
      "themes": {
        "pinned": "graphite",
        "allowed": ["paper", "panel", "graphite", "contrast"],
        "denied": [{ "theme": "ember" }],
        "allowUserThemes": false
      }
    }
  }
}
```

| Key | Meaning | Absent means |
|---|---|---|
| `pinned` | Exactly one theme id; becomes the effective value of `ui.theme` at the delivering layer's rank. The user's pointer is still **recorded**, and `punarctl theme set` returns the M4/M5 `overridden: true` + `effective_state` shape with exit `0` — recorded, not applied, not forbidden. | no pin |
| `allowed` | Allowlist of ids the user may select. | every installed theme |
| `denied` | Denylist; loses to `allowed` only in the sense that both are applied, deny winning. | nothing denied |
| `allowUserThemes` | `false` removes `~/.config/punar/themes/` from the search path (§3.4). | `true` |

`punarctl theme set <not-allowed>` on such a device exits `3` with a §73 message
naming the policy and its id, exactly like every other denial in the system —
and, per §46's own promise about stability, an id that is not installed is
reported as `not found`, never silently ignored.

**The accessibility carve-out is not optional.** `contrast` may not be removed
by an `allowed` list or a `denied` entry: the validator rejects an appearance
policy that excludes it, and `punarctl theme list` always shows it. An
organisation may standardise a look; it may not policy away the ability to read
the screen.

### 8.2 Personal mode is untouched

No `appearance` layer exists on an unenrolled device, so `ui.theme` resolves at
rank 5 (`local_user_preference`) and every installed theme is selectable,
including hand-written ones in `~/.config/punar/themes/`. No org chrome appears
in the picker, no line says a theme *could* be restricted, and unenrolling
(`enroll stop`) removes the org layer and with it the pin — the user's recorded
pointer, which was never deleted, becomes effective again on the next resolve.
That is design language §8 and spec §3.2: the calm state is the default state.

### 8.3 What a pin is, and what it is not

A pinned theme is a **configuration control**, on the same footing as a
corporate wallpaper. It is not a security boundary, and this document will not
let anyone read it as one:

- the session belongs to the user, who can run any compositor configuration
  they like;
- the shell is user-space code with a user-readable QML tree;
- the pointer file is in the user's own home directory.

So `ui.theme` is declared `"enforcement": "advisory"` in the effective document
(§6.1), the explain output prints that word, and the reconcile loop (spec §42)
does **not** remediate a theme: there is no drift to correct, only a preference
to record. An organisation that needs to *know* the look of a device reads it
from inventory; one that believes a pinned palette is a control has been
misled, and Punar's job is not to mislead them (spec §1.22).

---

## 9. Honest limits

### 9.1 What a theme cannot fix

- **It cannot change what a surface says.** Density, hierarchy, word choice and
  the order of a meta row are grammar and copy. A theme applied to a confusing
  screen produces a differently coloured confusing screen.
- **It cannot add a new meaning to colour.** There is no accent token, no
  brand slot, no per-application hue. An organisation that wants its identity on
  the device gets its name in the masthead as additive chrome — not a colour,
  because a fourth colour with a private meaning breaks the one thing the user
  learned once.
- **It cannot make status the only channel, or take that channel away.** Every
  status colour is accompanied by a status word, in every theme, so colour-blind
  users lose nothing and no theme can create that failure. Equally, no theme can
  grey a status out of existence — R4's saturation floor and R5's separation
  rule refuse it.
- **It cannot restyle third-party applications.** Punar exports a colour-scheme
  preference and stops (§7.4).
- **It cannot fix a display.** The floors are computed on authored sRGB values.
  Brightness, gamma, night-light filters, HDR mapping and panel quality all sit
  between those numbers and the user's eye. The contract is a promise **about
  the palette**, not a measurement of what anyone actually sees — and 4.5:1
  authored is not 4.5:1 perceived at 15% brightness in sunlight.
- **It cannot make an unreadable font readable.** Font choice and size are
  grammar, and the tracked 10px meta row is at the small end of legible by
  design; a theme can only make it darker, never larger.
- **Validation is a legibility gate, not a taste gate.** A theme can pass all
  24 pairs and still be ugly. Punar refuses illegible; it does not adjudicate
  beautiful. The shipped set is curated by people; the gate only removes the
  answers that are wrong.

### 9.2 What happens when a future milestone adds a token

The grammar file carries `meta.version` (currently `0.1.0`) and every theme
records the `meta.grammar` it was written against.

| Change | Version | What happens to existing themes |
|---|---|---|
| **A new colour token** (say `paper.raise3` for a third elevation in M12) | MINOR bump | **A new token may not be added without a derivation from existing tokens in the same change.** That is the migration rule. `raise3 = mix(raise2, ink, 0.06)` ships with the token; older themes get the derived value and keep working. `punarctl theme list` marks them `DERIVED 1`; `theme show` prints each derived token with the expression used; the picker renders such rows with a **dashed** rule, because a palette that is not fully authored for the current grammar is a mechanism outside the current claim (design language §7). |
| **A new measured pair or a raised floor** | MINOR bump | Selection is gated by the floors *in force at selection time*. A theme that now fails is marked `REVALIDATE` and cannot be re-selected until fixed — but an already-active theme is **not** switched away from. Punar does not redecorate a running desk without being asked; it says so in `punarctl theme status` and in one non-blocking row in System Control. |
| **Renaming or removing a token** | MAJOR bump | R9 refuses themes from the previous MAJOR, with a message naming the removed token and the replacement. No silent breakage, ever. |
| **A new *derived* output** (a new surface that follows the theme) | no bump | Themes are unaffected by construction — that is the whole point of deriving rather than authoring. |

The corollary for the shipped set: seven themes are seven files to update when
a token is added, and the derivation rule means that update is *optional*
rather than blocking. The set never gates a milestone.

### 9.3 Known open questions

1. Whether foot re-reads its configuration on a signal (§7.1). Until verified,
   the claim is limited to new terminals.
2. Whether `mood: "auto"` gets a clock source that costs no idle CPU. Reserved
   in the schema, drawn dashed in the picker, unbuilt.
3. Whether the greeter's system pointer is worth its file (§6.6).
4. Whether `~/.local/state/punar/` or `~/.config/punar/` is the right home for
   the pointer. This document chooses `~/.config` because a theme is a
   preference the user set, not session state the shell derived — the opposite
   call from M11's `browser-context.json`, and for that reason.

---

## 10. Acceptance checklist for the adopting milestone

1. `shell/theme/themes/` contains the seven documents of §5 and `default.json`
   pointing at `paper`; the image stages them next to `punar-tokens.json`.
2. `punarctl theme list | show | validate | set | reset | status | render` behave
   per §4.5, including exit code `6`.
3. `punarctl theme validate` implements R1–R9 with the arithmetic of §4.1, and
   its output for each shipped theme matches the table in §5.3 to two decimals.
4. A deliberately illegible theme fixture is refused with the §4.6 message and
   the failing pair named; the active theme is provably unchanged afterwards.
5. Switching repaints every open shell surface with no restart, in under one
   frame, driven by `FileView` — proven by an inotify-only trace with no timer
   and no socket traffic.
6. Derived `foot.ini`, `punar-theme.conf` and wallpaper output regenerate
   byte-identically in CI, offline.
7. Idle CPU after a switch returns to the pre-switch baseline (~0); combined
   daemon RSS is unchanged, because no daemon changed.
8. On a device enrolled against a fixture policy with `pinned`, the picker
   filters, `theme set` on a non-allowed id exits `3` with the policy named,
   `policy explain ui.theme` prints `Enforcement Advisory`, and `contrast`
   remains selectable.
9. `enroll stop` restores the user's recorded preference without a further
   action.
10. `DESIGN_LANGUAGE.md` §9.5 is updated to cite §4.2–§4.4 of this document.
