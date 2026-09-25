# Calendar — design

> **Status (2026-09-10): DESIGN ONLY.** No calendar exists. The only built thing
> is the window spike at `shell/punar-shell/Mail/shell.qml`, which reads nothing
> and says so. This document records decisions and, as importantly, the ones
> that were overturned — twelve of the first draft's decisions failed review and
> the corrected positions are what is written here.

Reference: Notion Calendar (being discontinued), from a screenshot supplied by
the user. Information architecture, interaction model and restraint are fair to
learn from. The name, wordmark, icon set, copy and any traced visual are not.

Governing constraint: `DESIGN_LANGUAGE.md` §2 *Application color (adopted
2026-09-10)*. Applications may use colour. The status triad stays reserved
everywhere; identity colour is a desaturated tint; structure stays monochrome;
nothing is colour-only.

---

## 1 · What the reference already solved for us

Three things in it are not compromises to work around but convergence:

- **The current-time line is black.** The most time-critical mark on the screen
  and it spends no hue — a dark rule, a dot at the axis, `11:42 AM` in the
  gutter. That is already our grammar.
- **Dashed means tentative.** Unconfirmed events are dashed and unfilled while
  settled ones are filled. The honesty grammar, arrived at independently.
- **Today is a filled mark, not a wash** — the numeral knocked out of a solid
  square. A fill is not colour-coding, so it transfers untouched.

It also corrected assumptions made from memory: the day count is **configurable**
(the screenshot shows 5, not a fixed week), there are **two time-zone columns**,
and there is a **right-hand panel**.

---

## 2 · The identity palette

Eight slots: seven hues on a fixed CIELAB LCh ring, plus one neutral.

| # | Name | Paper | Panel |
|---|------|-------|-------|
| 1 | Rose | `#B16D82` | `#BD778D` |
| 2 | Clay | `#AC745A` | `#B77E64` |
| 3 | Olive | `#88834E` | `#928D58` |
| 4 | Moss | `#548D69` | `#5E9873` |
| 5 | Teal | `#1B8F96` | `#2C99A1` |
| 6 | Indigo | `#4887B3` | `#5491BE` |
| 7 | Plum | `#8D78AA` | `#9882B5` |
| 8 | Stone | `#83817A` | `#888C92` |

Hues are `h_i = 359.57° + i × (360/7)`. Paper accents sit at `L* 54, C* 30`;
panel accents at `L* 58, C* 30`. Stone is the same ring at `C* 4` on each
block's own neutral hue.

**Why eight and not more.** Measured with `ThemeContrast`'s own arithmetic, the
minimum pairwise ΔE\*76 across the paper accents is **25.77** and across the
panel accents **25.86**. Both clear **25** — the exact floor
`ThemeContrast.minStatusSeparation` uses to keep `ok`/`warn`/`bad` apart. Eight
*hues* at this chroma would measure 24.0 and fail it. Rather than ship a
palette that needs an asterisk, the eighth slot is the neutral — which is also
the right default for a calendar nobody has coloured.

**Why it can never be mistaken for a verdict.** The rule is stated in CIELAB
chroma, not HSL saturation, because HSL would mislead anyone who checked:
`TEAL #1B8F96` measures HSL s = 0.695, *higher* than `ok`'s 0.529, purely
because cyan at mid lightness inflates HSL saturation. Its chroma is 30.1
against `ok`'s 49.0. Identity carries at most **61%** of the least-chromatic
status value, is lighter (`L* 54` against the triad's 35.9–42.3), and the
measured minimum ΔE\*76 from any slot to any status value is **26.4**.

**The tint is derived, not picked.** `tint = LCh(L*_tint, 11, hue(accent))`,
with `L*_tint` 93 on paper and 20 on panel. Fixing `L*` is the whole trick: CIE
`L*` is a pure function of relative luminance, so every tint at `L* 93` has
identical luminance and therefore an identical contrast ratio against any text
colour. **One proof binds all seven hues, the neutral, and any hue added
later.** Chroma 11 is also below `ThemeContrast`'s `C* ≤ 14` neutral cap — by
the validator's own measure of near-monochrome, an event fill *is* a neutral.

Measured on the tint: title `ink2` at **10.56:1**, meta `ink3` at **4.80:1**,
bar at 3.68:1 against paper. On panel, `panelInk3` measures 3.39:1 and **fails**
the 4.5 text floor, so the panel meta line steps up to `panelInk2` at 5.81:1.

---

## 3 · The removal test, answered honestly

Strip every hue and all eight fills collapse to exactly sRGB grey 235, all eight
bars to grey 129. **The block alone then carries nothing.** That is the honest
answer, not a reassuring one, and it is why the second channels are mandatory
rather than decorative:

- the **printed calendar name** in the rail, grouped by account (position);
- a **mono initial** in the block's meta line;
- the **calendar name** in the opened event's masthead.

Review overturned an earlier version that gated the initial on block size — a
second channel that disappears when the block is small is not a second channel.
`§8.2`'s "what scales with hardware is richness" does not license it, because
*nothing is colour-only* is a promise, not richness.

---

## 4 · State is shape, never hue

The organising principle: the **bar** answers *whose?*, the **fill and stroke**
answer *settled?*, and the **title** answers *still happening?* Three
independent slots, so any combination renders without a special case.

| State | Rendering |
|---|---|
| Confirmed | tint fill, 3px identity bar, no state word — the settled case says nothing |
| Tentative | dashed stroke, no fill |
| Declined | no fill, 1px **solid** stroke in `inputBorder` `#8C8880`, title `ink3` |
| Cancelled | strike-through on the title |

**Declined was corrected twice.** The first draft made hue-*absence* carry the
state, which is colour-only in its purest form, and drew it with `border`
`#E6E4DE` — a chrome hairline token, invisible against paper and
indistinguishable from three other things. `inputBorder` is the one boundary
token `ThemeContrast` measures against a 3:1 non-text floor. The hue drop is now
*decoration of* the state, never the state itself.

**An unanswered invitation is deliberately refused the `warn` triad.** `warn`
means the machine has a decision pending; an RSVP is a *person* asking, not an
authority ruling. Spending compliance amber on a lunch invite would teach the
palette to lie.

**Open, and the sharpest unresolved hole:** CalDAV carries a `COLOR` property as
arbitrary saturated sRGB, and nothing in the first draft clamped it. Honouring
it verbatim would let a remote server paint something indistinguishable from a
compliance verdict into the UI. The position of record is: honour it as
*intent*, map to the nearest ring slot by hue, print the mapping as a sentence,
and write back only on a deliberate human change.

---

## 5 · The grid

`GRID(n)` — one ranged grid, with Week and Day as values of `n` rather than
separate views. Counts **1, 3, 5, 7**, set by the bare digits, stepped with
`[` / `]`, `t` for today, `g` for the date field.

**Default 7, week-aligned, adapting rather than flattening.** Review overturned
a default of 5 that rested on two numbers existing nowhere in the repository — a
443px day track and an 84px column floor, both asserted, citation field empty.
The corrected rule: the app measures its own day track and renders the largest
count in the set that clears the derived floor.

**Anchoring is an invariant, not an initial condition.** The first draft had
four rules that contradicted each other on the common path with no stated
precedence. Corrected: every operation computes a target day, then normalises
exactly once — `anchor = (n === 7) ? weekStart(day) : day` — on all three paths.

**The day track is not a `Row`.** A `Row` is a positioner: it reassigns each
child's `x` from the running sum of its siblings' widths every frame a width
changes, so it fights any `Behavior` on `x`. Corrected to a plain `Item` with
absolutely positioned columns at `slot = trackW / n`.

**No right-hand panel.** The reference has one; taking it would make the frame
three panes wide, which this design has already refused. Its most interesting
content — the in-app shortcut list — is also a second source of truth for
keybindings, which `BindTable.qml` forbids in its own header.

---

## 6 · The mini-month, and the month question

**Punar ships no month view at 1.0 — as a scope cut, stated as one.** The first
draft rejected month on an honesty argument (empty cells past the sync horizon
read as authoritative emptiness), and review showed the replacement failed that
same test harder. Cutting on cost is defensible; dressing a cost cut as a
principle is not.

The mini-month lives in the rail and carries three facts on three channels, each
mood-safe:

- **Today** — a solid `shellFg` fill with the numeral knocked out in
  `shellSurface`. The loudest mark on the block.
- **Visible range** — a 2px rule per week-row segment, *not* a fill wash.
  `shellRaise2` collapses to `panelSurface` in panel mood, so a band would have
  rendered as literally the same colour as the ground on a dark session.
- **Sync horizon** — a dashed hairline under the numeral, with the block's foot
  printing `SYNCED · THROUGH 30 SEP`.

**Every mark names a mood-aware token.** The first draft typed the mini-month in
`ink` / `ink-2` / `ink-3`, which pin to the paper block; `Theme.qml`'s own
comment says a surface consuming `paperX`/`panelX` pins itself to one mood. On a
dark session it would have been invisible.

---

## 7 · What review changed, and why that matters

Twelve decisions did not survive. The pattern in them is worth keeping:

1. **Colour-only distinctions** dressed as something else — hue-absence for
   declined, a size-gated second channel.
2. **Tokens used outside their block** — paper `ink3` on a mood-aware surface,
   `shellRaise2` as a fill in panel mood where it collapses to the ground.
3. **Numbers with no provenance** — a 443px track and an 84px floor that exist
   in no file, supporting a default that then looked derived.
4. **Mechanisms that contradict the toolkit** — a `Behavior` on `x` inside a
   `Row`.
5. **Tests that cannot fire** — a falsifier measuring the modal value of a
   persisted preference, which measures the shipped default, not anyone's wish.

Every one of those would have been found in implementation, expensively, or not
at all.

---

## 8 · Open

- **The CalDAV colour clamp** (§4) — the mapping is decided in principle and
  unspecified in arithmetic.
- **The now-line's update cadence** against SPEC §6.3's no-polling rule. It is
  the one element that legitimately changes every minute; the timer needs an
  argument and a measured cost, and does not yet have one.
- **`ThemeContrast` does not measure any of these pairs.** The palette's proofs
  were computed with its arithmetic but live outside its shipped set; the
  identity ring needs to become measured rather than argued.
