# Punar Design Language — "Field Note"

**Status:** Adopted (2026-08-24) · **Source:** Smplify field-note editorial style
(reference: https://www.smplify.com/blog/field-note-001-the-study-of-intent)
**Canonical machine-readable tokens:** [`shell/theme/punar-tokens.css`](../../shell/theme/punar-tokens.css) · [`shell/theme/punar-tokens.json`](../../shell/theme/punar-tokens.json)

Punar's graphical experience uses Smplify's field-note design language: the OS
should read like a precision instrument — a technical drawing, not a dashboard.
Calm warm paper, near-monochrome ink, tracked uppercase mono labels, hairline
rules, and color reserved strictly for meaning. This aligns directly with spec
§13.4 ("fluid, not decorative") and §73 (every restriction explains itself —
the visual language must carry explanation, not decoration).

> **Instrument, not ornament.**

---

## 1. Typography

Two families, both SIL OFL licensed (safe to ship in an Apache-2.0 OS; fonts
remain under OFL as aggregated works):

| Family | License | Role |
|---|---|---|
| **Instrument Sans** | OFL (Google Fonts) | Body text, display headlines, assertions, UI controls |
| **Geist Mono** | OFL 1.1 (Vercel) | Labels, meta rows, section headers, code, data, terminal |

Fallback stacks: `"Instrument Sans", ui-sans-serif, system-ui, sans-serif` and
`"Geist Mono", ui-monospace, SFMono-Regular, monospace`. Vendoring the font
packages into the OS image is a Milestone 1 task.

### Type roles (the grammar)

| Role | Spec | Example |
|---|---|---|
| **Display** | Instrument Sans 700, tight tracking (−0.028em), large (28–56px), near-solid leading | "A mixed fleet should not require three operating models" |
| **Section header** | Geist Mono 500, **12px, UPPERCASE, +0.12em tracking, ink-3** — never big bold sans | `ONE OUTCOME BECOMES THREE NATIVE CHANGES` |
| **Meta row / eyebrow** | Geist Mono 500–600, 10–12px, UPPERCASE, +0.12–0.14em tracking, ink-3; middle-dot `·` separators | `PUNAR · SYSTEM CONTROL` / `08 · 2026` |
| **Body** | Instrument Sans 400, 16px/1.5–1.6, ink-2 for long text, ink for emphasis | prose |
| **Lede / deck** | Instrument Sans 400, 18–20px, ink or ink-2 | opening summary |
| **Assertion** | Instrument Sans 500, 17px, pure ink — a single load-bearing sentence | "The abstraction belongs above the platform, not in place of it." |
| **Data / numbers** | Geist Mono, `tabular-nums`, always | timers, counts, IDs |
| **Tag / pill** | Geist Mono 500, 10px UPPERCASE tracked, 1px border, 6px radius | `DESIRED STATE` |

Rules: headings whisper (small tracked mono), statements shout (big tight sans)
— never both at once. IDs, timestamps, versions, and counts are always mono
tabular. No italics as structure; no more than two weights per surface.

## 2. Color

Two surface systems. Color never decorates; it states status or identity.

### Paper (light — default for system surfaces)

| Token | HSL | Hex | Use |
|---|---|---|---|
| `paper` | 45 28.6% 97.3% | `#FAF9F6` | background |
| `ink` | 0 0% 0% | `#000000` | primary text, brand, primary buttons |
| `ink-2` | 0 0% 20% | `#333333` | body text, hover |
| `ink-3` | 0 0% 40% | `#666666` | labels, meta, secondary |
| `muted` | 45 26.7% 94.1% | `#F4F2EC` | raised surfaces, code background |
| `raise-2` | 43.6 23.4% 90.8% | `#EDEAE2` | second elevation step |
| `border` | 45 13.8% 88.6% | `#E6E4DE` | hairlines, rules, tag borders |
| `input` | 40 5% 52.5% | `#8C8880` | input borders |

### Panel (dark — terminal, plates, focused technical surfaces)

| Token | HSL | Hex | Use |
|---|---|---|---|
| `panel` | 210 11.1% 3.5% | `#08090A` | background |
| `panel-fg` | 220 13% 95.5% | `#F2F3F5` | primary text |
| `panel-ink-2` | 218.6 8.8% 68.6% | `#A8ADB6` | secondary text |
| `panel-ink-3` | 220 8.6% 52.4% | `#7B8290` | labels, meta |
| `panel-edge` | 225 9.5% 16.5% | `#26282E` | borders, rules |

### Status (semantic — the only "real" colors)

| State | On paper | On panel | OS meaning (spec §52) |
|---|---|---|---|
| ok | `#2E6B21` | `#A3E047` | compliant, allowed, active |
| warn | `#8A5A00` | `#F2BE85` | remediating, approval pending, expiring |
| bad | `#A31F2C` | `#FF7A7A` | non-compliant, denied, blocked |

Rules: interfaces are near-monochrome by default; a screen with no status to
report contains **no** color. Green/amber/red map 1:1 to policy decisions
(allow / approval_required / deny) and compliance states — a user learns the
meaning once and it never lies.

### Action color (adopted 2026-08-24)

Consequential affirmative primaries — **Approve, Unlock, Enroll, Commit** —
may carry the ok-family as a fill (`#2E6B21` on paper with paper text;
`#A3E047` on panel with panel text). Neutral primaries stay ink. Destructive
actions (**Deny, Revoke, Erase**) are bad-family ghost buttons — red border
and text — and take a red fill only on a final confirmation step. At most
**one** colored button per surface; if two actions compete, the affirmative
one holds the color and the other goes ghost. This keeps the semantic promise
intact: color still means decision, now including the one the user is about
to make.

## 3. Shape, elevation, rules

- Radius: **10px** (`0.625rem`) for cards/surfaces, **6px** for tags/pills.
- Borders are hairlines (1px, `border` / `panel-edge`). Structure is drawn
  with rules, not boxes-in-boxes.
- Shadows are warm and restrained: `0 18px 36px -18px rgb(28 24 16 / .16),
  0 2px 6px rgb(28 24 16 / .07)`. On panel surfaces, prefer edges to shadows.
- Horizontal rules (1–2px ink) close header blocks, exactly as the field-note
  masthead does.

## 4. Motion

- Curve: `cubic-bezier(0.2, 0, 0, 1)` · Duration: **300ms** standard,
  150ms micro, 450ms spatial (workspace/overview).
- Motion explains state change (a window tiling, an approval resolving) and
  is never ambient. This is spec §13.4 verbatim: *fluid, not decorative*.
- Reduced-motion preference collapses everything to 0/opacity-only.

## 5. The field-note grammar in the OS

The editorial idioms translate to OS surfaces:

- **Masthead meta rows** head every first-party surface, tracked mono with
  middle-dot separators, left context / right data, closed by a rule:

  ```text
  PUNAR · SYSTEM CONTROL                    COMPLIANT · 08 · 2026
  ────────────────────────────────────────────────────────────────
  ```

- **Plates** — full technical-drawing surfaces (monochrome hairline + dashed
  strokes, numbered stations `01…05`, uppercase mono annotations) — are the
  house style for diagrams: network topology (§37), policy flow (§40 explain),
  the AI authority view (§25), first-boot, and empty states.
- **Approval cards** (§28) are field-note cards:

  ```text
  APPROVAL · APR_123 · EXPIRES 14:02                        [MEDIUM]
  ──────────────────────────────────────────────────────────────────
  Claude Code requests system.install_package · libvirt

  Required by project Atlas.

  Policy: Acme AI Engineering Baseline v3
                                          [A] APPROVE      [D] DENY
  ```

- **CLI is part of the design language.** `punarctl` output uses the same
  grammar: uppercase tracked headers, `·` separators, tabular-nums columns,
  status words colored with the terminal's semantic slots — so the graphical
  shell and terminal read as one system (spec §10: same capability layer,
  same voice).
- Tone of copy inside surfaces follows §73: plain sentences, named policies,
  next steps. The typography carries authority; the words stay humane.

## 6. Surface assignment

| Surface | System |
|---|---|
| Shell bar, command center, System Control, approvals, AI panel, privacy panel, notifications, greeter/first-boot | **Paper** |
| Terminal, code editors (default theme), plates/diagnostics, OSD overlays | **Panel** |
| User preference | Paper and Panel are both first-class; a user may run all-panel (dark) — tokens exist for every role on both surfaces |

### Terminal palette v0 (draft — refine in Milestone 1)

Background `#08090A`, foreground `#F2F3F5`, cursor `#A3E047`;
ANSI red `#FF7A7A`, green `#A3E047`, yellow `#F2BE85`, black `#26282E`,
white `#F2F3F5`, bright-black `#7B8290`. Blue/magenta/cyan slots are
desaturated blue-grays pending M1 tuning — the scheme stays near-monochrome
with lime as the single accent, matching the plates.

## 7. Plate semantics and voice (from the field-note editorial record)

The internal editorial record for Field Note 001 (Confluence: SMPLIFY space,
page 148504578) defines conventions beyond the visuals. Punar adopts them:

- **Stroke semantics are claims.** In any plate/diagram: a **solid line marks
  an operating production path; a dashed line marks a mechanism outside the
  current production claim.** Implementation alone does not earn a solid line
  — the complete path must be operating. In Punar this is the drawing-level
  enforcement of spec §1.22: simulated Secure Boot/TPM, mocked Smplify, and
  unshipped paths are always dashed.
- **Registers, not legends.** Plates number their mechanisms (`01…05`) inside
  roman-numeral sectors, and a register below names each line. Diagrams state
  their counts (`SECT I · 05 DECLARE`).
- **Coverage is explicit.** The house vocabulary is `FULL` / `PARTIAL` /
  `UNSUPPORTED`, always with reasons, shown before commit — "silence is not
  support." Punar surfaces reporting capability or compliance use the same
  explicit-coverage voice (§52 states, §73 explainability).
- **Assertions open sections.** Each section leads with one bolded
  load-bearing claim sentence, then argues it.
- **Tone:** confident and authoritative while explicit about applicability,
  enforcement, and verification boundaries. No retrospective hedging in
  user-facing surfaces; no claims the evidence doesn't carry.
- **The rim may reward close reading.** Plates can carry a restrained easter
  egg (Field Note 001's rim spells `KEEP NATIVE` in Morse, start at twelve,
  clockwise). Optional flourish — never at the cost of legibility.

## 8. Unmanaged-first (adopted 2026-08-24)

Punar is an operating system first. Most devices will never enroll in an
organization, and the design language treats the **personal, unmanaged
device as the default state of every surface**:

- Organization chrome — compliance pills, `MANAGED` tags, org names in
  mastheads, policy citations — appears **only when enrolled**. Its absence
  is calm paper, never an "unenrolled" warning or an upsell.
- Personal mode still has policy: the user's own defaults (§20). The AI
  panel cites `POLICY · PERSONAL DEFAULTS`, not nothing — authority always
  has a named source, whoever set it.
- Privacy statements strengthen, never weaken, in personal mode: the ledger
  card reads *"no organization is enrolled · nothing leaves this machine ·
  enrolling later never applies retroactively."*
- Security features are user benefits before they are enterprise features:
  shadow-AI detection, the access ledger, approval gates, and drift
  visibility all render fully on personal devices — they protect the
  user first, the organization second.
- Enrollment is **additive chrome on the same surface** — it must never
  restructure a screen, only annotate it. (Demonstrated live by the
  Personal/Managed toggle in the AI panel mockup.)
- The plates in this document mostly depict the managed hero-demo device
  (Acme/Atlas); read them minus the org rows for the personal default.

This is spec §3.2, §11, and Test A as a drawing rule: Punar must be worth
choosing with Smplify nowhere in sight — and first-class when it is.

## 9. Non-negotiables

1. UI code consumes tokens (`punar-tokens.*`) — never hardcoded values.
2. No color without meaning; no decoration that doesn't explain.
3. Mono for labels and data, sans for statements and prose — never swapped.
4. Every first-party surface keyboard-operable (spec §12) — focus states use
   a 2px ink (or panel-fg) ring, offset 2px, no color dependence.
5. Contrast: text meets WCAG AA on its surface (ink-3 on paper = 4.6:1 ✓;
   panel-ink-3 reserved for ≥14px labels).

## 10. Reference mockups

- [`mockups/boot-greeter.html`](mockups/boot-greeter.html) — boot splash
  (panel dial, arc from twelve), LUKS unlock, and greeter (first paper
  surface; debut of the action color). Interactive; the register sections
  are the M1 acceptance reference.
- [`mockups/command-approval.html`](mockups/command-approval.html) — command
  center (SUPER+Space; intent resolves to visible typed capabilities; inline
  policy explain) and the approval overlay (identity chain, live expiry
  countdown, contract block, action-color pair).
- [`mockups/system-control.html`](mockups/system-control.html) — System
  Control (SUPER+S; §63 taxonomy rail, managed controls that explain
  themselves per §73/§40, simulated/undrawn states labeled honestly).
- [`mockups/ai-panel.html`](mockups/ai-panel.html) — AI panel (SUPER+A; §19
  registry, §20 authority vs §21 ledger on one screen, §25 unknown-AI view,
  Personal/Managed toggle demonstrating enrollment-as-additive-chrome).
- [`mockups/privacy-panel.html`](mockups/privacy-panel.html) — Privacy panel
  (§64 who-talks list, §37 connection anatomy, dual-hop relay drawn dashed
  while simulated, punard's own zero-connection row as the personal-mode
  proof of silence).
- [`mockups/desktop-multitasking.html`](mockups/desktop-multitasking.html) —
  Desktop and multitasking (§13 window grammar with HJKL focus/resize modes,
  §14 workspace overview with type-to-search, §13.6 scratchpad, restoration
  and multi-monitor drawn dashed as futures).
- [`mockups/first-boot.html`](mockups/first-boot.html) — First boot (§65
  seven-stage OOBE; the personal/organization fork with personal as the
  DEFAULT card, §54 nothing-to-opt-out-of telemetry fact, §49 enrollment
  chain as additive masthead annotation, relay and attestation dashed).
- [`mockups/notifications-osd.html`](mockups/notifications-osd.html) —
  Notifications and OSD (§28 approval toast with live expiry and action-color
  pair, source-grouped center with sticky approvals and DND that never mutes
  expiry warnings, §25 unknown-AI alert dashed, tick-meter volume/brightness
  OSD on panel).
- [`mockups/updates-apps.html`](mockups/updates-apps.html) — Updates and
  applications (§57 snapshot-pinned channel, §58 faster browser lane, staged
  rollout rings and required-app pills as managed annotation, §73-voice
  denial explain, A/B slots dashed as trajectory).
- [`mockups/projects-dev.html`](mockups/projects-dev.html) — Projects and
  development (§14 workspace detail: windows, §17 environment lifecycle, AI
  sessions, §36 network table with named policy source, short-lived
  credential countdown; SUPER+1..9 switcher strip; §14.4 activity dashed).
- [`mockups/identity-elevation.html`](mockups/identity-elevation.html) —
  Identity and elevation (§48 reason-required JIT privilege with countdown
  chip and early revoke, §29 broker issuance/deny cards with never-logged
  privacy line, lock screen as the greeter's sibling; managed chrome as
  annotation).
- [`mockups/webapps-browser.html`](mockups/webapps-browser.html) — Web apps
  and browser (§31 install contract with storage-context choice, web app as
  a native window carrying masthead identity and printed origin, §32 context
  picker where the org context exists only in managed mode).
- [`mockups/cli-grammar.html`](mockups/cli-grammar.html) — CLI grammar
  (punarctl status/explain/inspect, punar-env up, and an in-terminal §28
  approval in the §6 terminal palette — mastheads, middle dots, tabular
  columns, status-only color; --json and exit codes dashed as planned).
- [`mockups/wallpaper.html`](mockups/wallpaper.html) — Wallpaper (§7 as a
  field: the boot dial from the greeter plate with its progress arc removed,
  because an idle desktop asserts nothing; two ~5 KB token-only SVGs in
  [`assets/`](assets/), watermark contrast measured against both text colours
  and kept under the window-border hairline, flat-field letterboxing so no
  aspect ratio crops; the one shell surface with no data inputs at all).
- [`mockups/menubar.html`](mockups/menubar.html) — Menubar (§5 masthead grown
  into a bar: identity left, centre reserved for modality only, a fixed
  lifecycle-ordered status cluster that severity never reorders; the four-part
  slot rule, §2 colour only for a decision or deviation, SUPER+B landing on the
  highest-severity slot; §8 personal calm as the default and org chrome as one
  appended slot, every element traced to its file and milestone with
  approvals, credentials and environments dashed).
