# Device classes — how an opinionated OS adapts without becoming a settings panel

**Status:** design, 2026-08-26 · **Origin:** product owner, verbatim —
*"the OS should make some decisions based on the specs and device it is running
on to preserve and provide a rich experience. For some functions it needs a
beefier spec which is fine but Punar is an opinionated OS."*

---

## 1. The tension, stated before it is resolved

Those two sentences pull in opposite directions, and pretending otherwise
produces bad software.

**Adaptive** software behaves differently on different machines. Taken alone
that becomes a sprawl of conditionals nobody can reason about, and — worse —
behaviour a user cannot predict.

**Opinionated** software decides for you. Taken alone that becomes a product
that is excellent on the developer's machine and unusable on yours.

The resolution is not a compromise between them. It is a rule about **who
decides and what they are allowed to decide about**:

> **Punar measures the machine and makes the call itself. It never asks the
> user to tune it, never silently degrades, and never trades away a security or
> privacy guarantee for a slower device.** What scales with hardware is the
> RICHNESS of the experience. What never scales is what Punar promises about
> it.

**And the baseline is frugal everywhere.** Device classes decide what a capable
machine may *add*, never what a constrained one must *give up* from some
comfortable default. The standing rule is to use the least RAM possible on
every class — a workstation earns richer behaviour by measurement, it does not
receive waste by default. Stated because the opposite reading is the natural
one, and it is wrong: this is not "degrade gracefully on small hardware", it is
"cost nothing anywhere, then spend where it is demonstrably affordable".

Three consequences, each of which forecloses a tempting wrong turn:

- **No settings panel of knobs.** "Enable animations", "preload panels",
  "reduce effects" — every one of those is Punar failing to have an opinion and
  billing the user for it. The device class is observed, not configured.
- **No lowest-common-denominator.** The answer to "it must run on a 2 GB
  device" is not to make the 32 GB workstation feel like one. A capable machine
  gets the rich experience *because* it can carry it.
- **No silent degradation.** Adaptive behaviour that is not legible is
  indistinguishable from a bug. If the command centre is instant on a laptop
  and deliberate on an appliance, the machine must be able to say why — see §5.

## 2. What may vary, and what may never

This is the whole design. Getting the second column wrong is how "adaptive"
becomes "insecure on cheap hardware".

| May vary by device class | Never varies |
|---|---|
| Which surfaces are instantiated eagerly vs on first open | Whether the AI ledger records what an agent touched |
| Wallpaper: a 3.8 MP photograph or the 4.9 KB generated plate | Whether approval gates hold |
| Animation: the 300 ms token curve, or none | Whether secrets stay out of logs |
| XWayland: present for compatibility, or absent to reclaim 43 MB | Whether an unenrolled device stays unenrolled |
| Whether local model inference is offered at all | MAC randomisation, `SendHostname=no`, IPv6 privacy extensions |
| Wallpaper decode, font hinting, shadow rendering | Firewall default-deny inbound |
| Whether the full thirteen-surface shell ships in the image | That the machine tells the truth about what it is doing |

**The right-hand column is not negotiable at any price.** A Raspberry Pi does
not get weaker privacy because it has less RAM. If a guarantee cannot be met on
a device class, Punar does not ship that class — it does not ship the guarantee
quietly weakened.

## 3. The classes

Deliberately few. Every class is a maintenance burden, a CI matrix entry and a
set of decisions somebody must own.

| Class | Shape | The experience it targets |
|---|---|---|
| `workstation` | ≥ 16 GB RAM, ≥ 8 cores, no battery | Everything on, everything eager |
| `laptop` | ≥ 8 GB RAM, battery present | Everything on; power-aware where it costs nothing |
| `appliance` | < 8 GB RAM, or headless | Minimal resident footprint; RAM belongs to the workload |

`appliance` is the Raspberry Pi's primary role and the honest name for it: the
device exists to run something — inference, a service — and the desktop is
overhead against that. A 16 GB Pi 5 may legitimately classify as `laptop`, and
that is the point of measuring rather than matching on model names.

**Classification is observed, never asserted.** Reading `MemTotal`, core count,
the presence of `/sys/class/power_supply/BAT*` and whether a display is
connected is cheap, exact and needs no hardware database that would rot.

## 4. The mechanism already exists

Punard is a declarative reconciler with typed capabilities, layered policy
resolution and an audit trail. This needs no new machinery — but it does need
one new *kind* of thing, and the distinction matters:

**Existing capabilities are read-write.** `security.firewall` has an
`observe()` and an `apply()`; the daemon makes the world match the document.

**Hardware is read-only.** You cannot apply RAM. So a device class is an
**observed fact that becomes an input to policy resolution**, not a capability
with desired state. It joins the layered merge as a source of DEFAULTS —
outranked by an explicit user preference, and by org policy on an enrolled
device, exactly as personal defaults are today.

That ordering is what keeps it opinionated *and* unmanaged-first: Punar's
opinion is the default, a user who genuinely wants something else outranks it,
and neither requires an organization to exist.

## 5. Legibility is a requirement, not a nicety

An adaptive OS that will not explain itself is a buggy OS.

Every decision taken on the user's behalf must be answerable in the same voice
the rest of the product uses — the D-014 grammar, the same surfaces, the same
honesty:

```
DEVICE CLASS   APPLIANCE   3.7 GB RAM · 4 cores · no battery · no display
SURFACES       ON DEMAND   built at first open — 5 of 13 resident
WALLPAPER      GENERATED   the 4.9 KB plate, not the photographic set
XWAYLAND       ABSENT      X11 applications will not run on this device
```

The last line is the model for all of them: it states a **consequence**, not a
setting. A person reading it learns what their machine will and will not do,
which is the difference between an opinion and a surprise.

## 6. How this is tested, or it is not real

The failure mode is obvious and fatal: CI runs one VM shape, so exactly one
class would ever be exercised and the other two would be code nobody has run.

**The class must therefore be forceable.** A typed override — not a free-form
knob, an enumerated value — lets the in-VM exercise run every class on the same
hardware and assert what each one actually does. Without that, this document
describes three behaviours and proves one.

Two assertions matter more than the rest:

1. **Every class is exercised**, and the surfaces that a class claims are
   on-demand really are absent from the resident set until opened.
2. **The right-hand column of §2 is identical across all three.** That is the
   assertion that stops "adaptive" quietly becoming "less safe on cheap
   hardware", and it is the one this document exists to protect.

## 7. Open, and not decided here

- **The thresholds are placeholders.** 8 GB and 16 GB are plausible, not
  measured. They should be set from the measured cost of the desktop profile on
  each target, once aarch64 hardware exists.
- **Whether `appliance` ships the shell at all**, or a smaller surface set, is
  a product decision that interacts with the mkosi profile split
  (`base` + `desktop` today). A third profile is the natural home.
- **Battery-aware behaviour within `laptop`** is deliberately out of scope
  here; it is a different axis (power state, not capability) and mixing them
  would produce exactly the conditional sprawl §1 rejects.
