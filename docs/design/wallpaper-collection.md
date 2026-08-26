# Punar wallpaper collection

**Status:** shipped set, 2026-08-26 · **Manifest:** [`os/modules/desktop/wallpapers/wallpapers.json`](../../os/modules/desktop/wallpapers/wallpapers.json)
**Companion:** the generated instrument plate in [`mockups/wallpaper.html`](mockups/wallpaper.html) (Plate D-015) remains the default.

---

## 1. The curation rule

Punar's identity is austere and near-monochrome. A gallery of saturated
landscape photography would fight it, and the desktop would look like every
other distribution. But one generated wallpaper reads as thin.

The rule that resolves it, written before anything was picked:

> **Ship fields, not subjects.** A Punar wallpaper is a material seen close
> up — plaster, concrete, aggregate, asphalt, dressed stone. It has texture
> but no focal point, no horizon, no story competing with the window in
> front of it. It is the sheet the instrument is drawn on.

Three consequences, each measured rather than eyeballed:

- **Near-zero chroma.** Median C\* ≤ 14, 95th percentile ≤ 33.7. The shipped
  set is far below both — the loosest is 4.5 at p95, and Tarmac measures a
  median C\* of 0.8, effectively a grey card with a grain.
- **One luminance.** Field uniformity contrast ≤ 3.0, so no region of the
  image is a different brightness "zone" that text crosses into.
- **No competing lines.** The strongest straight-line contrast in the image
  must stay under 1.15 — quieter than a 1px window border, so Punar's own
  hairlines always read as the foreground grammar.

## 2. The shipped set

Nine fields, four **paper** and five **panel**, so every theme's surface
mood has more than one option. Names are materials, not moods.

| Id | Mood | MB | Bar contrast¹ | What it is |
|---|---|---|---|---|
| **Chalk** | paper | 1.9 | 7.58 | Painted plaster — the flattest bright field, the closest photographic relative of the `#FAF9F6` token |
| **Lime** | paper | 0.6 | 9.70 | Hand-floated lime render: a warm, slow swell with no edge anywhere in it |
| **Grit** | paper | 2.7 | 7.85 | Cast concrete close up — the paper mood with a coarse grain, for anyone who finds Chalk too clean |
| **Ballast** | paper | 2.9 | 7.46 | Pale aggregate: high-frequency texture that still holds a single luminance |
| **Tarmac** | panel | 2.2 | 8.11 | The most neutral surface in the whole pool — median C\* 0.8 |
| **Macadam** | panel | 1.7 | 6.49 | Coarse bound aggregate; the brightest panel field, so it holds the window hairline best |
| **Pitch** | panel | 1.6 | 5.56 | Tarred stone — the darkest field that still lets Punar draw a border on top |
| **Soot** | panel | 1.2 | 7.99 | Dark plaster rather than asphalt: the panel mood with a rendered wall grain |
| **Flagstone** | panel | 1.5 | 7.20 | Dressed stone with visible joints — the one shipped field with drawn lines, all quieter than a window border |

¹ Worst-patch contrast ratio for the theme's text token (ink `#000000` on
paper fields, panel-fg `#F2F3F5` on panel fields) measured in the region
where the menubar sits. **Every value clears WCAG AA (4.5:1) at the worst
patch, not merely on average** — the weakest is Pitch at 5.56.

## 3. Licensing

**Every image is CC0 1.0 Universal**, sourced from
[Poly Haven](https://polyhaven.com/license), whose entire library is
public-domain dedicated. Attribution is **not legally required** and
redistribution **is permitted** — which is what makes these safe to ship
inside an ISO.

Creators are recorded anyway, in the manifest and here: Amal Kumar,
Charlotte Baglioni, Dimitrios Savva, Jenelle van Heerden, Dario Barresi,
Rob Tuytel.

Each manifest entry carries the asset id, the source URL, the API URL, the
licence name and URL, the source policy URL, `attribution_required: false`,
`redistribution_permitted: true`, and the date the licence was verified
(2026-08-26). This is the same discipline the vendored OFL fonts got: the
manifest *is* the licence record.

## 4. Processing and budget

Sources are 8K texture maps (43.6 MB combined). Each was centre-cropped to
16:10 — the Plate D-015 sheet ratio — Lanczos-resampled to **3840×2400**,
and encoded as progressive JPEG at quality 82, 4:2:0, with Pillow 12.3.0.

**Total shipped: 16.3 MB.**

The arithmetic, stated rather than waved at: against ADR-003's 8 GiB root
slot that is **0.19%**, and against the 17 GiB fixed OS cost, **0.09%**.
The whole set ships in the image; no download path is needed, and none
exists. For contrast, the generated instrument plate is 4.9 KB — three
orders of magnitude smaller, which is why it stays the default.

## 5. Honest limits

- **A photograph cannot do what the plate does.** The generated wallpaper is
  resolution-independent and scales perfectly from 1366×768 to 8K; these are
  fixed rasters at 3840×2400 and will be resampled on other geometries.
  Above 4K they will soften.
- **These were measured, not judged.** The thresholds in §1 are the whole
  test. An image that passes them can still be ugly, and taste is not
  encoded here.
- **Nothing was rejected on licence grounds**, because Poly Haven's blanket
  CC0 meant no candidate ever had an ambiguous licence to resolve. A future
  source without that property needs per-image verification before it ships.
- **The 16:10 crop is a choice.** On a 16:9 display the field is
  centre-cropped again at runtime; on ultrawide it is scaled and cropped
  more aggressively. Because these are fields rather than subjects, nothing
  important is lost — which is the curation rule paying for itself.
