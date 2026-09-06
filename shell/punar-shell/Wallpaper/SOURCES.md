# Wallpaper sources and licences

Punar distributes the four raster desktop fields below at 3840×2400. They are
installed assets, never fetched at runtime. The original Field vector is a
Punar project work and is covered by the repository licence.

## Stillpoint (`assets/stillpoint.jpg`)

- Source: original image generated for Punar with OpenAI image generation on
  2026-08-26; no existing image was supplied to the model as a reference.
- Exact tool and prompt: [`GENERATION.md`](GENERATION.md).
- Direction: an original minimalist 16:10 developer-desktop field with deep
  indigo negative space, one controlled coral glow, three abstract matte
  planes, and a short precision accent; no literal landscape, road, horizon,
  terrain, text, logo, or recognizable place.
- Generation output: 1536×1024 PNG.
- Changes: centred 1536×960 crop to 16:10; resampled to 3840×2400; metadata
  removed through a lossless WebP/PPM round trip; encoded as JPEG at quality 88.
- Rights note: generated for the Punar project and distributed under the
  repository licence to the extent copyright or related rights exist; no claim
  is made that copyrightability is identical in every jurisdiction.
- Distributed SHA-256: `6313a086a8eddb5b8f113edc50b4d7c1656b433c0e7fdb3c7cd97d90d65439e0`

## Daybreak (`assets/daybreak.jpg`)

- Source: [Dark mountain panorama](https://commons.wikimedia.org/wiki/File:Dark_mountain_panorama.jpg)
- Creator: Ales Krivec / Dreamy Pixel
- Source dimensions: 7319×3910
- Licence: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Changes: centred 6256×3910 crop to 16:10; resampled to 3840×2400;
  metadata removed; encoded as JPEG at quality 84.
- Distributed SHA-256: `4aa5af32a22ead3930bab5b9b24e1a8c899ba13268e0e58acd94c96251905c18`

## Winterline (`assets/winterline.jpg`)

- Source: [Aerial view of lake in winter](https://commons.wikimedia.org/wiki/File:Aerial_view_of_lake_in_winter.jpg)
- Creator: Dreamy Pixel
- Source dimensions: 4313×2599
- Licence: [Creative Commons Attribution 4.0 International](https://creativecommons.org/licenses/by/4.0/)
- Changes: centred 4158×2599 crop to 16:10; resampled to 3840×2400;
  metadata removed; encoded as JPEG at quality 84.
- Distributed SHA-256: `04aab01c53774d96d336ef0d15d235e10d9f1194ee7409615f7956615b5759f1`

## Earthrise (`assets/earthrise.jpg`)

- Source: [View from Apollo 11 showing Earth above the Moon's horizon](https://commons.wikimedia.org/wiki/File:View_from_the_Apollo_11_shows_Earth_rising_above_the_moon%27s_horizon.jpg)
- Creator: NASA / Apollo 11 crew; catalog AS11-44-6549
- Source dimensions: 4000×3920
- Licence: public domain in the United States as a work created solely by NASA;
  see the source page for the jurisdiction notice.
- Changes: centred 4000×2500 crop to 16:10; resampled to 3840×2400;
  metadata removed; encoded as JPEG at quality 84.
- Distributed SHA-256: `f5a6fb900ec98de5acdcd817728fcadfba18a700949e9b474c9f58c71a4f182f`

Source and licence pages were checked on 2026-08-26. Punar's names for the
adapted files—Daybreak, Winterline, and Earthrise—do not replace the source
titles or creator attribution above.

## Topographic plates (`plates/*.svg.in`)

These five are **generated, not sourced**: `tools/build-wallpaper-plates.sh`
derives them from public-domain USGS data via `tools/wallpaper-plates.json`.
They are templates rather than assets — the three colours are placeholders
substituted at runtime, so each file serves both the paper and panel moods.

- Elevation: [USGS 3D Elevation Program](https://www.usgs.gov/3d-elevation-program)
  1/3 arc-second, one immutable staged tile per plate.
- Hydrography: [USGS National Hydrography Dataset](https://www.usgs.gov/national-hydrography),
  queried for the plate's own bounding box. Flowlines are filtered to named
  waters; NHD maps every ephemeral drainage at this scale and drawing them all
  buries the terrain.
- Licence: both are works of the United States Government and are in the public
  domain under 17 U.S.C. 105. No attribution is required; Punar credits USGS
  regardless.
- Type: the station block and scale bar are Geist Mono (SIL OFL 1.1, vendored at
  `os/modules/desktop/fonts/geist-mono/`) converted to outlines at generation
  time, so the plate contains no `<text>` and renders before any font loads.
- Rights note: the contour and hydrography geometry is a mechanical derivation
  of public-domain measurements. The layer choices, framing and typography are
  Punar project work under the repository licence.

| Plate | Place | Tile | Contours | Distributed SHA-256 |
|---|---|---|---|---|
| `yosemite` | Yosemite Valley, California, USA | `n38w120` | 30/60/150 m | `368d7ed76c911387ed032698c3906b17a63b71012db13eff71ba54c584bee198` |
| `grand-canyon` | Grand Canyon, Arizona, USA | `n37w113` | 40/80/200 m | `50d2b675bd4bf68146388cd9cf22e610067233294ba4561fe70075c69d7d6aa5` |
| `rainier` | Mount Rainier, Washington, USA | `n47w122` | 40/80/200 m | `de3d8b85b249b75ac93d011709d20cc4bdd74602d79b779833d08b64cebfd304` |
| `crater-lake` | Crater Lake, Oregon, USA | `n43w123` | 30/60/150 m | `57235e8bb858d5ed2daf6b418a084d14fd30288ca382535c13dcd958887d56a7` |
| `zion` | Zion Canyon, Utah, USA | `n38w114` | 40/80/200 m | `73e21fcac910732c2d311f31adb924270098b977bde2f3e3286ec25261064369` |
