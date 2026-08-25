# Vendored fonts — Instrument Sans + Geist Mono

The field-note design language (docs/design/DESIGN_LANGUAGE.md,
shell/theme/punar-tokens.json `font` block) requires **Instrument Sans**
(sans) and **Geist Mono** (mono), both SIL OFL 1.1. Neither family exists as
a package in the pinned Arch Linux Archive snapshot (`os/images/snapshot.env`,
2026/08/20): `ttf-geist`, `ttf-geist-mono`, and any Instrument Sans package
were verified absent on 2026-08-24 (the `otf-geist-mono-nerd` fork was
rejected). Both families are therefore vendored here from their official
upstream releases, unmodified, with each family's OFL license text alongside.

## instrument-sans/ — Instrument Sans (variable)

- Source: `google/fonts` GitHub repository, path `ofl/instrumentsans`,
  pinned to commit `ec626514f79f831f1ab848a82114a0ce7e2d6372`
  (main HEAD at vendoring time, 2026-08-24).
- Files (upstream names, byte-identical — git blob SHA-1s verified against
  the GitHub contents API at the pinned commit):
  - `InstrumentSans[wdth,wght].ttf` (194,336 B, blob `3589b81b…`)
  - `InstrumentSans-Italic[wdth,wght].ttf` (202,128 B, blob `72c12d62…`)
  - `OFL.txt` (4,403 B, blob `26bd2f95…`)
- Variable axes `wdth` 75–100, `wght` 400–700 (upstream METADATA.pb): the
  two variable TTFs cover the required Sans weights 400/500/600/700 in
  ~388 KB — leaner than four static weights.
- Download base URL:
  `https://raw.githubusercontent.com/google/fonts/ec626514f79f831f1ab848a82114a0ce7e2d6372/ofl/instrumentsans/`

## geist-mono/ — Geist Mono (static instances)

- Source: `vercel/geist-font` GitHub release **v1.7.2** (published
  2026-06-01), asset `geist-font-v1.7.2.zip` (8,207,303 B, sha256
  `7fc800d2ac6b92844895196e5041aca55d814c15db70c44f79b3b83ab82b04e2`).
  `https://github.com/vercel/geist-font/releases/download/v1.7.2/geist-font-v1.7.2.zip`
- Files extracted unmodified from the zip (only the weights the design
  language uses — Mono 400/500/600 — to keep the payload lean, ~450 KB):
  - `GeistMono-Regular.ttf`  (zip path `geist-font/GeistMono/ttf/`)
  - `GeistMono-Medium.ttf`
  - `GeistMono-SemiBold.ttf`
  - `OFL.txt` (zip path `geist-font/OFL.txt`, covers both Geist families)

## Licensing

Both families are licensed under the **SIL Open Font License 1.1** and ship
with their upstream `OFL.txt` unmodified in the same directory. This
Apache-2.0 repository aggregates the OFL fonts without modification — the
licenses are compatible for aggregation, and the OFL texts MUST be installed
into the image next to the font files (the OFL requires the license to
accompany the Font Software). The repo-level NOTICE update is handled at
integration (outside this directory's ownership).

## Integrity

`MANIFEST.sha256` lists the sha256 of every vendored file. Verify from this
directory with:

    shasum -a 256 -c MANIFEST.sha256

## Install paths (wired by the image-integration step)

- Font files + OFL.txt → `/usr/share/fonts/punar/instrument-sans/` and
  `/usr/share/fonts/punar/geist-mono/`
- `50-punar-fonts.conf` → `/etc/fonts/conf.d/50-punar-fonts.conf`
  (fontconfig defaults: sans-serif → Instrument Sans, monospace → Geist
  Mono, Noto families from the snapshot's `noto-fonts`/`noto-fonts-emoji`
  as fallback, per punar-tokens)
