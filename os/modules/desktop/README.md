# os/modules/desktop — desktop configuration modules

Source-of-truth configuration and assets for the Punar desktop (Milestone 1).
Nothing in this tree is consumed directly at build time yet: the image
integration step copies these files into `os/images/mkosi.extra/` (or installs
them from `mkosi.postinst`) so they land in the `punar-desktop` image. Keeping
them here, out of `mkosi.extra/`, keeps ownership clear per module and lets
CI diff them against the design tokens.

## Contents and intended install paths

| Module | File(s) | Install path in image |
|---|---|---|
| `foot/` | `foot.ini` | `/etc/xdg/foot/foot.ini` |
| `fonts/` | `instrument-sans/*` (2 variable TTFs + OFL.txt) | `/usr/share/fonts/punar/instrument-sans/` |
| `fonts/` | `geist-mono/*` (3 static TTFs + OFL.txt) | `/usr/share/fonts/punar/geist-mono/` |
| `fonts/` | `50-punar-fonts.conf` | `/etc/fonts/conf.d/50-punar-fonts.conf` |

## foot terminal (`foot/foot.ini`)

Panel-surface theme from `shell/theme/punar-tokens.json` (`terminal` block,
v0 draft) per DESIGN_LANGUAGE.md section 6: background `#08090A`, foreground
`#F2F3F5`, lime `#A3E047` cursor, full ANSI 16, Geist Mono 10.5, 12px
padding, no bell, 10k scrollback.

Install path decision — **`/etc/xdg/foot/foot.ini`**, verified against the
foot 1.27.0 manual (`doc/foot.ini.5.scd`, tag 1.27.0): foot searches
`$XDG_CONFIG_HOME/foot/foot.ini` (default `~/.config/foot/foot.ini`) first,
then `$XDG_CONFIG_DIRS/foot/foot.ini` (default `/etc/xdg/foot/foot.ini`),
and loads only the first file found. The system-wide path therefore needs
**no per-user copy and no `/etc/skel` wiring**. Two consequences the
integration step must honor:

- The Arch `foot` package ships its fully-commented example at the same
  path; `mkosi.extra` content overwrites it (intended).
- A user-created `~/.config/foot/foot.ini` *replaces* (does not merge with)
  the system file — the Punar defaults are a complete standalone config.

## Fonts (`fonts/`)

Instrument Sans and Geist Mono are absent from the pinned ALA snapshot
(2026/08/20), so both are vendored from official OFL-licensed upstream
releases — pinned commit/tag, per-file sha256 manifest, OFL.txt alongside
each family. See `fonts/README.md` for exact sources, pins, hashes, and the
licensing statement; verify with `shasum -a 256 -c fonts/MANIFEST.sha256`.
Total vendored size: ~852 KB.

`fonts/50-punar-fonts.conf` sets the fontconfig defaults per punar-tokens
(sans-serif → Instrument Sans, monospace → Geist Mono, Noto fallbacks from
the snapshot's `noto-fonts`/`noto-fonts-emoji`).

## Verification status

Rendering of these configs inside the built image is **unverified until the
CI desktop-test job runs** (spec 1.22 — labeled accordingly). Local checks
performed (2026-08-24):

- `foot.ini` parse-validated with the pinned `foot 1.27.0` package via
  `foot --check-config` inside the `punar-image-builder:2026-08-20`
  container — exit 0, zero warnings. (foot 1.27 deprecates `[colors]`;
  the config uses `[colors-dark]` + an identical `[colors-light]` so the
  runtime theme toggle can never fall back to foot's built-in light
  palette — the terminal is Panel on both user preferences.)
- foot config search order confirmed from the foot 1.27.0 manual
  (`doc/foot.ini.5.scd` at tag 1.27.0).
- Vendored font files hash-verified against upstream (git blob SHA-1s for
  google/fonts, release asset sha256 for geist-font); `50-punar-fonts.conf`
  checked for XML well-formedness.

Other desktop modules (hyprland, quickshell shell, greetd session, portals)
are owned by their respective integration tasks and will be added beside
these directories.
