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
| `chromium/` | `chromium-flags.conf` | `/etc/chromium-flags.conf` |
| `chromium/` | `mimeapps.list` | `/etc/xdg/mimeapps.list` |
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

## Chromium (`chromium/`)

Two files, and the reason they are worth reading together is that they have
**opposite override semantics to `foot.ini` above** — the same shape of
mistake in either direction produces a broken default.

### `chromium-flags.conf` -> `/etc/chromium-flags.conf`

Verified 2026-08-26 by reading the strings of the compiled `/usr/bin/chromium`
launcher from chromium 151.0.7922.173-1 in the pinned snapshot, rather than
from documentation:

> Custom flags are read in order from the following files:
> `/etc/chromium-flags.conf`, `$XDG_CONFIG_HOME/chromium-flags.conf`.
> Arguments are split on whitespace and shell quoting rules apply but no
> further parsing is performed. Lines starting with a hash symbol (#) are
> skipped. Lines with unbalanced quotes are skipped as well.

- **Both files are read, in order.** A user's `~/.config/chromium-flags.conf`
  *adds to* these defaults. This is the opposite of foot's first-found-wins
  rule: a user overriding one flag does not lose the rest, so Punar's defaults
  are a floor and not a cage.
- **An unbalanced quote makes a line vanish silently** — no warning, no error.
  Every line in the file is therefore unquoted, and `surfaces-check.sh` asserts
  the flags on the *running browser's argv* rather than asserting the file's
  text, because a present, readable, well-formed-looking file can still apply
  nothing.

The `--ozone-platform-hint=auto` flag is why the file exists. It previously
lived on the `PUNAR+B` keybind, which meant exactly one launch path got a
native Wayland browser while the application launcher, `xdg-open` and any
future web-app launcher went through `chromium.desktop` and got XWayland.

**No enterprise policy.** Chromium also reads `/etc/chromium/policies/managed/`.
Punar does not write there on an unmanaged device: a managed policy makes the
browser's own menu report "Managed by your organization" on a device that was
never enrolled — the same defect class as the M5 `policy.d/ai` directory that
was created on every device. DESIGN_LANGUAGE.md section 8. Managed policy is
the correct mechanism once a device *is* enrolled, and Milestone 11 introduces
it as an additive layer.

### `mimeapps.list` -> `/etc/xdg/mimeapps.list`

Nothing in the tree registered a handler for `http(s)`, so `xdg-open` — the
call a notification action, a terminal URL activation or the command center's
"open" verb makes — had nothing to open, and `xdg-utils` was not installed at
all. A human could reach the browser through the keybind; the system could not.

Resolution order is `$XDG_CONFIG_HOME/mimeapps.list`, then each
`$XDG_CONFIG_DIRS` entry (default `/etc/xdg`), so a user's chosen default
browser **outranks** this file. A dangling desktop id here fails *open* —
`xdg-open` falls through rather than erroring, which looks identical to having
no default — so the check asserts the resolved handler and the existence of
`chromium.desktop` on the running system.

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
