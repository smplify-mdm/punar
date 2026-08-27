# Desktop fields

**Status:** implemented in the shell; the CI surface report from the commit
containing this file is the runtime authority.

**Owner direction (2026-08-26):** ship very-high-resolution, royalty-free
wallpaper choices and make the desktop inviting and clean. This direction
supersedes D-015's earlier “desktop is a sheet, not a picture” constraint and
Milestone 13's “one static wallpaper” limit. D-015's Field drawing remains an
option instead of being discarded.

## Product decision

Stillpoint is the default: an original Punar work whose quiet indigo field,
three abstract matte planes, and controlled coral accent feel warm without
competing with windows. It contains no literal landscape, road, horizon, or
recognizable place. Daybreak keeps the photographic alpine-twilight option;
Winterline is a lighter, precise aerial composition; Earthrise is the dark,
forward-looking option; Field is the original theme-derived vector and the
constrained-machine choice.

The owner pointed to Omarchy's current Tokyo Night default as a mood reference,
then explicitly asked that Punar not look like a copy. Punar takes only the
broad, non-expressive qualities: twilight warmth, violet depth, generous
negative space, and quiet desktop legibility. Stillpoint removes the reference
image's representational subject and composition entirely: it is an abstract
field with no road, valley, mountains, horizon, or leading path. No Omarchy
image was supplied to the generation model. The inspected upstream reference
was
[`themes/tokyo-night/backgrounds/0-winding-road.webp`](https://github.com/basecamp/omarchy/blob/quattro/themes/tokyo-night/backgrounds/0-winding-road.webp).

Wallpaper selection does not enter first-run onboarding. A developer can press
`PUNAR+Space`, type `wallpaper`, inspect the explicit `SetWallpaper(<id>)`
actions, and press Enter. The same contract is available to scripts:

```bash
qs -p /usr/share/punar/shell ipc call wallpaper list
qs -p /usr/share/punar/shell ipc call wallpaper set winterline
qs -p /usr/share/punar/shell ipc call wallpaper reset
```

The preference is one versioned id in `~/.config/punar/wallpaper.json`, written
atomically. Missing, corrupt, or unknown state resolves to Stillpoint; a
future schema version is left untouched.

## Resource contract

- Four 3840×2400 JPEGs add 8,266,325 bytes to the image payload.
- Only the active asset is decoded. Choices that are not selected consume no
  resident memory and cause no file watches of their own.
- The photo is decoded to the smallest 16:10 texture that covers the output:
  about 8.8 MiB at 1920×1080 and 35.2 MiB at 3840×2160 in RGBA8888.
- Field uses the smallest 16:10 texture that fits the output, preserving the
  existing geometry and slightly lower 16:9 memory cost.
- There is no daemon, unit, resident helper process, network request,
  animation, polling loop, or periodic wake-up. The existing Quickshell
  process owns the layer; FileView/inotify reacts only to an explicit
  preference change. Reset launches one fixed-argv `rm -f` and returns.

The authoritative source, creator, licence/rights note, transformation, and
distributed hash for every raster asset is recorded in
`shell/punar-shell/Wallpaper/SOURCES.md` and ships beside the images.
