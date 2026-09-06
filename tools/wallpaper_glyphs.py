#!/usr/bin/env python3
"""Dump Geist Mono glyph outlines to JSON for the wallpaper plate generator.

Runs in the pinned python container (tools/build-wallpaper-plates.sh), which is
the only place fontTools is needed. The plate generator itself then stays
pure-stdlib and needs no font library and no network.

The output is an intermediate in the work directory, not a committed asset: it
is regenerated from the vendored TTF whenever plates are rebuilt, so there is
no second place for the type to drift to.
"""

from __future__ import annotations

import json
import pathlib
import sys

CHARSET = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    " .,:;'\"()[]/-–—+°·%&"
)


def main() -> int:
    from fontTools.pens.svgPathPen import SVGPathPen
    from fontTools.ttLib import TTFont

    font_file, destination = sys.argv[1], pathlib.Path(sys.argv[2])
    font = TTFont(font_file)
    glyph_set = font.getGlyphSet()
    cmap = font.getBestCmap()
    metrics = font["hmtx"]

    glyphs = {}
    missing = []
    for char in CHARSET:
        name = cmap.get(ord(char))
        if name is None:
            missing.append(char)
            continue
        pen = SVGPathPen(glyph_set)
        glyph_set[name].draw(pen)
        glyphs[char] = {"d": pen.getCommands(), "advance": metrics[name][0]}

    destination.write_text(json.dumps({
        "source": pathlib.Path(font_file).name,
        "units_per_em": font["head"].unitsPerEm,
        "glyphs": glyphs,
    }))
    print(f"glyphs: {len(glyphs)} from {pathlib.Path(font_file).name}"
          + (f" (missing {''.join(missing)})" if missing else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
