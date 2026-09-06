#!/usr/bin/env python3
"""Generate Punar topographic wallpaper plates from public-domain USGS data.

Runs INSIDE the pinned GDAL container (tools/build-wallpaper-plates.sh); it
needs gdal_translate and gdal_contour, and nothing else beyond the Python
standard library. Type outlines arrive as JSON from tools/wallpaper_glyphs.py,
which runs in the python container, so fontTools is not a dependency here.

Every plate is one `<id>.svg.in` carrying the same three substitutions the
shipped vector wallpaper uses (`__FIELD__`, `__HAIRLINE__`, `__EMPHASIS__`), so
paper and panel are one file rather than two assets. The template budget in
Wallpaper/punar-wallpaper.svg.in applies here too: no raster, no gradient, no
filter, no <text>, no animation, no script. The type in the corner is real type
— Geist Mono outlines converted to paths at generation time — precisely so the
plate still renders before any font is loaded.

Layers, quietest to loudest (only three tones exist, so weight and continuity
carry what colour would):
    supplementary contours   hairline, 0.5px, 75% — reads as tone, not line
    intermediate contours    hairline, 1.0px
    index contours           emphasis, 1.2px
    hydrography              emphasis, 1.8px, unbroken — the loudest thing on
                             the plate, because water is what makes a
                             topographic sheet legible as a place

Determinism: USGS tiles are immutable products, the crop derives from the
manifest alone, glyph outlines come from a committed TTF, and coordinates are
rounded to one decimal. Same manifest plus same tile gives a byte-identical
plate. (fontTools' version does not affect this: it reads outlines the font
already contains.) Hydrography is the one live query — a USGS service rather
than an immutable file — so a plate rebuilt years later may gain a stream the
survey has since mapped. That is a correction, not drift.
"""

from __future__ import annotations

import hashlib
import json
import math
import pathlib
import subprocess
import sys
import time
import urllib.parse
import urllib.request

VIEW_W, VIEW_H = 1600.0, 1000.0
FRAME_ASPECT = VIEW_W / VIEW_H
SIMPLIFY_PX = 0.22
MIN_LEN_PX = 3.0
INTERMEDIATE_EVERY = 2
INDEX_EVERY = 5

MARGIN_X, MARGIN_Y = 78.0, 70.0
NHD_ENDPOINT = "https://hydro.nationalmap.gov/arcgis/rest/services/nhd/MapServer"
NHD_FLOWLINE_LAYER = 6      # "Flowline - Large Scale"
NHD_WATERBODY_LAYER = 12    # "Waterbody - Large Scale"
NHD_TIMEOUT = 180
NHD_ATTEMPTS = 4


# --- geometry ---------------------------------------------------------------

def run(argv):
    subprocess.run(argv, check=True, stdout=subprocess.DEVNULL)


def perpendicular(point, start, end):
    (px, py), (ax, ay), (bx, by) = point, start, end
    dx, dy = bx - ax, by - ay
    if dx == 0 and dy == 0:
        return math.hypot(px - ax, py - ay)
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return math.hypot(px - (ax + t * dx), py - (ay + t * dy))


def simplify(points, tolerance):
    """Iterative Douglas-Peucker; recursion overflows on a long ridge."""
    if len(points) < 3:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        i, j = stack.pop()
        worst, index = 0.0, -1
        for k in range(i + 1, j):
            d = perpendicular(points[k], points[i], points[j])
            if d > worst:
                worst, index = d, k
        if worst > tolerance and index > 0:
            keep[index] = True
            stack.append((i, index))
            stack.append((index, j))
    return [p for p, k in zip(points, keep) if k]


def polyline_length(points):
    return sum(math.hypot(points[i + 1][0] - points[i][0],
                          points[i + 1][1] - points[i][1])
               for i in range(len(points) - 1))


def coord(value):
    text = f"{value:.1f}"
    return text[:-2] if text.endswith(".0") else text


def path_data(points, close=False):
    parts = [f"M{coord(points[0][0])} {coord(points[0][1])}"]
    parts.extend(f"L{coord(x)} {coord(y)}" for x, y in points[1:])
    if close:
        parts.append("Z")
    return "".join(parts)


def bounding_box(plate):
    """A crop that is 16:10 on the ground, not 16:10 in degrees."""
    half_lat = plate["lat_span"] / 2.0
    kx = math.cos(math.radians(plate["center_lat"]))
    half_lon = (FRAME_ASPECT * plate["lat_span"] / kx) / 2.0
    return (plate["center_lon"] - half_lon, plate["center_lat"] - half_lat,
            plate["center_lon"] + half_lon, plate["center_lat"] + half_lat)


# --- type -------------------------------------------------------------------

class Type:
    """Geist Mono outlines as SVG paths, so the plate needs no installed font.

    Outlines are extracted once by tools/wallpaper_glyphs.py; this side of the
    pipeline is deliberately pure-stdlib.
    """

    def __init__(self, glyph_file):
        data = json.loads(pathlib.Path(glyph_file).read_text())
        self._upem = data["units_per_em"]
        self._glyphs = data["glyphs"]
        self._fallback = self._upem // 2

    def _glyph(self, char):
        entry = self._glyphs.get(char)
        if entry is None:
            return "", self._fallback
        return entry["d"], entry["advance"]

    def width(self, text, size, tracking):
        scale = size / self._upem
        total = 0.0
        for char in text:
            total += self._glyph(char)[1] * scale + tracking
        return total - tracking if text else 0.0

    def render(self, text, size, x, y, tracking=0.0, anchor="start"):
        """Return <path> elements for one line. y is the text baseline."""
        scale = size / self._upem
        if anchor == "end":
            x -= self.width(text, size, tracking)
        parts = []
        cursor = x
        for char in text:
            commands, advance = self._glyph(char)
            if commands and char != " ":
                parts.append(
                    f'<path transform="translate({cursor:.2f} {y:.2f}) '
                    f'scale({scale:.5f} {-scale:.5f})" d="{commands}"/>'
                )
            cursor += advance * scale + tracking
        return "".join(parts)


# --- data -------------------------------------------------------------------

def fetch_nhd(layer, west, south, east, north):
    """Bbox query against the USGS NHD service. Public domain, no key.

    Retries, then FAILS. A timeout here used to degrade to a warning, which
    wrote a plate with no hydrography and said so only in passing — the Grand
    Canyon shipped without the Colorado River. A committed artifact that is
    quietly missing a layer is worse than no artifact, so exhausting the
    retries is fatal.
    """
    query = urllib.parse.urlencode({
        "geometry": f"{west},{south},{east},{north}",
        "geometryType": "esriGeometryEnvelope",
        "inSR": "4326",
        "outSR": "4326",
        "spatialRel": "esriSpatialRelIntersects",
        "outFields": "gnis_name",
        "returnGeometry": "true",
        "f": "geojson",
    })
    url = f"{NHD_ENDPOINT}/{layer}/query?{query}"
    last = None
    for attempt in range(1, NHD_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(url, timeout=NHD_TIMEOUT) as response:
                payload = json.loads(response.read().decode())
            if payload.get("exceededTransferLimit"):
                # A truncated layer is also an incomplete plate.
                raise RuntimeError("the service truncated the result set")
            return payload
        except Exception as error:                      # noqa: BLE001
            last = error
            if attempt < NHD_ATTEMPTS:
                print(f"  NHD layer {layer} attempt {attempt} failed ({error}); retrying",
                      file=sys.stderr)
                time.sleep(attempt * 4)
    raise SystemExit(
        f"NHD layer {layer} could not be read after {NHD_ATTEMPTS} attempts ({last}). "
        f"Refusing to write a plate with missing hydrography."
    )


def rings(geometry):
    """Yield coordinate rings from a LineString/MultiLineString/Polygon."""
    kind = geometry["type"]
    coords = geometry["coordinates"]
    if kind == "LineString":
        yield coords, False
    elif kind == "MultiLineString":
        for part in coords:
            yield part, False
    elif kind == "Polygon":
        for ring in coords:
            yield ring, True
    elif kind == "MultiPolygon":
        for polygon in coords:
            for ring in polygon:
                yield ring, True


# --- plate ------------------------------------------------------------------

def build(plate, dataset, work, out_dir, type_setter):
    west, south, east, north = bounding_box(plate)
    tif = work / f"{plate['id']}.tif"
    geojson = work / f"{plate['id']}.geojson"
    source = f"/vsicurl/{dataset['base_url']}/{plate['tile']}/USGS_13_{plate['tile']}.tif"

    run(["gdal_translate", "-q", "-projwin",
         str(west), str(north), str(east), str(south), source, str(tif)])
    run(["gdal_contour", "-q", "-a", "elev", "-i", str(plate["interval_m"]),
         str(tif), str(geojson), "-f", "GeoJSON"])

    features = json.loads(geojson.read_text())["features"]
    if not features:
        raise SystemExit(f"{plate['id']}: no contours in the requested window")

    lons, lats = [], []
    for feature in features:
        for x, y in feature["geometry"]["coordinates"]:
            lons.append(x)
            lats.append(y)
    lon0, lon1 = min(lons), max(lons)
    lat0, lat1 = min(lats), max(lats)
    kx = math.cos(math.radians((lat0 + lat1) / 2.0))
    ground_w, ground_h = (lon1 - lon0) * kx, lat1 - lat0
    scale = max(VIEW_W / ground_w, VIEW_H / ground_h)
    off_x = (VIEW_W - ground_w * scale) / 2.0
    off_y = (VIEW_H - ground_h * scale) / 2.0

    def project(x, y):
        return ((x - lon0) * kx * scale + off_x, (lat1 - y) * scale + off_y)

    def collect(geometry, tolerance=SIMPLIFY_PX, minimum=MIN_LEN_PX):
        out = []
        for ring, closed in rings(geometry):
            points = simplify([project(x, y) for x, y in ring], tolerance)
            if len(points) < 2 or polyline_length(points) < minimum:
                continue
            out.append(path_data(points, closed))
        return out

    intermediate_step = plate["interval_m"] * INTERMEDIATE_EVERY
    index_step = plate["interval_m"] * INDEX_EVERY
    supplementary, intermediate, index = [], [], []
    elevations = []
    for feature in features:
        elevation = int(round(feature["properties"]["elev"]))
        points = simplify([project(x, y) for x, y in feature["geometry"]["coordinates"]],
                          SIMPLIFY_PX)
        if len(points) < 2 or polyline_length(points) < MIN_LEN_PX:
            continue
        elevations.append(elevation)
        drawn = path_data(points)
        if elevation % index_step == 0:
            index.append(drawn)
        elif elevation % intermediate_step == 0:
            intermediate.append(drawn)
        else:
            supplementary.append(drawn)

    # Hydrography. Streams are simplified harder than contours: they are drawn
    # loud, so their wobble would read as noise rather than as terrain.
    water = []
    named = set()
    for layer in (NHD_FLOWLINE_LAYER, NHD_WATERBODY_LAYER):
        payload = fetch_nhd(layer, west, south, east, north)
        for feature in payload.get("features", []):
            geometry = feature.get("geometry")
            if not geometry:
                continue
            name = (feature.get("properties") or {}).get("gnis_name")
            # Flowlines are filtered to NAMED waters. NHD maps every ephemeral
            # drainage at this scale, and drawing them all buries the terrain
            # under a web of gullies. A named river is what makes a sheet
            # legible as a place; an unnamed draw is noise.
            if layer == NHD_FLOWLINE_LAYER and not name:
                continue
            water.extend(collect(geometry, tolerance=0.35, minimum=5.0))
            if name:
                named.add(name)

    # Scale bar: a round number of kilometres, sized from the real ground width.
    ground_metres = ground_w * 111_320.0
    metres_per_px = ground_metres / VIEW_W
    for candidate in (1000, 2000, 5000, 10000):
        if candidate / metres_per_px < VIEW_W * 0.14:
            bar_metres = candidate
    bar_px = bar_metres / metres_per_px
    bar_x, bar_y = MARGIN_X, VIEW_H - MARGIN_Y
    bar = (f'<path d="M{bar_x:.1f} {bar_y:.1f}h{bar_px:.1f}'
           f'M{bar_x:.1f} {bar_y - 5:.1f}v10'
           f'M{bar_x + bar_px:.1f} {bar_y - 5:.1f}v10"/>')
    bar_label = type_setter.render(f"{bar_metres // 1000} KM", 12.0,
                                   bar_x, bar_y - 14.0, tracking=1.1)

    # Corner block: rule, place, region, coordinates.
    lat_hemisphere = "N" if plate["label_lat"] >= 0 else "S"
    lon_hemisphere = "E" if plate["label_lon"] >= 0 else "W"
    readout = (f"{abs(plate['label_lat']):.4f}° {lat_hemisphere}, "
               f"{abs(plate['label_lon']):.4f}° {lon_hemisphere}")
    right = VIEW_W - MARGIN_X
    rule = f'<path d="M{right - 26:.1f} {MARGIN_Y:.1f}h26"/>'
    # Knockout panels. Marginalia on a real sheet sits on the paper, not on the
    # terrain; without these the outlines ghost into the contours underneath.
    block_w = max(
        type_setter.width(plate["place"].upper(), 21.0, 1.8),
        type_setter.width(plate["region"].upper(), 12.5, 1.3),
        type_setter.width(readout, 12.5, 1.3),
    )
    knockouts = (
        f'<rect x="{right - block_w - 22:.1f}" y="{MARGIN_Y - 22:.1f}" '
        f'width="{block_w + 44:.1f}" height="118" fill="__FIELD__" '
        f'fill-opacity="0.92"/>'
        f'<rect x="{bar_x - 18:.1f}" y="{bar_y - 34:.1f}" '
        f'width="{bar_px + 36:.1f}" height="52" fill="__FIELD__" '
        f'fill-opacity="0.92"/>'
    )
    block = "".join([
        type_setter.render(plate["place"].upper(), 21.0, right,
                           MARGIN_Y + 34.0, tracking=1.8, anchor="end"),
        type_setter.render(plate["region"].upper(), 12.5, right,
                           MARGIN_Y + 58.0, tracking=1.3, anchor="end"),
        type_setter.render(readout, 12.5, right,
                           MARGIN_Y + 78.0, tracking=1.3, anchor="end"),
    ])

    svg = f"""<?xml version="1.0" encoding="UTF-8"?>
<!-- Punar wallpaper plate: {plate['place']}, {plate['region']}.

     GENERATED — do not hand-edit. Regenerate with
     tools/build-wallpaper-plates.sh from tools/wallpaper-plates.json.

     Elevation: {dataset['name']}, tile {plate['tile']}, {dataset['licence']}.
     Hydrography: USGS National Hydrography Dataset, same licence.
     Contours {plate['interval_m']} m supplementary / {intermediate_step} m
     intermediate / {index_step} m index. Frame is 16:10 on the ground: the
     longitude span is widened by 1/cos(latitude) so terrain is never stretched.

     A TEMPLATE, NOT AN ASSET: the three colours are placeholders substituted at
     runtime by Wallpaper.qml (theme-system.md 7.3), which is what makes paper
     and panel one file. Budget as punar-wallpaper.svg.in — no raster, no
     gradient, no filter, no text element, no animation, no script. The corner
     type is Geist Mono converted to outlines here, so the plate renders
     correctly before any font is loaded. -->
<svg xmlns="http://www.w3.org/2000/svg" width="1600" height="1000"
     viewBox="0 0 1600 1000" preserveAspectRatio="xMidYMid meet" role="img">
  <title>Punar — {plate['place']}, {plate['region']}</title>

  <!-- 01 · FIELD. Overscanned so letterboxing is painted, not left to the clear colour. -->
  <rect x="-6000" y="-4000" width="13600" height="9000" fill="__FIELD__"/>

  <!-- 02 · SUPPLEMENTARY CONTOURS. {len(supplementary)} lines at {plate['interval_m']} m; tone, not line. -->
  <g fill="none" stroke="__HAIRLINE__" stroke-width="0.5" stroke-opacity="0.75"
     stroke-linecap="round" stroke-linejoin="round">
    <path d="{''.join(supplementary)}"/>
  </g>

  <!-- 03 · INTERMEDIATE CONTOURS. {len(intermediate)} lines at {intermediate_step} m. -->
  <g fill="none" stroke="__HAIRLINE__" stroke-width="1"
     stroke-linecap="round" stroke-linejoin="round">
    <path d="{''.join(intermediate)}"/>
  </g>

  <!-- 04 · INDEX CONTOURS. {len(index)} lines at {index_step} m. -->
  <g fill="none" stroke="__EMPHASIS__" stroke-width="1.2"
     stroke-linecap="round" stroke-linejoin="round">
    <path d="{''.join(index)}"/>
  </g>

  <!-- 05 · HYDROGRAPHY. {len(water)} watercourses and waterbodies, NHD. -->
  <g fill="none" stroke="__EMPHASIS__" stroke-width="1.4"
     stroke-linecap="round" stroke-linejoin="round">
    <path d="{''.join(water)}"/>
  </g>

  <!-- 06 · MARGINALIA GROUND. Type sits on the field, not on the terrain. -->
  {knockouts}

  <!-- 07 · SCALE. {bar_metres // 1000} km measured off the real ground width. -->
  <g fill="none" stroke="__EMPHASIS__" stroke-width="1.2">
    {bar}
  </g>
  <g fill="__EMPHASIS__" stroke="none">
    {bar_label}
  </g>

  <!-- 08 · STATION BLOCK. {plate['landmark']}. -->
  <g fill="none" stroke="__EMPHASIS__" stroke-width="1.2">
    {rule}
  </g>
  <g fill="__EMPHASIS__" stroke="none">
    {block}
  </g>
</svg>
"""
    destination = out_dir / f"{plate['id']}.svg.in"
    destination.write_text(svg)
    return {
        "id": plate["id"],
        "bytes": len(svg.encode()),
        "supplementary": len(supplementary),
        "intermediate": len(intermediate),
        "index": len(index),
        "water": len(water),
        "named_waters": sorted(named)[:8],
        "min_m": min(elevations) if elevations else 0,
        "max_m": max(elevations) if elevations else 0,
        "scale_km": bar_metres // 1000,
        "sha256": hashlib.sha256(svg.encode()).hexdigest(),
    }


def main():
    manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
    out_dir = pathlib.Path(sys.argv[2])
    work = pathlib.Path(sys.argv[3])
    out_dir.mkdir(parents=True, exist_ok=True)
    work.mkdir(parents=True, exist_ok=True)
    type_setter = Type(sys.argv[4])

    only = sys.argv[5:] or None
    report = []
    for plate in manifest["plates"]:
        if only and plate["id"] not in only:
            continue
        result = build(plate, manifest["dataset"], work, out_dir, type_setter)
        report.append(result)
        print(f"{result['id']:<14} {result['bytes']:>8} B  "
              f"{result['supplementary']:>4}/{result['intermediate']:>3}/"
              f"{result['index']:>3} contours  {result['water']:>4} water  "
              f"{result['min_m']}–{result['max_m']} m  {result['sha256'][:16]}")
    (out_dir / "plates.report.json").write_text(json.dumps(report, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
