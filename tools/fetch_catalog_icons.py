"""Fetch each catalogue app's real icon from Flathub, at generation time.

WHY GENERATION TIME AND NOT THE DEVICE. Punar's runtime image has no background
network and no updater fetching assets behind a person's back; a store that
reached out to dl.flathub.org while you browsed would leak which apps you looked
at, and would show blank tiles on a machine that is offline. So the icons are
resolved on a maintainer's machine, land in catalog/icons/, and ship in the
image beside catalog.json — which is exactly how the twenty-one hand-added ones
already worked. The device draws a local file or nothing.

WHAT IT DOES NOT OVERWRITE. An icon already present is left alone. Several were
added by hand for apps whose Flathub art is poor or absent, and a bulk refresh
that silently replaced them would undo that work with no record.

THE MONOGRAM STAYS. An app whose icon cannot be fetched keeps the generated
monogram, which is a real fallback rather than a broken image: Flathub has apps
with no icon at all, and a network hiccup here must not produce an entry that
renders an empty box on every device forever.

ON TRADEMARKS, because shipping other people's logos deserves a sentence. These
are the same 128px icons Flathub serves to every Linux software centre for the
purpose of listing the app, reproduced unmodified and only for apps this
catalogue lists. Punar adds no branding of its own to them and claims no
affiliation. If a publisher objects, the fix is to delete the file — the
monogram takes over with no code change.
"""

import json
import pathlib
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
ICONS = REPO / "catalog/icons"
API = "https://flathub.org/api/v2/appstream/"
# 128px is what the surface draws into a 52px plate at 2x, and what the existing
# files are. The @2 variants would double the bytes in every image for pixels
# no shipped surface asks for.
MAX_BYTES = 256 * 1024


def get(url, timeout=30):
    request = urllib.request.Request(url, headers={"User-Agent": "punar-catalog/1.0"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def icon_url(app_id):
    data = json.loads(get(API + app_id))
    direct = data.get("icon")
    if isinstance(direct, str) and direct.startswith("https://") and direct.endswith(".png"):
        return direct
    for entry in data.get("icons") or []:
        url = entry.get("url")
        if entry.get("width") == 128 and isinstance(url, str) and url.endswith(".png"):
            return url
    return None


def main():
    catalog_path = REPO / "catalog/catalog.json"
    catalog = json.loads(catalog_path.read_text())
    ICONS.mkdir(parents=True, exist_ok=True)
    existing = {p.name for p in ICONS.iterdir()}

    fetched, kept, missed, total_bytes = [], [], [], 0
    for app in catalog["apps"]:
        if app.get("icon") and app["icon"] in existing:
            kept.append(app["id"])
            continue
        flat = next((s["appId"] for s in app["sources"] if s["kind"] == "flatpak"), None)
        if not flat:
            missed.append((app["id"], "not a Flatpak; no Flathub icon to fetch"))
            continue
        try:
            url = icon_url(flat)
            if not url:
                missed.append((app["id"], "Flathub lists no 128px icon"))
                continue
            blob = get(url)
            if not blob.startswith(b"\x89PNG") or len(blob) > MAX_BYTES:
                missed.append((app["id"], f"not a plausible PNG ({len(blob)} bytes)"))
                continue
            name = f"{app['id']}.png"
            (ICONS / name).write_bytes(blob)
            app["icon"] = name
            fetched.append(app["id"])
            total_bytes += len(blob)
        except Exception as error:  # noqa: BLE001 - reported, never swallowed
            missed.append((app["id"], f"fetch failed: {error}"))

    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"fetched {len(fetched)}  kept {len(kept)}  without an icon {len(missed)}")
    print(f"added {total_bytes / 1024:.0f} KiB to the image")
    for app_id, why in missed:
        print(f"  monogram: {app_id} — {why}")


if __name__ == "__main__":
    main()
