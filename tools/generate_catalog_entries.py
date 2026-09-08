"""Build catalogue entries from Flathub's own metadata instead of by hand.

WHY. Every entry in catalog/catalog.json used to be composed by a person: a
summary rewritten, a category chosen, keywords invented. docs/design/app-catalog.md
section 8.1 prices that at ~15 minutes per entry per release and says plainly
where it leads — "600 hours a year of catalog re-review is not a plan; it is how
a catalog quietly stops being reviewed while continuing to say it was". The
owner's decision is to stop paying it, which means the copy has to come from
somewhere that already maintains it. Flathub does.

WHAT PUNAR THEREFORE SAYS, AND DOES NOT SAY. Every descriptive field below is
Flathub's, reproduced rather than authored: name, summary, developer, licence,
category. Punar does not claim to have read the app, judged it, or scanned it.
What Punar adds is the PIN — the exact commit, runtime and metadata digest that
tools/verify-app-catalog.sh re-fetches and compares byte for byte — and the
rendering of the publisher-verification flag Flathub publishes. Those two are
mechanical and checkable, which is the whole reason they are the only claims
made. An earlier design shipped a `containment: sandboxed` label nothing could
verify and was rejected by every reviewer; this file exists to not do that again.

THE VERIFICATION FLAG IS FLATHUB'S, NOT PUNAR'S. `verification_verified` means
Flathub established that the publisher is the upstream project — an identity
check, in the shape of macOS's "identified developer". It is NOT a malware scan,
Punar has not performed one, and no string here may imply otherwise.
"""

import json
import pathlib
import sys
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
API = "https://flathub.org/api/v2/appstream/"

# Flathub's main category -> the catalogue's own vocabulary. Anything unmapped
# lands in `utilities` rather than inventing a category the surface cannot draw.
CATEGORY = {
    "development": "developer",
    "network": "communication",
    "office": "productivity",
    "graphics": "graphics",
    "audiovideo": "media",
    "system": "diagnostics",
    "utility": "utilities",
    "security": "security",
    "education": "productivity",
    "science": "productivity",
}

# Both strings must fit the schema's 240-character disclosure limit, which is a
# useful constraint: a disclosure nobody finishes reading is not a disclosure.
VERIFIED = {
    "id": "publisher:verified",
    "text": (
        "Flathub verified the publisher is the project itself — an identity check, not an "
        "inspection. Punar has not reviewed or scanned this app. It pins the exact bytes "
        "and shows the access the app asks for before you install."
    ),
}

UNVERIFIED = {
    "id": "publisher:unverified",
    "text": (
        "Flathub has not verified who publishes this app. Punar has not reviewed or scanned "
        "it either. It pins the exact bytes and shows the access the app asks for before "
        "you install."
    ),
}

# Flathub has no AI category, so tools for running and talking to models scatter
# across utility, network and development. Punar has an `ai` section and a person
# looking for these will look there, so the mapping is explicit rather than
# inferred from a summary — inferring it would silently miscategorise the day a
# description changes.
AI_APPS = {
    "ai.lmstudio.lm-studio",
    "ai.jan.Jan",
    "ai.opencode.opencode",
    "com.jeffser.Alpaca",
    "io.gpt4all.gpt4all",
    "com.openwebui.open-webui",
}


def fetch(app_id):
    request = urllib.request.Request(
        API + app_id, headers={"User-Agent": "punar-catalog/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read())


def entry_id(app_id, taken):
    """A short, stable id from the reverse-DNS one, unique within the catalogue."""
    base = app_id.rsplit(".", 1)[-1]
    slug = "".join(c if c.isalnum() else "-" for c in base).strip("-").lower()
    slug = "-".join(part for part in slug.split("-") if part) or app_id.lower()
    candidate = slug
    n = 2
    while candidate in taken:
        candidate = f"{slug}-{n}"
        n += 1
    return candidate


def build(app_id, sources, taken):
    data = fetch(app_id)
    meta = data.get("metadata") or {}
    verified = bool(meta.get("flathub::verification::verified"))
    cats = [c.lower() for c in (data.get("categories") or [])]
    if app_id in AI_APPS:
        category = "ai"
    else:
        category = next((CATEGORY[c] for c in cats if c in CATEGORY), "utilities")
    summary = (data.get("summary") or "").strip()
    if summary and not summary.endswith("."):
        summary += "."
    return {
        "id": entry_id(app_id, taken),
        "name": data.get("name") or app_id,
        "featured": False,
        "category": category,
        # Flathub's own categories, lowercased, as search terms. Not invented.
        "keywords": sorted({c for c in cats if c})[:8] or [category],
        "summary": summary or "No summary published on Flathub.",
        # `curated` here means Punar pins and re-verifies the bytes every release.
        # It does NOT mean a person read the app; see the module docstring.
        "trustTier": "curated" if verified else "community",
        "license": "free" if data.get("is_free_license") else "proprietary",
        "publisher": "flathub",
        "bundledUpdater": "none",
        "disclosures": [VERIFIED if verified else UNVERIFIED],
        "sources": sources,
    }


def main():
    selected = json.loads(pathlib.Path(sys.argv[1]).read_text())
    pins = json.loads(pathlib.Path(sys.argv[2]).read_text())
    catalog_path = REPO / "catalog/catalog.json"
    catalog = json.loads(catalog_path.read_text())
    taken = {a["id"] for a in catalog["apps"]}

    added, skipped = [], []
    for app_id in selected:
        rows = pins.get(app_id)
        if not rows:
            skipped.append((app_id, "no resolved pin"))
            continue
        try:
            record = build(app_id, rows, taken)
        except Exception as error:  # noqa: BLE001 - reported, never swallowed
            skipped.append((app_id, f"metadata fetch failed: {error}"))
            continue
        taken.add(record["id"])
        catalog["apps"].append(record)
        added.append(record["id"])

    catalog["apps"].sort(key=lambda a: a["id"])
    catalog_path.write_text(json.dumps(catalog, indent=2) + "\n")
    print(f"added {len(added)} entries; catalogue now {len(catalog['apps'])}")
    for app_id, why in skipped:
        print(f"  skipped {app_id}: {why}")


if __name__ == "__main__":
    main()
