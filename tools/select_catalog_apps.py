"""Choose the curated catalogue from Flathub's own ranking, not from taste.

WHY THIS EXISTS. The catalogue was hand-written: 62 entries, each with a summary
somebody composed. docs/design/app-catalog.md section 8.1 prices that at roughly
fifteen minutes per entry per release and concludes that 400 entries is "not a
plan; it is how a catalog quietly stops being reviewed while continuing to say it
was". The owner's decision is to stop paying that cost, so selection and copy
both have to come from data.

WHAT IT SELECTS, and the two judgements it encodes — both the owner's, recorded
here so they are arguable rather than implicit:

  1. GAMES AND EMULATORS ARE EXCLUDED from the curated tier. Measured: of
     Flathub's top 500 by installs, 73 are `game`, and the top of the list is
     Roblox clients, Steam, Bottles, Heroic and a run of console emulators.
     Ranking alone would spend the curated slots on them and leave developer
     tooling out. They remain fully installable from the listed tier; this is
     about which apps Punar puts its name against, not which apps exist.
  2. DEVELOPMENT CATEGORY IS TAKEN WHOLE, before anything else. Only 32 of that
     top 500 are `development` at all, so a purely popularity-ordered list
     under-serves the machine's actual purpose.

Everything after those two rules is Flathub's install ranking, untouched.
"""

import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent

# Flathub's own category for things this machine is not for. `game` is the
# main category; the sub-categories catch emulators filed under `system` and
# `utility`, which is where several of the most-installed ones sit.
EXCLUDED_MAIN = {"game"}
EXCLUDED_SUB = {"emulator", "packagemanager"}

# Apps the ranking surfaces that this machine should not vouch for, each with
# the reason, so the list is arguable rather than a matter of taste. The first
# three are FUNCTIONAL: they would install and then not work here.
EXCLUDED_APPS = {
    "com.mattjakeman.ExtensionManager": "manages GNOME Shell extensions; Punar runs Hyprland",
    "com.github.Matoking.protontricks": "operates on a Steam installation Punar does not ship",
    "io.github.kolunmi.Bazaar": "a second Flatpak storefront, competing with this catalogue",
    "com.stremio.Stremio": "media streaming, not developer tooling",
    "org.qbittorrent.qBittorrent": "torrent client, not developer tooling",
    "io.freetubeapp.FreeTube": "video front-end, not developer tooling",
    "edu.mit.Scratch": "teaching environment for children",
    "org.turbowarp.TurboWarp": "teaching environment for children",
    "org.thonny.Thonny": "teaching IDE for beginners",
    "org.mozilla.thunderbird_esr": "extended-support duplicate of an entry already curated",
    "org.mozilla.thunderbird": "duplicate app id; org.mozilla.Thunderbird is already curated",
    "org.winehq.Wine": "a Windows compatibility layer, adjacent to the gaming use this tier excludes",
    "io.github.ilya_zlobintsev.LACT": "GPU overclocking utility, not developer tooling",
}

# Development tooling that a developer would expect and Flathub's install
# ranking does not surface in the top 500. Named explicitly so the omission is a
# decision rather than an accident of what happens to be popular this month.
#
# THE PAID JETBRAINS EDITIONS ARE HERE ON PURPOSE, having been excluded once as
# "duplicates of the Community build" — which was wrong twice over. CLion,
# Rider, WebStorm, PhpStorm, RustRover and GoLand have no Community equivalent
# at all, and Ultimate/Professional are distinct products somebody may hold a
# licence for. Whether a person can afford an app is not this catalogue's
# judgement to make; whether Punar can pin and verify its bytes is.
DEV_MUST_HAVE = [
    "io.github.shiftey.Desktop",
    "ai.opencode.opencode",
    "com.github.marhkb.Pods",
    "com.github.sdv43.whaler",
    "org.sqlitebrowser.sqlitebrowser",
    "org.pgadmin.pgadmin4",
    "com.usebruno.Bruno",
    "com.sublimehq.SublimeText",
    "org.apache.netbeans",
    "org.ghidra_sre.Ghidra",
]


def load_ranked(paths):
    seen, out = set(), []
    for path in paths:
        for hit in json.loads(pathlib.Path(path).read_text())["hits"]:
            if hit["app_id"] not in seen:
                seen.add(hit["app_id"])
                out.append(hit)
    return out


def is_excluded(hit):
    if hit["app_id"] in EXCLUDED_APPS:
        return True
    if (hit.get("main_categories") or "") in EXCLUDED_MAIN:
        return True
    subs = {s.lower() for s in (hit.get("sub_categories") or [])}
    return bool(subs & EXCLUDED_SUB)


def select(ranked, already, target):
    """Development first, then install rank. Never a game, never a duplicate."""
    chosen, taken = [], set(already)

    def take(hit):
        if hit["app_id"] in taken or is_excluded(hit):
            return False
        taken.add(hit["app_id"])
        chosen.append(hit)
        return True

    by_id = {h["app_id"]: h for h in ranked}
    for app_id in DEV_MUST_HAVE:
        if app_id in by_id:
            take(by_id[app_id])
    for hit in ranked:
        if (hit.get("main_categories") or "") == "development":
            take(hit)
    for hit in ranked:
        if len(chosen) + len(already) >= target:
            break
        take(hit)
    return chosen


def main():
    target = int(sys.argv[1]) if len(sys.argv) > 1 else 100
    pages = sorted(pathlib.Path(sys.argv[2]).glob("pop-p*.json")) if len(sys.argv) > 2 else []
    if not pages:
        sys.exit("usage: select_catalog_apps.py <target> <dir-with-pop-p*.json>")

    catalog = json.loads((REPO / "catalog/catalog.json").read_text())
    already = {s["appId"] for a in catalog["apps"] for s in a["sources"] if s.get("appId")}

    ranked = load_ranked(pages)
    chosen = select(ranked, already, target)
    print(json.dumps([h["app_id"] for h in chosen], indent=2))
    print(
        f"\n// {len(catalog['apps'])} existing + {len(chosen)} selected "
        f"= {len(catalog['apps']) + len(chosen)} (target {target})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
