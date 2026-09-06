#!/usr/bin/env python3
"""Render or apply Flathub pins resolved by tools/pin-catalog-app.sh.

The shell script owns the network and the container; this file owns the JSON.
Splitting them that way keeps the digest rule (hash the metadata FILE, never a
shell capture) in one place and keeps catalog.json edits in a language that can
preserve key order without a regex.

Two modes, matching the shell script's:

  resolve   print JSON source rows for pasting into a new catalog entry
  refresh   rewrite catalog.json in place, moving every flatpak source to the
            commit Flathub serves right now, and report what moved

Neither mode is authoritative. tools/verify-app-catalog.sh re-fetches every pin
and compares it byte for byte; that is the check that decides whether a pin is
real. This file only reduces the typing.
"""

import collections
import json
import sys


def read_pins(path):
    """appId -> arch -> (commit, runtime, metadata_sha256), skipping failures."""
    pins = collections.defaultdict(dict)
    unavailable = []
    for line in open(path, encoding="utf-8"):
        parts = line.rstrip("\n").split("\t")
        if len(parts) != 5:
            continue
        app_id, arch, commit, runtime, sha = parts
        if commit in ("UNAVAILABLE", "METAFAIL"):
            unavailable.append((app_id, arch, commit))
            continue
        pins[app_id][arch] = (commit, runtime, sha)
    return pins, unavailable


def source_row(app_id, arch, commit, runtime, sha):
    return collections.OrderedDict([
        ("kind", "flatpak"),
        ("architectures", [arch]),
        ("remote", "flathub"),
        ("appId", app_id),
        ("ref", "app/%s/%s/stable" % (app_id, arch)),
        ("commit", commit),
        ("runtime", runtime),
        ("metadataSha256", sha),
    ])


def do_resolve(pins, unavailable):
    for app_id in sorted(pins):
        rows = [source_row(app_id, arch, *pins[app_id][arch])
                for arch in ("x86_64", "aarch64") if arch in pins[app_id]]
        print("\n// %s" % app_id)
        print(json.dumps(rows, indent=2))
    for app_id, arch, why in unavailable:
        # Named explicitly: a silently missing architecture becomes a catalog
        # entry that claims coverage it does not have.
        print("// note: %s has no %s build on Flathub (%s)" % (app_id, arch, why.lower()),
              file=sys.stderr)
    return 0


def do_refresh(catalog_path, pins, unavailable):
    with open(catalog_path, encoding="utf-8") as handle:
        doc = json.load(handle, object_pairs_hook=collections.OrderedDict)

    moved, missing = [], []
    for app in doc["apps"]:
        for source in app["sources"]:
            if source.get("kind") != "flatpak":
                continue
            arches = source.get("architectures") or []
            if len(arches) != 1:
                # The catalog's convention is one architecture per source row;
                # a multi-arch row would make "which commit" ambiguous.
                missing.append((app["id"], ",".join(arches), "not a single-architecture row"))
                continue
            arch = arches[0]
            found = pins.get(source["appId"], {}).get(arch)
            if not found:
                missing.append((app["id"], arch, "no pin resolved"))
                continue
            commit, runtime, sha = found
            if source["commit"] == commit:
                continue
            moved.append((app["id"], arch, source["commit"][:12], commit[:12]))
            source["commit"] = commit
            source["runtime"] = runtime
            source["metadataSha256"] = sha

    with open(catalog_path, "w", encoding="utf-8") as handle:
        json.dump(doc, handle, indent=2, ensure_ascii=False)
        handle.write("\n")

    for app_id, arch, old, new in moved:
        print("moved  %-28s %-8s %s -> %s" % (app_id, arch, old, new))
    for app_id, arch, why in missing + [(a, r, w.lower()) for a, r, w in unavailable]:
        print("SKIP   %-28s %-8s %s" % (app_id, arch, why), file=sys.stderr)
    print("==> %d source row(s) repinned, %d left untouched" % (len(moved), len(missing)))
    return 0


def main(argv):
    if len(argv) != 4:
        print("usage: pin_catalog_app.py <resolve|refresh> <catalog.json> <pins.tsv>",
              file=sys.stderr)
        return 2
    mode, catalog_path, pins_path = argv[1], argv[2], argv[3]
    pins, unavailable = read_pins(pins_path)
    if not pins:
        print("error: no pins resolved - Flathub unreachable, or every id was wrong",
              file=sys.stderr)
        return 1
    if mode == "resolve":
        return do_resolve(pins, unavailable)
    if mode == "refresh":
        return do_refresh(catalog_path, pins, unavailable)
    print("error: unknown mode %r" % mode, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
