#!/usr/bin/env bash
# A surface loaded by URL must name the types of its own directory (and of any
# other directory without a qmldir) through an aliased import.
#
# WHY THIS IS WORTH A GATE. The surface-cost probe (surface-probe.qml) loads
# each deferred surface by URL, the way it measures the object tree the
# product ships. Quickshell then does not hand that file the other files of
# its directory as bare type names, and an unaliased `import "../Overview"`
# does not either: Overview.qml's `WorkspaceWireframe {}` failed with
# "WorkspaceWireframe is not a type", the Overview and the Alt+Tab switcher
# never loaded in the probe, and the desktop gate's surface-cost check failed
# (found in the VM, SMP-1405 WP-02). The main shell imports every directory
# at its root, so it hid the fault, and qmllint reports these files CLEAN.
# CommandCenter, SystemControl and Shortcuts already use the pattern this
# holds: `import "." as Local` and `Local.Actions {}`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${REPO_ROOT}/shell/punar-shell" <<'PY' || exit 1
import pathlib, re, sys

root = pathlib.Path(sys.argv[1]).resolve()
probe = (root / "surface-probe.qml").read_text()
surfaces = re.findall(r'Qt\.resolvedUrl\("([^"]+\.qml)"\)', probe)
if len(surfaces) < 5:
    print(f"qml-url-surface-import-test: FAIL only {len(surfaces)} URL-loaded surfaces found in surface-probe.qml")
    sys.exit(1)


def code_only(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    text = re.sub(r"//[^\n]*", "", text)
    return re.sub(r'"(?:[^"\\\n]|\\.)*"', '""', text)


bad = []
for relative in surfaces:
    path = (root / relative).resolve()
    if not path.is_file():
        bad.append(f"{relative}: named by surface-probe.qml but missing")
        continue
    text = path.read_text()
    # Directories whose files this one could reach by bare name: its own, and
    # every unaliased path import of a directory that has no qmldir.
    directories = [path.parent]
    for target in re.findall(r'^import\s+"([^"]+)"\s*$', text, flags=re.M):
        directories.append((path.parent / target).resolve())
    body = code_only(text)
    for directory in directories:
        if (directory / "qmldir").exists():
            continue
        for sibling in sorted(directory.glob("*.qml")):
            name = sibling.stem
            if sibling.resolve() == path or not name[:1].isupper():
                continue
            if re.search(r"(?<![\w.])" + re.escape(name) + r"\s*\{", body):
                where = directory.relative_to(root) if directory.is_relative_to(root) else directory
                bad.append(
                    f"{relative}: uses {name} (from {where}/) by bare name; import that "
                    f"directory with an alias (import \".\" as Local) and write Local.{name}"
                )

if bad:
    print("qml-url-surface-import-test: FAIL")
    for line in bad:
        print("  " + line)
    sys.exit(1)
print(f"qml-url-surface-import-test: ok ({len(surfaces)} URL-loaded surfaces name their directories' types through an alias)")
PY
