#!/usr/bin/env bash
# An inline component must be declared on its file's ROOT object.
#
# WHY THIS IS WORTH A GATE. `component Foo: Item {}` declares a file-scoped
# TYPE. Nest one inside a Column or a Row and the QML engine refuses the whole
# file — and the only symptom is a surface that never appears. No compile step
# catches it: qmllint reports the file CLEAN, because every individual binding
# in it is valid.
#
# That combination — invalid file, clean linter, silent failure — cost three CI
# cycles on the Mail window. The window "never appeared in hyprctl clients", and
# the first two diagnoses were wrong because the real error was in a log the
# gate was discarding.
#
# Every one of the inline components in the shipped shell already obeys this.
# The check exists so the next file that does not is caught in seconds by a
# script rather than in twenty minutes by a VM.
#
# Depth is measured in BRACES, not indentation: a component is legal at brace
# depth 1 (inside the root object and nothing else) and nowhere deeper.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${REPO_ROOT}/shell/punar-shell" <<'PY' || exit 1
import pathlib, re, sys

root = pathlib.Path(sys.argv[1])
bad, checked = [], 0

for path in sorted(root.rglob("*.qml")):
    depth = 0
    in_block_comment = False
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw

        # Strip comments and string literals before counting braces, or a `{`
        # inside a comment or a JS string shifts the depth for the whole file.
        if in_block_comment:
            end = line.find("*/")
            if end == -1:
                continue
            line, in_block_comment = line[end + 2:], False
        while True:
            start = line.find("/*")
            if start == -1:
                break
            end = line.find("*/", start + 2)
            if end == -1:
                line, in_block_comment = line[:start], True
                break
            line = line[:start] + line[end + 2:]
        line = re.sub(r"//.*$", "", line)
        line = re.sub(r'"(?:[^"\\]|\\.)*"', '""', line)
        line = re.sub(r"'(?:[^'\\]|\\.)*'", "''", line)

        stripped = line.strip()
        if stripped.startswith("component ") and ":" in stripped:
            checked += 1
            # The declaration itself opens a brace on this line, so the depth
            # BEFORE it is what matters.
            if depth != 1:
                bad.append((path, lineno, stripped[:60], depth))

        depth += line.count("{") - line.count("}")

if checked == 0:
    print("qml-inline-component-depth-test: FAIL: found no inline components to "
          "check — the parser stopped matching and this test is now blind",
          file=sys.stderr)
    sys.exit(1)

if bad:
    print("qml-inline-component-depth-test: FAIL: inline components not on the "
          "file root (the engine refuses the whole file, and qmllint says it is "
          "clean):", file=sys.stderr)
    for path, lineno, text, depth in bad:
        rel = path.relative_to(root.parent.parent)
        print(f"  {rel}:{lineno} at brace depth {depth}, must be 1 — {text}",
              file=sys.stderr)
    sys.exit(1)

print(f"qml-inline-component-depth-test: {checked} inline components, all on their file root")
PY
