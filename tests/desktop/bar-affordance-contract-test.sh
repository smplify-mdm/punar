#!/usr/bin/env bash
# A control that changes the cursor must also change its appearance.
#
# THE BUG THIS EXISTS FOR. The bar's workspace label opened the project overview
# — the surface that owns switching — and a person testing the build reported
# twice that they could not see how to switch project workspaces with a mouse.
# They were right. It was the only interactive control in the identity row drawn
# with no affordance at all: no hover fill, no hover rule, no padding, and a hit
# box that was the glyph box of an 11px label inside a 30px bar. At rest and on
# hover it was indistinguishable from the inert " · " separators beside it.
#
# The tell was already in the source: `hoverEnabled: true` was set on a
# MouseArea with NO id, so no binding could reach containsMouse. The property
# was inert. Someone intended the visual and never wired it, and nothing
# noticed, because a missing hover state breaks no test and throws no warning —
# it just quietly makes a feature undiscoverable.
#
# So the rule is mechanical and checkable: in the bar, a MouseArea that sets
# Qt.PointingHandCursor is claiming to be a control, and a control must have an
# id whose containsMouse/pressed drives at least one visible binding. The cursor
# is not an affordance on its own — a person only sees it once the pointer is
# already on the target, which is precisely the discovery problem.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BAR="${REPO_ROOT}/shell/punar-shell/Bar/Bar.qml"

fail() {
    echo "bar-affordance-contract-test: FAIL: $*" >&2
    exit 1
}

[ -f "${BAR}" ] || fail "no Bar.qml at ${BAR#"${REPO_ROOT}/"}"

python3 - "${BAR}" <<'PY' || exit 1
import re, sys

path = sys.argv[1]
src = open(path).read()

# EXEMPTIONS, each with its reason, because an unexplained allowlist is how a
# rule rots. `revokeGrant` is the elevation chip's two-step revoke: its feedback
# is the ARM state change (the chip's own text and colour change on the first
# click), which is a deliberate design for an action that must not happen by
# accident. It is a different affordance, not an absent one.
EXEMPT = {"root.revokeGrant()": "two-step arm; feedback is the chip's arm state"}

problems = []
checked = 0
for match in re.finditer(r"MouseArea\s*\{(.*?)\n(\s*)\}", src, re.S):
    body = match.group(1)
    if "PointingHandCursor" not in body:
        continue
    line = src[: match.start()].count("\n") + 1

    handler = re.search(r"onClicked:\s*([^\n]+)", body)
    action = handler.group(1).strip() if handler else ""
    if action in EXEMPT:
        continue

    checked += 1
    ident = re.search(r"\bid:\s*(\w+)", body)
    if not ident:
        problems.append(
            f"  Bar.qml:{line} — a control with a pointing-hand cursor and no id, "
            f"so nothing can bind to its hover state ({action or 'no onClicked'})"
        )
        continue
    name = ident.group(1)
    if not re.search(rf"\b{name}\.(containsMouse|pressed)\b", src):
        problems.append(
            f"  Bar.qml:{line} — {name} sets a pointing-hand cursor but no "
            f"visible binding reads {name}.containsMouse/pressed, so the control "
            f"looks identical whether or not the pointer is on it ({action})"
        )

if checked == 0:
    print("bar-affordance-contract-test: FAIL: found no pointing-hand controls to "
          "check — the parser stopped matching and this test is now blind",
          file=sys.stderr)
    sys.exit(1)

if problems:
    print("bar-affordance-contract-test: FAIL: controls that change the cursor "
          "but not their appearance:", file=sys.stderr)
    for p in problems:
        print(p, file=sys.stderr)
    sys.exit(1)

print(f"bar-affordance-contract-test: {checked} bar controls each show hover state")
PY

# THE WORKSPACE CONTROL SPECIFICALLY, pinned by name, because it is the one the
# report was about and the one whose absence of affordance was invisible for the
# longest. It must be a bar-height target with padding, like its siblings — a
# MouseArea parented to bare text inherits the text's tiny implicit box, which
# on a scaled display makes most of the visible pixels miss.
grep -q 'id: workspaceButton' "${BAR}" \
    || fail "the workspace indicator is not a named control any more"
grep -q 'width: workspaceLabel.implicitWidth + 12' "${BAR}" \
    || fail "the workspace control lost its padding; its hit box is the glyph box"
grep -q 'height: bar.height' "${BAR}" \
    || fail "the workspace control is no longer a bar-height hit target"

# And it must still open the overview: the affordance is only worth having if
# the door still leads somewhere. D-016 Sect III lists Workspace among the
# bar's doors, and the overview is the surface that owns switching.
grep -q 'onClicked: root.overviewRequested()' "${BAR}" \
    || fail "the workspace control no longer opens the project overview"

echo "bar-affordance-contract-test: PASS"
