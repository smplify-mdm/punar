#!/usr/bin/env bash
# System Control must not claim, offer or hide more than the device does.
#
# THE BUGS THIS EXISTS FOR, each found by the terminal-parity audit and each
# silent: nothing crashed, no test failed, a person was simply told or offered
# something untrue.
#
#   * [S] on a live grant wrote "enabled"/"disabled" to ANY capability. For
#     system.hostname, whose value space is open, that would have renamed the
#     machine "enabled".
#   * The footer said "Same capabilities as punarctl", which was not true.
#   * The battery was read from BAT0 only, while punard counts any BAT* entry
#     or any power_supply whose `type` is Battery.
#   * capabilityLabel had no name for two of punard's five capabilities.
#   * The bar's revoke and the approval card's decision ran detached, so a
#     refusal from punard was thrown away and the person saw nothing.
#   * Views rendered organization-supplied names as AutoText, where anything
#     that looks like markup is read as markup.
#   * The policy command printed for a person to copy left out --reason.
#
# Each rule below is mechanical: it reads the source, not a screenshot.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${REPO_ROOT}" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
shell = root / "shell/punar-shell"
control = (shell / "SystemControl/ControlData.qml").read_text()
sysctl = (shell / "SystemControl/SystemControl.qml").read_text()
problems = []


def fail(rule, why):
    problems.append(f"{rule}: {why}")


# 1. [S] is offered only for a capability that declares exactly two values.
actions = re.search(r"function capabilityActions\(.*?\n    }\n", control, re.S)
if actions is None:
    fail("toggle", "capabilityActions() not found in ControlData.qml")
else:
    body = actions.group(0)
    if "otherAllowedState(" not in body:
        fail("toggle", "the [S] action is not derived from allowed_desired_states")
    if re.search(r'===\s*"enabled"\s*\?\s*"disabled"\s*:\s*"enabled"', body):
        fail("toggle", "the [S] action still hardcodes an enabled/disabled flip")
helper = re.search(r"function otherAllowedState\(.*?\n    }\n", control, re.S)
if helper is None or "length !== 2" not in helper.group(0):
    fail("toggle", "otherAllowedState() must refuse anything but exactly two values")

# 2. The footer does not claim parity it does not have.
if "Same capabilities as punarctl" in sysctl:
    fail("footer", "SystemControl.qml still claims 'Same capabilities as punarctl'")

# 3. No battery path is hardcoded anywhere in the shell.
for qml in shell.rglob("*.qml"):
    if re.search(r"power_supply/BAT\d", qml.read_text()):
        fail("battery", f"{qml.relative_to(root)} hardcodes a BATn path")

# 4. Every capability punard registers has a human label.
ids = set()
for rs in (root / "crates/punard/src/backends").glob("*.rs"):
    for match in re.finditer(r'pub const CAPABILITY_ID: &str = "([a-z_.]+)";', rs.read_text()):
        ids.add(match.group(1))
if not ids:
    fail("labels", "found no CAPABILITY_ID in crates/punard/src/backends")
labels = re.search(r"function capabilityLabel\(.*?\n    }\n", control, re.S)
labelled = set(re.findall(r'case "([a-z_.]+)":', labels.group(0) if labels else ""))
for missing in sorted(ids - labelled):
    fail("labels", f"capabilityLabel has no name for {missing}")

# 5. A decision or a revoke reads its own exit: never detached.
for rel in ("Bar/Bar.qml", "Approval/ApprovalOverlay.qml"):
    text = (shell / rel).read_text()
    if re.search(r'execDetached\(\s*\[\s*"punarctl"', text):
        fail("refusals", f"{rel} runs punarctl detached, so a refusal is thrown away")

# 6. System Control renders text plainly. The shared Meta component and every
#    direct Text element carry textFormat: Text.PlainText.
meta = re.search(r"component Meta: Text \{(.*?)\n    \}", sysctl, re.S)
if meta is None or "textFormat: Text.PlainText" not in meta.group(1):
    fail("plain text", "SystemControl.qml's Meta component is not plain text")
lines = sysctl.split("\n")
for index, line in enumerate(lines):
    if not re.match(r"^\s*Text \{\s*$", line):
        continue
    depth, body = 1, []
    for following in lines[index + 1:]:
        depth += following.count("{") - following.count("}")
        body.append(following)
        if depth == 0:
            break
    if not any("textFormat: Text.PlainText" in b for b in body):
        fail("plain text", f"SystemControl.qml:{index + 1} Text without textFormat: Text.PlainText")

# 7. The policy command printed for a person is one they can run.
printed = re.search(r'data\.lastActionArgv = "punarctl policy ".*?;', control, re.S)
if printed is None or "--reason" not in printed.group(0):
    fail("policy argv", "the printed `punarctl policy` command leaves out --reason")

if problems:
    for problem in problems:
        print(f"system-control-parity-contract-test: FAIL: {problem}", file=sys.stderr)
    sys.exit(1)
print(f"system-control-parity-contract-test: ok ({len(ids)} capabilities labelled)")
PY
