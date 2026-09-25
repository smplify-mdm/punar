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
#   * The bar's revoke, the approval card's decision, the alert card's
#     dismissal and the AI panel's purge ran detached, so a refusal was thrown
#     away and the person saw nothing.
#   * Views rendered organization-supplied names as AutoText, where anything
#     that looks like markup is read as markup.
#   * The policy command printed for a person to copy left out --reason.
#   * System Control wrote a workspace binding straight into the state file,
#     with its own rules and no refusal to show. The shell also read
#     ~/.local/state even when punarctl wrote under $XDG_STATE_HOME.
#   * Encryption, Secure Boot and Power read sysfs themselves. Encryption
#     looked at dm-0 alone, a second LUKS2 answer that could disagree with
#     the one punard reports to an organization and the Mail vault requires.
#   * Network, Displays, Connections and Relay were hard-coded sentences that
#     went stale the day their subject shipped: Connections and Relay said
#     punar-netd "arrives in Milestone 12" after it had, Network promised Wi-Fi
#     from the same milestone, and Displays listed three registry backends
#     when there were six.
#   * The first fix still hard-coded "display configuration is not a
#     registered capability" and "no punarctl verb exists" for Wi-Fi, and the
#     Network view dropped its policy row, silently, when punar-netd did not
#     answer.
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

# 5. Anything the shell asks punarctl to DO reads its own exit: run detached,
#    a refusal is thrown away and the person sees nothing. The only detached
#    punarctl calls allowed are launchers, which hand over to a long-running
#    program and have no refusal to show. Each exemption carries its reason.
DETACHED_OK = {
    ("web-apps", "browse"): "opens the browser; the window is the answer",
    ("web-apps", "launch"): "opens a web app; the window is the answer",
}
for qml in sorted(shell.rglob("*.qml")):
    text = qml.read_text()
    for match in re.finditer(r'execDetached\(\s*\[\s*"punarctl"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"', text):
        verb = (match.group(1), match.group(2))
        if verb in DETACHED_OK:
            continue
        line = text[: match.start()].count("\n") + 1
        fail("refusals", f"{qml.relative_to(root)}:{line} runs `punarctl {' '.join(verb)}` "
             "detached, so a refusal is thrown away")

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

# 8. A person's browser-context choice is punarctl's write, the same one a
#    terminal makes, and the shell reads the file punarctl writes.
browser = (shell / "Services/BrowserContext.qml").read_text()
action = re.search(r'kind === "webContext"\) \{(.*?)\n        \} else if', control, re.S)
if action is None:
    fail("context", "the webContext action was not found in ControlData.qml")
else:
    body = action.group(1)
    if '"web-apps", "context", "bind"' not in body or "data.runMutation(" not in body:
        fail("context", "the workspace binding does not run `punarctl web-apps context bind`")
    if re.search(r"BrowserContext\.(write|use|bind)", body):
        fail("context", "the webContext action still writes the state file itself")
if re.search(r"function (use|bindToFocusedWorkspace)\(", browser):
    fail("context", "BrowserContext.qml still writes a person's choice itself")
if "XDG_STATE_HOME" not in browser:
    fail("context", "BrowserContext.qml does not read the file punarctl writes")

# 9. Encryption, Secure Boot and Power come from `punarctl device posture`,
#    the device.posture answer, not from sysfs read on the side.
if '"punarctl", "device", "posture", "--json"' not in control:
    fail("posture", "ControlData.qml does not run `punarctl device posture --json`")
for needle, what in [
    ("/sys/block/dm-", "a device-mapper UUID"),
    ("SecureBoot-8be4df61", "the SecureBoot EFI variable"),
    ("/sys/class/power_supply", "the power_supply directory"),
]:
    if needle in control:
        fail("posture", f"ControlData.qml reads {what} itself instead of device.posture")

# 10. A view that has a verb draws what the verb said. Copy a person reads
#     may not promise a milestone, count the registry, or say a capability
#     does not exist: those are the sentences that went stale. Checked in
#     every string literal outside comments, so a new "Milestone 13" or
#     "seven backends" fails as the old ones did. Each view must ask its own
#     verb with the exact argv a terminal types, and say so when it did not
#     answer.
code_lines = [
    line for line in control.splitlines()
    if not line.lstrip().startswith(("//", "/*", "*"))
]
literals = re.findall(r'"(?:[^"\\\n]|\\.)*"', "\n".join(code_lines))
number_words = (r"(?:\d+|one|two|three|four|five|six|seven|eight|nine|ten|eleven|"
                r"twelve|dozen)")
for pattern, why in [
    (r"\bMilestone\s+\d+", "a view says what exists now, not which milestone it arrives in"),
    (r"\barrives in (?:Milestone|M\d+)\b", "a view says what exists now, from the verb that knows"),
    (number_words + r"\s+(?:registered\s+)?(?:backends?|capabilities)\b",
     "the registry's size is read from punarctl capabilities, not written down"),
    (r"\bis not a registered capability\b|\bno punarctl verb exists\b",
     "whether a capability exists is the registry's answer, not a sentence"),
]:
    for literal in literals:
        if re.search(pattern, literal, re.I):
            fail("stale copy", f"ControlData.qml says {literal[:90]!r}: {why}")
for view, argv in [
    ("network", '["punarctl", "network", "status", "--json"]'),
    ("connections", '["punarctl", "privacy", "connections", "--json"]'),
    ("relay", '["punarctl", "relay", "status", "--json"]'),
]:
    if argv not in control:
        fail("view verbs", f"the {view} view does not ask {argv}")
for function, probe in [
    ("viewConnections", "connectionsProbe.payload"),
    ("viewRelay", "relayProbe.payload"),
    ("viewNetwork", "networkProbe.payload"),
    ("displaysNote", "data.capabilityList"),
    ("displaysNote", 'data.capabilityIds("display.")'),
    ("viewNetwork", 'data.capabilityIds("wifi")'),
    ("viewNetwork", "data.netdSilent(networkProbe"),
    ("viewConnections", "data.netdSilent(connectionsProbe"),
    ("viewRelay", "data.netdSilent(relayProbe"),
]:
    body = re.search(r"function " + function + r"\(.*?\n    }\n", control, re.S)
    if body is None:
        fail("view verbs", f"{function}() not found in ControlData.qml")
    elif probe not in body.group(0):
        fail("view verbs", f"{function}() does not draw from {probe}")

if problems:
    for problem in problems:
        print(f"system-control-parity-contract-test: FAIL: {problem}", file=sys.stderr)
    sys.exit(1)
print(f"system-control-parity-contract-test: ok ({len(ids)} capabilities labelled)")
PY
