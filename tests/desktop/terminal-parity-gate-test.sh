#!/usr/bin/env bash
# Terminal parity, held by construction (parity plan section 5, step 12).
#
# Everything the shell does to the device or the session must be something a
# person can do from a terminal, and the shell should do it BY RUNNING that
# same command, so the two cannot drift. Two rules, both read from source:
#
#   1. Every process the shell starts (runMutation, execDetached, a Process
#      `command`, Process.exec, and the shell's own funnels that end in one)
#      runs `punarctl`, or a fixed helper listed below with the reason it is
#      not a punarctl verb, or is a documented exception. A new direct tool
#      call fails this test until it is routed through punarctl or earns an
#      entry here with a reason a reviewer can check.
#
#   2. Every System Control view maps to the punarctl verb that gives the same
#      answer, in tests/desktop/system-control-verbs.json. A view with no verb
#      names why. punarctl's own unit tests prove every listed verb parses.
#
# Today's remaining gaps are listed as exceptions WITH their reason, so the
# list is also the to-do list.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 - "${REPO_ROOT}" <<'PY'
import json
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
shell = root / "shell/punar-shell"
problems = []

# ---------------------------------------------------------------------------
# Rule 1: what the shell runs.
# ---------------------------------------------------------------------------

PUNARCTL = {"punarctl", "/usr/bin/punarctl"}

# Fixed helpers that are deliberately not punarctl verbs, the only files that
# may run each, and why. Scoped per file, so allowing `hyprctl binds -j` for
# the shortcuts sheet does not allow a `hyprctl dispatch` anywhere else.
HELPERS = {
    "qs": (("CommandCenter/Actions.qml", "CommandCenter/CommandCenter.qml", "Bar/StatusCluster.qml"),
           "the shell's own IPC to itself (open a surface, probe its targets); "
           "a surface is not a device or session action"),
    "/usr/bin/date": (("Services/LocalTime.qml",),
                      "formats the bar clock; reads nothing a daemon owns"),
    "busctl": (("Services/Notifications.qml",),
               "the notification server checks which process owns its own bus name"),
    "rm": (("Theme/Theme.qml", "Services/WallpaperState.qml"),
           "drops the person's own theme or wallpaper preference file when the shell's "
           "own reset is asked for; `punarctl theme reset` removes the same file"),
    "/bin/sh": (("shell.qml",),
                "writes the shell's readiness marker at startup "
                "($XDG_RUNTIME_DIR/punar/shell-ready); not an action a person takes"),
    "/usr/lib/punar/punar-terminal-app.sh": (("Services/Apps.qml",),
        "the launcher's terminal adapter for a Terminal=true desktop entry; "
        "`punarctl app open <desktop-id>` runs the same adapter for the same entry"),
}

# A launch whose argv is a variable. Each names what fills it.
DYNAMIC = {
    ("Services/PasswordRun.qml", "argv"):
        "PasswordRun.start's funnel; every caller passes a literal /usr/bin/punarctl argv "
        "with --ticket-from-parent and the IPC method its ticket is for, which this test checks",
    ("SystemControl/ControlData.qml", "argv"):
        "runMutation's own funnel; every caller passes a literal argv this test checks",
    ("SystemControl/ControlData.qml", "probe"):
        "the Probe component's ask(argv); every caller passes a literal argv this test checks",
    ("Services/HyprlandActions.qml", "argv"):
        "the ordered punarctl queue; every entry comes from root.run([...]) literals this test checks",
    ("WindowActions/WindowActions.qml", "argv"):
        "runWindowVerb's funnel; every caller passes a literal punarctl argv this test checks",
    ("AiPanel/AiPanel.qml", "argv"):
        "the Kick component's ask(argv); every caller passes a literal argv this test checks",
}

# Whole files that run before any person's session exists.
FILE_EXCEPTIONS = {
    "Greeter/shell.qml": "the greeter runs before anyone has logged in: onboarding, login "
                         "and its keyboard layout act on no person's session, which is "
                         "what punarctl acts on",
}

# A launch: a call through one of the shell's process paths, or a Process's
# `command` (`x.command = …` or a declarative `command: …`). `.exec(` counts
# only with a literal array, because a RegExp has an `exec` too.
LAUNCH = re.compile(
    r"(?P<kind>execDetached|runMutation|\.ask|root\.run|runWindowVerb)\(\s*(?P<arg>\[|[A-Za-z_][\w.]*)"
    r"|(?P<ekind>\.exec)\(\s*(?P<earg>\[)"
    r"|(?P<prop>\.command\s*=|^\s*command\s*:)\s*(?P<parg>\[|[A-Za-z_][\w.]*)",
    re.MULTILINE,
)
FIRST = re.compile(r'\[\s*"([^"]+)"')


def literal_before(text, position, name):
    """The literal array a local variable was last given before `position`."""
    found = None
    for assignment in re.finditer(r"(?:\bvar\s+)?\b" + re.escape(name) + r"\s*=\s*\[", text[:position]):
        found = assignment.end() - 1
    return found


seen_kinds = set()

for qml in sorted(shell.rglob("*.qml")):
    relative = str(qml.relative_to(shell))
    if relative in FILE_EXCEPTIONS:
        continue
    text = qml.read_text()
    for match in LAUNCH.finditer(text):
        start = match.start()
        line_start = text.rfind("\n", 0, start) + 1
        line_text = text[line_start:text.find("\n", start)]
        stripped = line_text.strip()
        # Declarations and comments are not launches.
        if stripped.startswith("//") or stripped.startswith("function ") or stripped.startswith("*"):
            continue
        arg = match.group("arg") or match.group("earg") or match.group("parg")
        kind = match.group("kind") or match.group("ekind") or "command"
        line = text[:start].count("\n") + 1
        where = f"shell/punar-shell/{relative}:{line}"
        at = next(match.start(g) for g in ("arg", "earg", "parg") if match.group(g))
        if arg != "[":
            # A local variable given a literal array earlier is that literal.
            literal = literal_before(text, start, arg)
            if literal is not None:
                arg, at = "[", literal
        if arg == "[":
            first = FIRST.match(text, at)
            if first is None:
                problems.append(f"{where}: a {kind} argv whose program is not a string literal")
                continue
            program = first.group(1)
            seen_kinds.add(kind)
            if program in PUNARCTL:
                continue
            if program in HELPERS and relative in HELPERS[program][0]:
                continue
            problems.append(
                f"{where}: runs {program!r} directly. Route it through a punarctl verb, "
                "or add it to HELPERS, for this file, with the reason it is not one."
            )
        else:
            if kind == "command" and arg in {"true", "false"}:
                continue
            if (relative, arg.split(".")[0]) in DYNAMIC or (relative, arg) in DYNAMIC:
                continue
            problems.append(
                f"{where}: {kind} runs a computed argv ({arg}). Pass a literal punarctl "
                "argv, or document what fills it in DYNAMIC."
            )

for (relative, _), reason in DYNAMIC.items():
    if not (shell / relative).is_file():
        problems.append(f"DYNAMIC names {relative}, which no longer exists")
for name, (files, reason) in HELPERS.items():
    if len(reason) < 30:
        problems.append(f"the helper {name} needs a real reason")
    for relative in files:
        if not (shell / relative).is_file():
            problems.append(f"HELPERS lets {relative} run {name}, but that file no longer exists")
for name, reason in FILE_EXCEPTIONS.items():
    if len(reason) < 30:
        problems.append(f"the exception for {name} needs a real reason")

# PasswordRun (F0-S4) confirms the command it starts with a ticket punar-authd
# binds to that process, so what it starts is held to more than the rule
# above: every `<run>.start(argv, …, action)` on a PasswordRun instance passes
# punarctl's own argv by its ABSOLUTE path — a punarctl earlier on PATH would
# be the process the ticket is bound to — as a literal, or a local variable
# whose assignment is made only of literals; every one of those carries
# --ticket-from-parent, the relay PasswordRun implements; and the call names
# the IPC method the ticket is for, as a string literal that is a method name.
# Anything else would bind a confirmation to a program nobody reviewed, or
# leave punarctl waiting on a terminal it does not have.
password_starts = 0
for qml in sorted(shell.rglob("*.qml")):
    relative = str(qml.relative_to(shell))
    text = qml.read_text()
    runs = re.findall(r"PasswordRun\s*\{\s*id:\s*(\w+)", text)
    for run in runs:
        for call in re.finditer(re.escape(run) + r"\.start\(\s*(\[|[A-Za-z_]\w*)", text):
            line = text[: call.start()].count("\n") + 1
            where = f"shell/punar-shell/{relative}:{line}"
            if call.group(1) == "[":
                statement = text[call.end(1) - 1 : text.find("]", call.end(1)) + 1]
            else:
                assigned = None
                for assignment in re.finditer(
                    r"(?:\bvar\s+)?\b" + re.escape(call.group(1)) + r"\s*=([^;]*);",
                    text[: call.start()],
                ):
                    assigned = assignment.group(1)
                if assigned is None:
                    problems.append(f"{where}: {run}.start() is given {call.group(1)}, which is never assigned a literal argv")
                    continue
                statement = assigned
            literals = re.findall(r"\[[^\[\]]*\]", statement)
            if not literals:
                problems.append(f"{where}: {run}.start() is not given a literal argv")
                continue
            for literal in literals:
                first = FIRST.match(literal)
                if first is None or first.group(1) != "/usr/bin/punarctl":
                    problems.append(f"{where}: {run}.start() would bind a confirmation to {literal[:40]}…, not /usr/bin/punarctl")
                if '"--ticket-from-parent"' not in literal:
                    problems.append(f"{where}: {run}.start() runs an argv without --ticket-from-parent")
                if '"--password-from-parent"' in literal:
                    problems.append(f"{where}: {run}.start() still passes the removed --password-from-parent")
            # The call's last argument: the IPC method the ticket is for.
            depth, end = 0, None
            for index in range(call.start(1), len(text)):
                char = text[index]
                if char in "([":
                    depth += 1
                elif char in ")]":
                    if depth == 0:
                        end = index
                        break
                    depth -= 1
            tail = text[call.start(1):end] if end is not None else ""
            method = re.search(r',\s*"([a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+)"\s*$', tail)
            if method is None:
                problems.append(f"{where}: {run}.start() does not name the IPC method its ticket is for")
            password_starts += 1
if password_starts == 0:
    problems.append("no PasswordRun.start() call was found; the DYNAMIC entry for PasswordRun is unchecked")

# The funnels are only safe while their callers pass literals: the scan above
# must have seen literal argvs through each of them.
for funnel in ["runMutation", ".ask", "root.run", "runWindowVerb"]:
    if funnel not in seen_kinds:
        problems.append(f"no literal argv was found through {funnel}; the DYNAMIC entry for it is unchecked")

# ---------------------------------------------------------------------------
# Rule 2: every System Control view has its verb.
# ---------------------------------------------------------------------------

table = json.loads((root / "tests/desktop/system-control-verbs.json").read_text())["views"]
control = (shell / "SystemControl/ControlData.qml").read_text()
views = set(re.findall(r'\{id: "([a-z]+)", name: "', control))
if not views:
    problems.append("found no System Control view ids in ControlData.qml")
for view in sorted(views - set(table)):
    problems.append(f"System Control view {view!r} has no entry in system-control-verbs.json")
for view in sorted(set(table) - views):
    problems.append(f"system-control-verbs.json lists {view!r}, which is not a System Control view")
for view, entry in sorted(table.items()):
    verb, exception = entry.get("verb"), entry.get("exception")
    if (verb is None) == (exception is None):
        problems.append(f"{view}: give exactly one of `verb` or `exception`")
    if verb is not None and not (isinstance(verb, list) and verb and all(isinstance(v, str) for v in verb)):
        problems.append(f"{view}: `verb` is punarctl's argv, a list of strings")
    if exception is not None and len(exception) < 30:
        problems.append(f"{view}: the exception needs a real reason")

if problems:
    for problem in problems:
        print(f"terminal-parity-gate-test: FAIL: {problem}", file=sys.stderr)
    sys.exit(1)
verbs = sum(1 for entry in table.values() if "verb" in entry)
print(f"terminal-parity-gate-test: ok ({verbs} of {len(table)} views have a verb; "
      f"{len(HELPERS)} fixed helpers and {len(DYNAMIC)} funnels documented)")
PY
