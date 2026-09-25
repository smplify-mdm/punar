#!/usr/bin/env bash
# Ending the session from the keyboard asks first.
#
# THE FINDING THIS EXISTS FOR (first-party apps review, PLAN.md section 7).
# PUNAR+SHIFT+E was bound straight to the compositor's exit dispatcher. It sits
# beside PUNAR+SHIFT+W, +Q, +R and +F, and ending a session closes every window
# in it with no undo, so one slipped chord cost a person every unsaved
# document. The session menu already had the confirmation this needs: a
# destructive row arms on the first press and acts on the second.
#
# So the chord now opens that menu with "End session" armed. This test pins
# every link of that chain, because each one failing alone would silently
# restore the one-press exit or make the chord do nothing:
#
#   1. no keyboard bind in either compositor config calls the exit dispatcher;
#   2. the Lua bind for PUNAR+SHIFT+E runs ctx.session_end;
#   3. hyprland.lua defines session_end as the shell's `session endSession` IPC;
#   4. shell.qml's `session` IpcHandler has endSession, and it reaches
#      SessionMenu.requestSessionEnd without opening anything else;
#   5. requestSessionEnd arms through activate("sessionEnd"), and activate()
#      acts only when the same row is already armed — the arm-then-act rule;
#   6. show() disarms, so opening the menu can never inherit an armed row.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HYPR="${REPO_ROOT}/os/modules/desktop/hypr"
SHELL_DIR="${REPO_ROOT}/shell/punar-shell"

python3 - "${HYPR}" "${SHELL_DIR}" <<'PY'
import re
import sys

hypr, shell = sys.argv[1], sys.argv[2]
failures = []


def fail(message):
    failures.append(message)


def read(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def strip_lua_comments(text):
    return "\n".join(line.split("--", 1)[0] for line in text.splitlines())


def strip_hash_comments(text):
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))


def function_body(src, name):
    match = re.search(r"function\s+" + re.escape(name) + r"\s*\([^)]*\)\s*:\s*\w+\s*\{", src)
    if not match:
        return None
    depth, start = 1, match.end()
    for index in range(start, len(src)):
        if src[index] == "{":
            depth += 1
        elif src[index] == "}":
            depth -= 1
            if depth == 0:
                return src[start:index]
    return None


binds_lua = strip_lua_comments(read(f"{hypr}/punar-binds.lua"))
hyprland_lua = strip_lua_comments(read(f"{hypr}/hyprland.lua"))
binds_conf = strip_hash_comments(read(f"{hypr}/punar-binds.conf"))

# 1. The exit dispatcher is never a keyboard bind.
if re.search(r"hl\.dsp\.exit\s*\(", binds_lua):
    fail("punar-binds.lua binds the compositor's exit dispatcher; ending the session must ask first")
for line in binds_conf.splitlines():
    if re.match(r"\s*bind\w*\s*=", line) and re.search(r",\s*exit\s*(,|$)", line):
        fail(f"punar-binds.conf binds the exit dispatcher: {line.strip()}")

# 2. PUNAR+SHIFT+E runs ctx.session_end.
chord = re.search(r'bind\(\s*mod\s*\.\.\s*"\s*\+\s*SHIFT\s*\+\s*E"\s*,\s*([^\n]*)', binds_lua)
if not chord:
    fail("punar-binds.lua has no PUNAR+SHIFT+E bind")
elif not re.match(r"hl\.dsp\.exec_cmd\(\s*ctx\.session_end\s*\)", chord.group(1)):
    fail(f"PUNAR+SHIFT+E does not run ctx.session_end: {chord.group(1).strip()}")

# 3. ctx.session_end is the shell's confirming IPC call.
defined = re.search(r'local\s+sessionEnd\s*=\s*"([^"]*)"', hyprland_lua)
if not defined or defined.group(1) != "qs -p /usr/share/punar/shell ipc call session endSession":
    fail("hyprland.lua does not define sessionEnd as `qs -p /usr/share/punar/shell ipc call session endSession`")
if not re.search(r"\bsession_end\s*=\s*sessionEnd\b", hyprland_lua):
    fail("hyprland.lua does not pass session_end = sessionEnd to punar-binds.lua")

# The legacy hyprlang file mirrors the same call.
if not re.search(
    r"bindd\s*=\s*\$mod SHIFT,\s*E,[^,]*,\s*exec,\s*qs -p /usr/share/punar/shell ipc call session endSession\s*$",
    binds_conf,
    re.M,
):
    fail("punar-binds.conf does not mirror PUNAR+SHIFT+E as the confirming IPC call")

# 4. The IPC handler reaches requestSessionEnd.
shell_qml = read(f"{shell}/shell.qml")
handler = re.search(r'IpcHandler\s*\{\s*target:\s*"session"(.*?)\n    \}', shell_qml, re.S)
if not handler:
    fail("shell.qml has no `session` IpcHandler")
else:
    body = function_body(handler.group(1), "endSession")
    if body is None:
        fail("the `session` IpcHandler has no endSession()")
    else:
        if "ensureLoaded(false)" not in body:
            fail("endSession() must load the menu without opening it by itself (ensureLoaded(false))")
        if "requestSessionEnd()" not in body:
            fail("endSession() does not call requestSessionEnd()")
        if re.search(r"punarctl|session\s+end|\.exec\(", body):
            fail("endSession() ends something itself instead of arming the menu")

base = read(f"{shell}/Services/DeferredSurfaceBase.qml")
if function_body(base, "requestSessionEnd") is None:
    fail("DeferredSurfaceBase.qml does not declare requestSessionEnd(), so the call is not typed")

# 5. and 6. Arm, then act; and opening disarms.
menu = read(f"{shell}/SessionMenu/SessionMenu.qml")
request = function_body(menu, "requestSessionEnd")
if request is None:
    fail("SessionMenu.qml has no requestSessionEnd()")
else:
    if 'activate("sessionEnd")' not in request:
        fail('requestSessionEnd() does not go through activate("sessionEnd")')
    if re.search(r"power\.exec|punarctl", request):
        fail("requestSessionEnd() runs something itself instead of arming")
activate = function_body(menu, "activate")
if activate is None:
    fail("SessionMenu.qml has no activate()")
else:
    arm = activate.find("if (root.armed !== kind)")
    act = activate.find('power.exec(["/usr/bin/punarctl", "session", "end"])')
    if arm < 0 or act < 0 or arm > act:
        fail("activate() no longer arms a row before it runs `punarctl session end`")
    arm_block = activate[arm:activate.find("}", arm)]
    if "return" not in arm_block:
        fail("activate() does not stop after arming a row")
show = function_body(menu, "show")
if show is None or 'root.armed = ""' not in show:
    fail("SessionMenu.show() does not disarm, so a reopened menu could act on one press")

if failures:
    for message in failures:
        print(f"session-end-confirm-contract-test: FAIL: {message}", file=sys.stderr)
    sys.exit(1)
print("session-end-confirm-contract-test: ok")
PY
