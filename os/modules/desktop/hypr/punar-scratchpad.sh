#!/bin/sh
# Demand-start the terminal scratchpad, then toggle its special workspace.
#
# The terminal used to be pre-spawned at every login and retained roughly
# 6 MiB of PSS even when a person never opened it. The ordinary foot server
# remains warm, so a footclient window is cheap to create; paying that cost on
# the first PUNAR+T is a better resource contract than billing every session.
# No user-controlled value reaches a shell command: this helper has no args
# and both the app-id and workspace name are fixed product identifiers.

set -u

# Serialize summons until the first client maps. Without this lock, two quick
# key presses can both observe "absent" and create duplicate scratchpads.
# XDG_RUNTIME_DIR is private to this login session and always exists under
# greetd; failing closed is preferable to falling back to a shared /tmp lock.
: "${XDG_RUNTIME_DIR:?XDG_RUNTIME_DIR is required}"
exec 9>"${XDG_RUNTIME_DIR}/punar-scratchpad.lock"
flock 9

if hyprctl -j clients 2>/dev/null \
        | jq -e 'any(.[]; .class == "punar-scratch")' >/dev/null 2>&1; then
    exec hyprctl dispatch "hl.dsp.workspace.toggle_special('term')"
fi

# The window rule parks this app-id on special:term silently. Wait only on the
# cold path so the workspace is toggled after the client maps; this removes a
# compositor-ordering race and keeps the ordinary toggle path synchronous.
# --no-wait separates launch success from the eventual shell exit status. A
# normally closed scratchpad must not be mistaken for a server failure and
# immediately replaced by a standalone foot window. foot remains the fixed
# fallback when the warm server is genuinely unavailable after a crash.
if ! footclient --no-wait --app-id=punar-scratch >/dev/null 2>&1; then
    foot --app-id=punar-scratch >/dev/null 2>&1 &
fi

attempt=0
while [ "${attempt}" -lt 100 ]; do
    if hyprctl -j clients 2>/dev/null \
            | jq -e 'any(.[]; .class == "punar-scratch")' >/dev/null 2>&1; then
        exec hyprctl dispatch "hl.dsp.workspace.toggle_special('term')"
    fi
    attempt=$((attempt + 1))
    sleep 0.02
done

exit 1
