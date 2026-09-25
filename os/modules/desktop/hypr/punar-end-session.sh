#!/bin/sh
# punar-end-session — what PUNAR+SHIFT+E runs: ask before ending the session,
# whether or not the desktop shell is there to ask (F0 review).
#
# With the shell: its session menu opens with "End session" armed, and only a
# second press (or E, or a click) signs out (SessionMenu.qml). That is the
# whole path whenever the shell answers its IPC.
#
# Without the shell (it crashed, or has not started yet): the chord used to do
# nothing, because it only called the shell. Now the compositor asks: the
# first press draws Hyprland's own notification saying what a second press
# will do, and arms the chord for five seconds; a second press inside that
# window runs `punarctl session end`, the same verb the menu and a terminal
# use. A press after the window only arms it again. Nothing ends on one press.

set -u

shell_ipc() {
    qs -p /usr/share/punar/shell ipc call session endSession >/dev/null 2>&1
}

if shell_ipc; then
    exit 0
fi

runtime=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
armed="${runtime}/punar-end-session.armed"
now=$(date +%s)
if [ -f "${armed}" ] && [ ! -L "${armed}" ]; then
    then_s=$(head -c 32 "${armed}" 2>/dev/null | tr -cd '0-9')
    rm -f "${armed}"
    if [ -n "${then_s}" ] && [ $((now - then_s)) -ge 0 ] && [ $((now - then_s)) -le 5 ]; then
        exec /usr/bin/punarctl session end
    fi
fi
rm -f "${armed}"
(umask 077 && printf '%s\n' "${now}" > "${armed}")
hyprctl notify 1 5000 "rgb(ff9e3b)" \
    "The desktop shell is not running. Press PUNAR+SHIFT+E again within 5 seconds to end the session." \
    >/dev/null 2>&1 || true
