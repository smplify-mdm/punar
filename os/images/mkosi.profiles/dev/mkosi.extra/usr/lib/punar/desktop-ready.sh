#!/bin/sh
# Desktop ready detector (milestone-1.md §7 step 2). Runs as the session
# user via Hyprland `exec-once` — LAST in the exec-once order, so the shell
# has already been launched when this starts.
#
# Waits for punar-shell's own private ready flag (below XDG_RUNTIME_DIR,
# touched by shell.qml once the bar completes), captures rendering + meminfo
# into /run/punar, then creates /run/punar/desktop-ready — which triggers
# the root punar-desktop-marker.path/.service to print PUNAR_DESKTOP_OK on
# the serial console. /run/punar is created by tmpfiles.d (0755 punar punar).

RUN_DIR=/run/punar
SHELL_READY_DIR=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/punar
SHELL_READY=${SHELL_READY_DIR}/shell-ready
WAIT_SECS=180

i=0
while [ "${i}" -lt "${WAIT_SECS}" ]; do
    [ -e "${SHELL_READY}" ] && break
    i=$((i + 1))
    sleep 1
done

if [ ! -e "${SHELL_READY}" ]; then
    # Fallback signal per the shell contract: is a quickshell process up at
    # all? Proceed either way — a screenshot of a shell-less session is
    # still diagnostic gold in CI, and the RAM measurement must still run.
    if pgrep -f 'quickshell|qs -p' >/dev/null 2>&1; then
        echo "punar: desktop-ready: shell-ready flag missing but quickshell is running; proceeding" >&2
    else
        echo "punar: desktop-ready: shell-ready flag missing and no quickshell process after ${WAIT_SECS}s" >&2
    fi
fi

# Let the first frames land before capturing.
sleep 2

# Proof of real rendering (llvmpipe): grim uses wlr-screencopy against the
# live compositor. Non-fatal — the marker chain must not die on a
# screenshot failure; CI treats a missing screenshot as its own signal.
# Dismiss transient compositor notices (e.g. the 0.56 .conf-format
# deprecation banner) so the proof screenshot shows the desktop, not chrome.
hyprctl dismissnotify -1 >/dev/null 2>&1 || true
grim "${RUN_DIR}/screenshot.png" || echo "punar: desktop-ready: grim screenshot failed" >&2

cat /proc/meminfo > "${RUN_DIR}/meminfo" 2>/dev/null || true

: > "${RUN_DIR}/desktop-ready"
