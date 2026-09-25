#!/bin/sh
# punar-shell-run — start the desktop shell for this Hyprland session, with no
# core dumps, and start it again if it crashes (F0 review).
#
# NO CORE FILE, SOFT OR HARD. The shell holds a password as a string while a
# person types it (System Control, the approval overlay, Command Center, the
# lock screen), and a JavaScript string is only dropped, never wiped. Yama
# (usr/lib/sysctl.d/50-punar-yama.conf) stops another program of the same
# person from attaching to the shell; a crash dump would hand it the same
# memory anyway: `kill -SEGV` the shell, then read the core systemd-coredump
# keeps for that person. RLIMIT_CORE 0 makes systemd-coredump store nothing
# for this process, and because the HARD limit is 0 as well, no program of
# the person can raise it again (raising a hard limit needs CAP_SYS_RESOURCE;
# prlimit(2) on another process of the same uid can only lower it).
#
# RESTARTED AFTER A CRASH. PUNAR+SHIFT+E, the lock chord and every surface
# are the shell's. It used to be started once, so a crash left the session
# with no lock screen and no way to end it but a terminal. A crash — the shell
# killed by a fault signal (SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE) or by
# SIGKILL (the out-of-memory killer), or exiting with an error — starts it
# again after a second. An exit a person asked for (status 0, or SIGTERM,
# SIGINT, SIGHUP: `pkill`, the m2 gate's restart test) is left alone. Five
# crashes within half a minute each stop the loop and say so in the journal:
# a shell that cannot start must not spin. The loop also ends with the
# compositor, whose instance socket goes away when the session does.
#
# Started by hyprland.lua as `/usr/lib/punar/punar-shell-run`.

set -u

# RLIMIT_CORE 0, soft and hard, for this process and everything it starts.
# util-linux's prlimit is the portable spelling; the shell builtin is the
# fallback (dash and bash both set soft and hard together without -S/-H).
if ! prlimit --pid "$$" --core=0:0 2>/dev/null; then
    # shellcheck disable=SC3045 # every /bin/sh a Punar lane ships has it
    ulimit -c 0
fi

shell_argv_path=/usr/share/punar/shell
signature=${HYPRLAND_INSTANCE_SIGNATURE:-}
runtime=${XDG_RUNTIME_DIR:-/run/user/$(id -u)}
instance_socket="${runtime}/hypr/${signature}/.socket.sock"

compositor_alive() {
    [ -n "${signature}" ] && [ -S "${instance_socket}" ]
}

say() {
    logger -t punar-shell-run -- "$*" 2>/dev/null || printf 'punar-shell-run: %s\n' "$*" >&2
}

quick_crashes=0
while :; do
    started=$(date +%s)
    qs -p "${shell_argv_path}"
    status=$?
    case "${status}" in
        # Asked to stop: exit 0, SIGHUP (129), SIGINT (130), SIGTERM (143).
        0 | 129 | 130 | 143) exit "${status}" ;;
    esac
    compositor_alive || exit "${status}"
    ran=$(( $(date +%s) - started ))
    if [ "${ran}" -lt 30 ]; then
        quick_crashes=$((quick_crashes + 1))
    else
        quick_crashes=1
    fi
    if [ "${quick_crashes}" -ge 5 ]; then
        say "the desktop shell exited with status ${status} five times within 30 seconds each; not starting it again (PUNAR+SHIFT+E still asks, through the compositor)"
        exit "${status}"
    fi
    say "the desktop shell exited with status ${status}; starting it again"
    sleep 1
done
