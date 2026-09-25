#!/bin/sh
# The desktop shell's supervisor and PUNAR+SHIFT+E's helper (F0 review).
#
# punar-shell-run: the shell runs with RLIMIT_CORE 0, soft AND hard; a crash
# starts it again; an exit a person asked for (0, SIGTERM) does not; five
# quick crashes stop the loop; and the loop ends with the compositor.
#
# punar-end-session: with the shell answering, the chord only asks the shell;
# without it, one press arms and draws a notification, a second press inside
# five seconds ends the session through punarctl, and a press after the window
# only arms again. Nothing ends on one press.
set -eu

REPO_ROOT="$(cd -- "$(dirname "$0")/../.." && pwd)"
HYPR="${REPO_ROOT}/os/modules/desktop/hypr"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/punar-shell-run-test.XXXXXX")"
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

fail() {
    printf 'shell-run-test: FAIL: %s\n' "$*" >&2
    exit 1
}

mkdir -p "${TEST_ROOT}/bin" "${TEST_ROOT}/runtime/hypr/sig"
XDG_RUNTIME_DIR="${TEST_ROOT}/runtime"
HYPRLAND_INSTANCE_SIGNATURE=sig
PATH="${TEST_ROOT}/bin:${PATH}"
export XDG_RUNTIME_DIR HYPRLAND_INSTANCE_SIGNATURE PATH

# The compositor's instance socket: a real socket, as `[ -S ]` requires.
python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.bind(sys.argv[1])' \
    "${XDG_RUNTIME_DIR}/hypr/sig/.socket.sock"
: > "${TEST_ROOT}/logger.log"
cat > "${TEST_ROOT}/bin/logger" <<LOGGER
#!/bin/sh
printf '%s\n' "\$*" >> "${TEST_ROOT}/logger.log"
LOGGER
cat > "${TEST_ROOT}/bin/sleep" <<'SLEEP'
#!/bin/sh
exit 0
SLEEP

# A fake shell: records its core limits, then exits with the next status in
# the script (one per line), or 143 once the script is used up.
cat > "${TEST_ROOT}/bin/qs" <<QS
#!/bin/sh
case "\$*" in
    *"ipc call"*) exit "\$(cat "${TEST_ROOT}/ipc-status")" ;;
esac
grep -i '^Max core file size' /proc/\$\$/limits >> "${TEST_ROOT}/limits.log"
n=\$(( \$(cat "${TEST_ROOT}/runs" 2>/dev/null || echo 0) + 1 ))
printf '%s\n' "\${n}" > "${TEST_ROOT}/runs"
status=\$(sed -n "\${n}p" "${TEST_ROOT}/statuses")
exit "\${status:-143}"
QS
chmod 0755 "${TEST_ROOT}/bin/"*

run_supervisor() {
    printf '%s\n' "$@" > "${TEST_ROOT}/statuses"
    rm -f "${TEST_ROOT}/runs" "${TEST_ROOT}/limits.log"
    set +e
    sh "${HYPR}/punar-shell-run.sh"
    supervisor_status=$?
    set -e
    runs=$(cat "${TEST_ROOT}/runs")
}

# A crash is restarted; SIGTERM afterwards is a person asking, and ends it.
run_supervisor 139 134 143
[ "${runs}" = 3 ] || fail "a crash was not restarted (ran ${runs} times)"
[ "${supervisor_status}" = 143 ] || fail "SIGTERM did not end the loop (${supervisor_status})"
while read -r line; do
    case "${line}" in
        *" 0 "*" 0 "*) ;;
        *) fail "the shell ran without a zero core limit, soft and hard: ${line}" ;;
    esac
done < "${TEST_ROOT}/limits.log"
printf 'ok   a crash restarts the shell, SIGTERM stops it, core limit 0 soft and hard\n'

# A clean exit is not restarted.
run_supervisor 0
[ "${runs}" = 1 ] || fail "a clean exit was restarted"
printf 'ok   a clean exit is not restarted\n'

# Five quick crashes stop the loop, and say so.
run_supervisor 139 139 139 139 139 139 139
[ "${runs}" = 5 ] || fail "a crash loop ran ${runs} times, not 5"
grep -q 'five times' "${TEST_ROOT}/logger.log" || fail "the crash loop stopped without saying so"
printf 'ok   five quick crashes stop the loop, logged\n'

# The compositor gone: no restart.
mv "${XDG_RUNTIME_DIR}/hypr/sig/.socket.sock" "${TEST_ROOT}/socket.moved"
run_supervisor 139 139
[ "${runs}" = 1 ] || fail "the shell was restarted after the compositor went away"
mv "${TEST_ROOT}/socket.moved" "${XDG_RUNTIME_DIR}/hypr/sig/.socket.sock"
printf 'ok   no restart once the compositor has gone\n'

# --- punar-end-session -----------------------------------------------------
sed "s#exec /usr/bin/punarctl session end#exec ${TEST_ROOT}/bin/punarctl session end#" \
    "${HYPR}/punar-end-session.sh" > "${TEST_ROOT}/end-session"
cat > "${TEST_ROOT}/bin/punarctl" <<CTL
#!/bin/sh
printf '%s\n' "\$*" >> "${TEST_ROOT}/ended.log"
CTL
cat > "${TEST_ROOT}/bin/hyprctl" <<HCTL
#!/bin/sh
printf '%s\n' "\$*" >> "${TEST_ROOT}/notified.log"
HCTL
chmod 0755 "${TEST_ROOT}/bin/punarctl" "${TEST_ROOT}/bin/hyprctl"
press() { sh "${TEST_ROOT}/end-session"; }

# The shell answers: it alone asks.
echo 0 > "${TEST_ROOT}/ipc-status"
press
press
[ ! -e "${TEST_ROOT}/ended.log" ] || fail "the helper ended the session although the shell answered"
[ ! -e "${TEST_ROOT}/notified.log" ] || fail "the helper drew its own prompt although the shell answered"
printf 'ok   with the shell there, the chord only asks the shell\n'

# No shell: one press arms and tells the person; the second ends.
echo 255 > "${TEST_ROOT}/ipc-status"
press
[ ! -e "${TEST_ROOT}/ended.log" ] || fail "one press ended the session"
grep -q 'notify' "${TEST_ROOT}/notified.log" || fail "the first press did not say what a second would do"
press
[ "$(cat "${TEST_ROOT}/ended.log" 2>/dev/null)" = "session end" ] \
    || fail "a second press within the window did not end the session"
printf 'ok   without the shell, one press arms, the second ends it\n'

# A press after the window only arms again.
rm -f "${TEST_ROOT}/ended.log"
printf '%s\n' "$(( $(date +%s) - 60 ))" > "${XDG_RUNTIME_DIR}/punar-end-session.armed"
press
[ ! -e "${TEST_ROOT}/ended.log" ] || fail "a press a minute after arming ended the session"
[ -f "${XDG_RUNTIME_DIR}/punar-end-session.armed" ] || fail "a late press did not arm again"
printf 'ok   a press after the window only arms again\n'
printf 'shell-run-test: ok\n'
