#!/bin/sh
# Punar keys, keyboard layout and window grammar in-VM exercise (SMP-1405
# WP-02).
#
# WHAT IT PROVES, on the running desktop:
#   * the keyboard layout is one device setting: the person at the machine
#     sets it with `punarctl keyboard layout set` (punard's person-scoped
#     system.keymap, audited under their name), /etc/vconsole.conf records
#     it, the session's data file and the live compositor load it, and the
#     lock screen names it;
#   * a layout that cannot type Latin letters (Russian, the plan's
#     acceptance case) is loaded behind a US first group with the both-Alt
#     switch chord, so PUNAR+Return still opens a terminal, and after the
#     chord that terminal receives Cyrillic;
#   * a workspace keeps its own layout preset, live and across sessions;
#   * the keys do what the grammar says, pressed as REAL KEYS: Alt+Tab, the
#     tenth workspace, a quiet move, maximize, pop-out, and pointer move and
#     resize with PUNAR held.
#
# HOW KEYS ARE PRESSED. The desktop gate (tools/boot-test.sh) runs
# tools/qmp-keys.py beside QEMU. This script prints `PUNAR_QMP_KEYS <id>
# <sequence>` on the console; the driver sends that named sequence as
# keyboard and pointer events over QMP, and this script then checks the
# effect through the compositor. The first request is a handshake: a probe
# window must receive "ok" typed on the keyboard, so a missing driver is a
# FAIL with its own message, never a pile of confusing ones.
#
# Runs as User=punar (the surfaces-check pattern): every assertion is scoped
# to the person's session. ALWAYS exits 0; the verdict is the last line of
# /run/punar/keys-report.txt (PUNAR_KEYS_OK / PUNAR_KEYS_FAIL), hard-gated by
# tools/boot-test.sh, including a missing report.
#
# It leaves the session as it found it: the device's layout is set back, the
# probe windows are closed and workspace 1 is focused again.
#
# Predicates below are invoked indirectly through `wait_for` (shellcheck
# cannot see that; the surfaces-check.sh precedent).
# shellcheck disable=SC2329
set -u

REPORT=/run/punar/keys-report.txt
FAILED=0
SHELL_CMD="qs -p /usr/share/punar/shell"
CTL=/usr/bin/punarctl

mkdir -p /run/punar
: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }
fail() { note "FAIL $*"; FAILED=1; }

check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        fail "$1 (expected '$2', got '$3')"
    fi
}

wait_for() {
    wf_tenths=$(( $1 * 10 )); shift; wf_i=0
    while [ "${wf_i}" -lt "${wf_tenths}" ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        wf_i=$((wf_i + 1)); sleep 0.1
    done
    return 1
}

finish() {
    cleanup
    if [ "${FAILED}" -eq 0 ]; then
        note "PUNAR_KEYS_OK"
    else
        note "PUNAR_KEYS_FAIL"
    fi
    cat "${REPORT}"
    exit 0
}

note "# Punar keys, keyboard layout and window grammar — $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- session env discovery (surfaces-check.sh pattern) ------------------------
XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XDG_RUNTIME_DIR
HIS=""
for d in "${XDG_RUNTIME_DIR}/hypr/"*/; do
    [ -d "${d}" ] || continue
    HIS="$(basename "${d}")"; break
done
WAYLAND_DISPLAY=""
for s in "${XDG_RUNTIME_DIR}"/wayland-*; do
    case "${s}" in
        *.lock) ;;
        *) [ -e "${s}" ] && WAYLAND_DISPLAY="$(basename "${s}")" && break ;;
    esac
done
HYPRLAND_INSTANCE_SIGNATURE="${HIS}"
export HYPRLAND_INSTANCE_SIGNATURE WAYLAND_DISPLAY
note "# instance=${HIS:-none} wayland=${WAYLAND_DISPLAY:-none} uid=$(id -u) user=$(id -un)"

ipc() { ${SHELL_CMD} ipc call "$@" 2>/dev/null | tr -d '"' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }

ORIGINAL_LAYOUT=""
PROBES=""
cleanup() {
    for probe_address in ${PROBES}; do
        "${CTL}" window close --address "${probe_address}" >/dev/null 2>&1 || true
    done
    PROBES=""
    if [ -n "${ORIGINAL_LAYOUT}" ]; then
        "${CTL}" keyboard layout set "${ORIGINAL_LAYOUT}" >/dev/null 2>&1 || true
        ORIGINAL_LAYOUT=""
    fi
    "${CTL}" workspace focus 1 >/dev/null 2>&1 || true
}

if [ -z "${HIS}" ] || [ -z "${WAYLAND_DISPLAY}" ]; then
    fail "no Hyprland session (instance='${HIS}', wayland='${WAYLAND_DISPLAY}')"
    finish
fi

# --- helpers over the compositor, all through punarctl or read-only hyprctl ---
clients() { hyprctl -j clients 2>/dev/null; }
address_of() { clients | jq -r --arg c "$1" '[.[] | select(.class == $c)][0].address // ""'; }
active_address() { hyprctl -j activewindow 2>/dev/null | jq -r '.address // ""'; }
active_workspace() { hyprctl -j activeworkspace 2>/dev/null | jq -r '.id // ""'; }
client_field() { clients | jq -r --arg a "$1" "[.[] | select(.address == \$a)][0]$2 // \"\""; }
terminal_count() { clients | jq '[.[] | select(.class == "foot" or .class == "footclient")] | length'; }
keymaps() { hyprctl -j devices 2>/dev/null | jq -r '[.keyboards[].active_keymap] | join(",")'; }
option() { hyprctl -j getoption "$1" 2>/dev/null | jq -r '.str // ""'; }

REQ=0
# Ask the host's QMP driver for one named sequence. Printed to stdout, which
# the unit sends to the serial console the driver reads.
press() {
    REQ=$((REQ + 1))
    printf 'PUNAR_QMP_KEYS %s %s\n' "${REQ}" "$*"
}

PROBE_SCRIPT="${XDG_RUNTIME_DIR}/punar/keys-probe.sh"
mkdir -p "${XDG_RUNTIME_DIR}/punar"
cat > "${PROBE_SCRIPT}" <<'PROBE'
#!/bin/sh
# One line typed into this window, recorded verbatim.
IFS= read -r line
printf '%s\n' "${line}" > "$1"
sleep 30
PROBE
chmod 0700 "${PROBE_SCRIPT}"

# A foot window with its own app id that records the one line typed into it;
# prints its address. Called in a command substitution, so the caller keeps
# the address for cleanup, and foot's own output goes nowhere near the pipe.
open_probe() {
    op_class="$1"; op_out="$2"
    rm -f "${op_out}"
    foot --app-id "${op_class}" "${PROBE_SCRIPT}" "${op_out}" >/dev/null 2>&1 &
    if ! wait_for 20 probe_mapped "${op_class}"; then
        return 1
    fi
    address_of "${op_class}"
}
probe_mapped() { [ -n "$(address_of "$1")" ]; }
focus_window() {
    "${CTL}" window focus --address "$1" >/dev/null 2>&1
    wait_for 5 is_active "$1"
}
is_active() { [ "$(active_address)" = "$1" ]; }
file_is() { [ -f "$1" ] && [ "$(cat "$1")" = "$2" ]; }
lock_is() { [ "$(ipc lock state)" = "$1" ]; }
more_terminals() { [ "$(terminal_count)" -gt "$1" ]; }
keymap_has() { keymaps | grep -q "$1"; }
on_workspace() { [ "$(active_workspace)" = "$1" ]; }
window_on() { [ "$(client_field "$1" .workspace.id)" = "$2" ]; }
field_is() { [ "$(client_field "$1" "$2")" = "$3" ]; }
moved_by() {
    mb_x="$(client_field "$1" '.at[0]')"; mb_y="$(client_field "$1" '.at[1]')"
    [ $((mb_x - $2)) -ge 80 ] && [ $((mb_y - $3)) -ge 60 ]
}
resized_from() {
    rf_w="$(client_field "$1" '.size[0]')"; rf_h="$(client_field "$1" '.size[1]')"
    [ "${rf_w}" != "$2" ] || [ "${rf_h}" != "$3" ]
}
abs() { printf '%s %s\n' "$1" "$2" | awk '{printf "%d", $1 * 32767 / $2}'; }
tiled_is() { [ "$(hyprctl -j activeworkspace 2>/dev/null | jq -r '.tiledLayout // ""')" = "$1" ]; }

# --- 1. the device's layout, set by the person at the machine ----------------
ORIGINAL="$("${CTL}" --json keyboard layout status 2>/dev/null | jq -r '.device // ""')"
note "# layout before the exercise: ${ORIGINAL:-unknown}"
case "${ORIGINAL}" in
    ''|*[!A-Za-z0-9_+,-]*) ORIGINAL=us ;;
esac

non_latin_missing="$("${CTL}" --json keyboard layout list 2>/dev/null \
    | jq -r '[.non_latin[]? | select(.installed != true) | .layout] | join(",")')"
non_latin_count="$("${CTL}" --json keyboard layout list 2>/dev/null | jq '[.non_latin[]?] | length')"
if [ "${non_latin_count:-0}" -gt 0 ] && [ -z "${non_latin_missing}" ]; then
    note "ok   every layout punar treats as non-Latin (${non_latin_count}) is installed on this image"
else
    fail "non-Latin layouts missing from the image's XKB list: '${non_latin_missing}' (of ${non_latin_count:-0})"
fi

if "${CTL}" keyboard layout set ru > /run/punar/keys-set.txt 2>&1; then
    ORIGINAL_LAYOUT="${ORIGINAL}"
    note "ok   punarctl keyboard layout set ru, as $(id -un), without an administrator"
else
    fail "punarctl keyboard layout set ru was refused: $(head -c 300 /run/punar/keys-set.txt)"
fi
check_eq "XKBLAYOUT in /etc/vconsole.conf" "XKBLAYOUT=ru" "$(grep '^XKBLAYOUT=' /etc/vconsole.conf 2>/dev/null)"
audited="$("${CTL}" --json audit tail -n 20 2>/dev/null \
    | jq -r '[.events[]? | select(.action == "capabilities.set" and .resource == "system.keymap" and .decision == "allow")] | last | .user_id // ""')"
check_eq "the change is audited under the person's name" "$(id -un)" "${audited}"
if grep -q '^    kb_layout = "us,ru",$' "${XDG_RUNTIME_DIR}/punar/session/input.lua" 2>/dev/null; then
    note "ok   the session's data file carries us,ru"
else
    fail "the session's data file does not carry us,ru: $(tr '\n' ' ' < "${XDG_RUNTIME_DIR}/punar/session/input.lua" 2>/dev/null | head -c 200)"
fi
check_eq "live input:kb_layout (Latin first)" "us,ru" "$(option input:kb_layout)"
check_eq "live input:kb_options (the switch chord)" "grp:alts_toggle" "$(option input:kb_options)"

# --- 1b. a workspace keeps its own layout preset -----------------------------
# The rule is applied live with one hl.workspace_rule; the compositor's own
# activeworkspace answer (tiledLayout) is the proof it took.
tiled() { hyprctl -j activeworkspace 2>/dev/null | jq -r '.tiledLayout // ""'; }
if "${CTL}" layout columns --workspace active >/dev/null 2>&1 && wait_for 5 tiled_is scrolling; then
    note "ok   the focused workspace took its own preset (tiledLayout scrolling)"
else
    fail "the per-workspace preset did not reach the compositor (tiledLayout '$(tiled)')"
fi
stored="$(jq -r --arg ws "$(active_workspace)" '.workspaces[$ws] // ""' \
    "${HOME}/.local/state/punar/workspace-layouts.json" 2>/dev/null)"
check_eq "the workspace's preset is kept for the next session" "columns" "${stored}"
case "$("${CTL}" --json layout status 2>/dev/null | jq -r '.preset // ""')" in
    columns) session_algorithm=scrolling ;;
    rows|focus) session_algorithm=master ;;
    stack) session_algorithm=monocle ;;
    *) session_algorithm=dwindle ;;
esac
"${CTL}" layout default --workspace active >/dev/null 2>&1
if wait_for 5 tiled_is "${session_algorithm}"; then
    note "ok   default gave the workspace back to the session preset (${session_algorithm})"
else
    fail "default left tiledLayout '$(tiled)', not the session's ${session_algorithm}"
fi

# --- 2. the lock screen names the layout -------------------------------------
lock_password="punar"
ipc lock lock >/dev/null
if wait_for 10 lock_is locked; then
    lock_keyboard="$(ipc lock keyboard)"
    case "${lock_keyboard}" in
        "Keyboard "*"Alt + Alt switches") note "ok   the lock screen names the layout: ${lock_keyboard}" ;;
        *) fail "the lock screen's layout line is '${lock_keyboard}'" ;;
    esac
    ipc lock submit "${lock_password}" >/dev/null
    wait_for 15 lock_is unlocked || fail "the session did not unlock after the layout check"
else
    fail "the session did not lock"
fi

# --- 3. the key driver answers: a probe window receives typed text ----------
PROBE_OUT="${XDG_RUNTIME_DIR}/punar/keys-probe-a.txt"
PROBE_A="$(open_probe punar-keys-a "${PROBE_OUT}")" || PROBE_A=""
PROBES="${PROBES} ${PROBE_A}"
if [ -z "${PROBE_A}" ] || ! focus_window "${PROBE_A}"; then
    fail "the probe window did not open or take focus"
    finish
fi
press ping
if wait_for 20 file_is "${PROBE_OUT}" ok; then
    note "ok   the QMP key driver reaches this session's keyboard (typed 'ok')"
else
    fail "no key driver answered: the probe window received '$(cat "${PROBE_OUT}" 2>/dev/null)' (is tools/qmp-keys.py running beside QEMU?)"
    finish
fi

# --- 4. under Russian, PUNAR+Return still opens a terminal ------------------
before="$(terminal_count)"
press punar-return
if wait_for 20 more_terminals "${before}"; then
    note "ok   PUNAR+Return opened a terminal with the Russian layout loaded"
    new_terminal="$(clients | jq -r '[.[] | select(.class == "foot" or .class == "footclient")] | last | .address')"
    PROBES="${PROBES} ${new_terminal}"
else
    fail "PUNAR+Return opened no terminal with the Russian layout loaded (terminals ${before} -> $(terminal_count))"
fi

# --- 5. after the switch chord, a terminal receives Cyrillic ----------------
PROBE_OUT_B="${XDG_RUNTIME_DIR}/punar/keys-probe-b.txt"
PROBE_B="$(open_probe punar-keys-b "${PROBE_OUT_B}")" || PROBE_B=""
PROBES="${PROBES} ${PROBE_B}"
if [ -n "${PROBE_B}" ] && focus_window "${PROBE_B}"; then
    press alts
    if wait_for 10 keymap_has Russian; then
        note "ok   both Alt keys switched the keymap to Russian ($(keymaps))"
    else
        fail "the switch chord did not reach Russian (active keymaps: $(keymaps))"
    fi
    press cyrillic
    if wait_for 20 file_is "${PROBE_OUT_B}" "привет"; then
        note "ok   the terminal received Cyrillic: привет"
    else
        fail "the terminal received '$(cat "${PROBE_OUT_B}" 2>/dev/null)' instead of привет"
    fi
    press alts
    wait_for 10 keymap_has "English (US)" || fail "the switch chord did not return to English"
else
    fail "the second probe window did not open"
fi

# --- 6. Alt+Tab: the previous window, then the one before -------------------
# Three probe windows focused in order A, B, C make the history C, B, A.
PROBE_C="$(open_probe punar-keys-c "${XDG_RUNTIME_DIR}/punar/keys-probe-c.txt")" || PROBE_C=""
PROBES="${PROBES} ${PROBE_C}"
if [ -n "${PROBE_A}" ] && [ -n "${PROBE_B}" ] && [ -n "${PROBE_C}" ]; then
    focus_window "${PROBE_A}"; focus_window "${PROBE_B}"; focus_window "${PROBE_C}"
    switch_started="$(date +%s)"
    press alt-tab
    if wait_for 10 is_active "${PROBE_B}"; then
        switch_secs=$(( $(date +%s) - switch_started ))
        note "ok   Alt+Tab went back to the previous window (${switch_secs} s)"
        # The switcher finishes on its own five seconds after a MISSED
        # release. Finishing sooner is the proof that releasing Alt did it.
        if [ "${switch_secs}" -ge 4 ]; then
            fail "Alt+Tab finished after ${switch_secs} s: the release of Alt did not end the switch (the five-second fallback did)"
        fi
    else
        fail "Alt+Tab focused $(active_address), not the previous window ${PROBE_B}"
    fi
    # Now B, C, A: two Tabs in one Alt hold reach A.
    press alt-tab-tab
    if wait_for 10 is_active "${PROBE_A}"; then
        note "ok   two Tabs in one Alt hold reached the third window"
    else
        fail "Alt+Tab+Tab focused $(active_address), not ${PROBE_A}"
    fi
else
    fail "the Alt+Tab windows did not open"
fi

# --- 7. the tenth workspace and a quiet move ----------------------------------
press punar-0
if wait_for 10 on_workspace 10; then
    note "ok   PUNAR+0 reached workspace 10"
else
    fail "PUNAR+0 left the session on workspace $(active_workspace)"
fi
press punar-1
wait_for 10 on_workspace 1 || fail "PUNAR+1 did not return to workspace 1"
if [ -n "${PROBE_A}" ] && focus_window "${PROBE_A}"; then
    start_ws="$(active_workspace)"
    press punar-alt-2
    if wait_for 10 window_on "${PROBE_A}" 2; then
        note "ok   PUNAR+ALT+2 moved the window to workspace 2"
        check_eq "the person stayed on their workspace" "${start_ws}" "$(active_workspace)"
    else
        fail "PUNAR+ALT+2 left the window on workspace $(client_field "${PROBE_A}" .workspace.id)"
    fi
fi

# --- 8. maximize and pop-out ----------------------------------------------------
if [ -n "${PROBE_B}" ] && focus_window "${PROBE_B}"; then
    press punar-m
    if wait_for 10 field_is "${PROBE_B}" .fullscreen 1; then
        note "ok   PUNAR+M maximized the window"
    else
        fail "PUNAR+M left fullscreen=$(client_field "${PROBE_B}" .fullscreen)"
    fi
    press punar-m
    wait_for 10 field_is "${PROBE_B}" .fullscreen 0 || fail "PUNAR+M did not restore the window"
    press punar-o
    if wait_for 10 field_is "${PROBE_B}" .pinned true && field_is "${PROBE_B}" .floating true; then
        note "ok   PUNAR+O popped the window out (floating and pinned)"
    else
        fail "PUNAR+O left floating=$(client_field "${PROBE_B}" .floating) pinned=$(client_field "${PROBE_B}" .pinned)"
    fi
fi

# --- 9. pointer move and resize with PUNAR held -------------------------------
if [ -n "${PROBE_B}" ] && field_is "${PROBE_B}" .floating true; then
    mon="$(hyprctl -j monitors | jq -r '[.[] | select(.focused)][0] | "\(.width) \(.height) \(.scale) \(.x) \(.y)"')"
    # shellcheck disable=SC2086 # five numbers from jq
    set -- ${mon}
    mw=$(printf '%s %s\n' "$1" "$3" | awk '{printf "%d", $1 / $2}')
    mh=$(printf '%s %s\n' "$2" "$3" | awk '{printf "%d", $1 / $2}')
    mx="$4"; my="$5"
    bx="$(client_field "${PROBE_B}" '.at[0]')"; by="$(client_field "${PROBE_B}" '.at[1]')"
    bw="$(client_field "${PROBE_B}" '.size[0]')"; bh="$(client_field "${PROBE_B}" '.size[1]')"
    cx=$((bx + bw / 2 - mx)); cy=$((by + bh / 2 - my))
    press drag "$(abs "${cx}" "${mw}")" "$(abs "${cy}" "${mh}")" "$(abs $((cx + 160)) "${mw}")" "$(abs $((cy + 120)) "${mh}")"
    if wait_for 10 moved_by "${PROBE_B}" "${bx}" "${by}"; then
        note "ok   PUNAR+drag moved the window ($(client_field "${PROBE_B}" '.at | join(",")') from ${bx},${by})"
    else
        fail "PUNAR+drag did not move the window (still $(client_field "${PROBE_B}" '.at | join(",")'))"
    fi
    bx="$(client_field "${PROBE_B}" '.at[0]')"; by="$(client_field "${PROBE_B}" '.at[1]')"
    cx=$((bx + bw * 3 / 4 - mx)); cy=$((by + bh * 3 / 4 - my))
    press rdrag "$(abs "${cx}" "${mw}")" "$(abs "${cy}" "${mh}")" "$(abs $((cx + 120)) "${mw}")" "$(abs $((cy + 90)) "${mh}")"
    if wait_for 10 resized_from "${PROBE_B}" "${bw}" "${bh}"; then
        note "ok   PUNAR+right-drag resized the window ($(client_field "${PROBE_B}" '.size | join("x")') from ${bw}x${bh})"
    else
        fail "PUNAR+right-drag did not resize the window (still $(client_field "${PROBE_B}" '.size | join("x")'))"
    fi
    press punar-o
    wait_for 10 field_is "${PROBE_B}" .pinned false || fail "PUNAR+O did not put the window back"
else
    fail "no popped-out window to drag"
fi

# --- 10. the layout goes back, and the compositor follows ----------------------
cleanup
check_eq "the device's layout after the exercise" "${ORIGINAL}" \
    "$("${CTL}" --json keyboard layout status 2>/dev/null | jq -r '.device // ""')"
finish
