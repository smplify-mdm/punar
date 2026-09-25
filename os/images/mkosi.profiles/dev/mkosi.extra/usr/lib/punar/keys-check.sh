#!/bin/sh
# Punar keys, keyboard layout and window grammar in-VM exercise (SMP-1405
# WP-02).
#
# WHAT IT PROVES, on the running desktop:
#   * the keyboard layout is one device setting: the person at the machine
#     sets it with `punarctl keyboard layout set` from their own session
#     (punard's person-scoped system.keymap, audited under their name),
#     /etc/vconsole.conf records it, the session's data file and the live
#     compositor load it, and the lock screen names it; the same uid from
#     OUTSIDE the seat session (this very service) is refused;
#   * the login screen's choice, as session start adopts it, becomes the
#     device's layout, and a configuration load (the path session start
#     takes) reads it: live input:kb_layout and the lock screen follow;
#   * a layout that cannot type Latin letters (Russian, the plan's
#     acceptance case) is loaded behind a US first group with the both-Alt
#     switch chord, so PUNAR+Return still opens a terminal, after the chord
#     that terminal receives Cyrillic, and a letter bind (PUNAR+M) still
#     fires while Russian is the active group;
#   * a workspace keeps its own layout preset, live and across sessions;
#   * the brightness and media keys' verbs say "not present" (exit 6) for
#     hardware this VM lacks, and no brightness row is drawn; the microphone
#     key mutes and unmutes a real PipeWire source (a virtual one this
#     check creates), and says "not present" when there is none;
#   * the keys do what the grammar says, pressed as REAL KEYS: Alt+Tab (and
#     how long a quick switch takes), the tenth workspace, a quiet move,
#     maximize, pop-out, pointer move and resize with PUNAR held, swap,
#     toggle split, the file manager, next workspace, the workspace wheel,
#     the Mac-style clipboard keys in a terminal (paste arrives, copy never
#     interrupts), and a look toggle that survives a configuration reload;
#   * under French (AZERTY), whose number row types & é " … unshifted, the
#     workspace keys still work (they are bound by key code) and PUNAR+F1
#     opens the shortcut help that PUNAR+/ cannot reach there.
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
# probe windows are closed and workspace 1 is focused again. (Setting the
# layout back records it as the person's preference; its value is the one
# the device had, and the OS default it stands in for is persisted once and
# never changes, so nothing a person sees differs. The VM is discarded after
# the gate.)
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
        in_session keyboard layout set "${ORIGINAL_LAYOUT}" >/dev/null 2>&1 || true
        ORIGINAL_LAYOUT=""
    fi
    if [ "${CLIPBOARD_KEYS_ON}" = yes ]; then
        "${CTL}" keyboard clipboard-keys off >/dev/null 2>&1 || true
        CLIPBOARD_KEYS_ON=no
    fi
    if [ -n "${TEST_MIC}" ]; then
        pw-cli destroy "${TEST_MIC}" >/dev/null 2>&1 || true
        TEST_MIC=""
    fi
    "${CTL}" workspace focus 1 >/dev/null 2>&1 || true
}
CLIPBOARD_KEYS_ON=no
TEST_MIC=""

# RUN FROM THE SEAT SESSION. This check is a system service running as the
# person's uid; the keyboard layout is granted only to a call from the
# person's own session on the seat (punard's seat-presence check), which is
# where their terminal and System Control run it. So the compositor starts
# the command, in the session's scope, as a key bind would; its output and
# exit status come back through files. Arguments are layout values and
# flags, checked against a fixed character set before they are written.
SESSION_RUN_N=0
in_session() {
    SESSION_RUN_N=$((SESSION_RUN_N + 1))
    sr_dir="${XDG_RUNTIME_DIR}/punar/keys-session-${SESSION_RUN_N}"
    rm -rf "${sr_dir}"
    mkdir -p "${sr_dir}"
    sr_args=""
    for sr_arg in "$@"; do
        case "${sr_arg}" in
            ''|*[!A-Za-z0-9_+,.%-]*) note "# in_session: refusing argument '${sr_arg}'"; return 2 ;;
        esac
        sr_args="${sr_args} '${sr_arg}'"
    done
    printf '#!/bin/sh\n%s%s >%s/out 2>%s/err\necho $? >%s/rc.tmp\nmv %s/rc.tmp %s/rc\n' \
        "${CTL}" "${sr_args}" "${sr_dir}" "${sr_dir}" "${sr_dir}" "${sr_dir}" "${sr_dir}" \
        > "${sr_dir}/run.sh"
    hyprctl dispatch "hl.dsp.exec_cmd('sh ${sr_dir}/run.sh')" >/dev/null 2>&1
    if ! wait_for 30 test -s "${sr_dir}/rc"; then
        note "# in_session: '$*' did not finish in 30 s"
        return 124
    fi
    cat "${sr_dir}/out"
    cat "${sr_dir}/err" >&2
    return "$(cat "${sr_dir}/rc")"
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
# Absent is "", never jq's `// ""`: that also turns a real `false` into "",
# so a wait for `.pinned false` could never succeed (it failed the pop-out's
# way back in the VM while the window was in fact back in the layout).
client_field() { clients | jq -r --arg a "$1" "[.[] | select(.address == \$a)][0]$2 | if . == null then \"\" else . end"; }
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
# One line typed into this window, recorded verbatim. The window then stays
# until the check closes it (cleanup, or the unit's end): a probe that exited
# 30 s after its line vanished mid-check in the VM, and the workspace walk
# that still needed its workspace failed for that reason alone.
IFS= read -r line
printf '%s\n' "${line}" > "$1"
exec sleep 900
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

# --- 1a. the login screen's choice, as session start adopts it -------------
# greetd starts a session with PUNAR_KEYMAP only after a successful sign-in
# (punar-onboard's greetd tests), and session.sh then runs exactly this
# command, in the session, before the compositor reads the file. The dev
# image signs in without the login screen, so the check makes session
# start's own call from the seated session and follows the choice to the
# device, the audit log, the session's data file, and then through a
# configuration load (what the compositor does at start) to the live
# compositor and the lock screen.
case "${ORIGINAL}" in
    de|de[+,]*) GREETER_CHOICE=fr; GREETER_NAME=French ;;
    *) GREETER_CHOICE=de; GREETER_NAME=German ;;
esac
adopt="$(in_session --json keyboard layout render --adopt "${GREETER_CHOICE}" 2>/run/punar/keys-adopt.txt)"
if [ "$(printf '%s' "${adopt}" | jq -r '.adopted // false' 2>/dev/null)" = true ]; then
    ORIGINAL_LAYOUT="${ORIGINAL}"
    note "ok   session start adopted the login screen's ${GREETER_CHOICE} as the device's layout"
else
    fail "session start did not adopt the login screen's ${GREETER_CHOICE}: $(printf '%s' "${adopt}" | head -c 200) $(head -c 200 /run/punar/keys-adopt.txt)"
fi
check_eq "XKBLAYOUT after the login screen's choice" "XKBLAYOUT=${GREETER_CHOICE}" \
    "$(grep '^XKBLAYOUT=' /etc/vconsole.conf 2>/dev/null)"
if grep -q "^    kb_layout = \"${GREETER_CHOICE}\",\$" "${XDG_RUNTIME_DIR}/punar/session/input.lua" 2>/dev/null; then
    note "ok   the session's data file carries ${GREETER_CHOICE}"
else
    fail "the session's data file does not carry ${GREETER_CHOICE}: $(tr '\n' ' ' < "${XDG_RUNTIME_DIR}/punar/session/input.lua" 2>/dev/null | head -c 200)"
fi
adopter="$("${CTL}" --json audit tail -n 20 2>/dev/null \
    | jq -r '[.events[]? | select(.action == "capabilities.set" and .resource == "system.keymap" and .decision == "allow")] | last | .user_id // ""')"
check_eq "the adoption is audited under the person's name" "$(id -un)" "${adopter}"
# The compositor reads that file when it loads its configuration, at start
# and on every reload; a reload is the same path, taken now. (A compositor
# that ignored the file would still pass everything above.)
hyprctl reload >/dev/null 2>&1
layout_is() { [ "$(option input:kb_layout)" = "$1" ]; }
if wait_for 10 layout_is "${GREETER_CHOICE}"; then
    note "ok   a configuration load reads the file: live input:kb_layout = ${GREETER_CHOICE}"
else
    fail "a configuration load did not take the file: live input:kb_layout = '$(option input:kb_layout)', not ${GREETER_CHOICE}"
fi
lock_names() { case "$(ipc lock keyboard)" in "Keyboard $1"*) return 0 ;; *) return 1 ;; esac; }
ipc lock lock >/dev/null
if wait_for 10 lock_is locked; then
    if wait_for 10 lock_names "${GREETER_NAME}"; then
        note "ok   the lock screen names the login screen's layout: $(ipc lock keyboard)"
    else
        fail "the lock screen's layout line is '$(ipc lock keyboard)', not ${GREETER_NAME}"
    fi
    ipc lock submit "punar" >/dev/null
    wait_for 15 lock_is unlocked || fail "the session did not unlock after the layout check"
else
    fail "the session did not lock"
fi

# --- 1. (cont.) the person sets the device's layout from their session ------
if in_session keyboard layout set ru > /run/punar/keys-set.txt 2>&1; then
    ORIGINAL_LAYOUT="${ORIGINAL}"
    note "ok   punarctl keyboard layout set ru, from $(id -un)'s session, without an administrator"
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

# The same uid, OUTSIDE the seat session: this check is a system service, as
# a user service, a D-Bus-activated app or an agent's escaped helper would be
# a process that is not the person's session. It must be refused, and the
# device must not change.
"${CTL}" keyboard layout set us+dvorak > /run/punar/keys-outside.txt 2>&1
check_eq "the same uid outside the seat session is refused (exit 3)" 3 "$?"
check_eq "and the device's layout did not change" "XKBLAYOUT=ru" "$(grep '^XKBLAYOUT=' /etc/vconsole.conf 2>/dev/null)"

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

# --- 1c. keys whose hardware this VM does not have --------------------------
# The brightness, microphone and media keys run punarctl verbs that say when
# what they drive is absent (exit 6, "not present") and draw nothing. This VM
# has no backlight, no sound card and no media player; if one ever appears,
# the verb must work instead, so each branch is read from the machine. (A
# media player needs a D-Bus service the image does not ship, so the media
# keys' positive case is punarctl's own test against a fake bus; WP-03's
# audio panel brings the in-VM one.)
if ls /sys/class/backlight/* >/dev/null 2>&1; then
    "${CTL}" display brightness get >/dev/null 2>&1
    check_eq "display brightness reads the backlight this machine has" 0 "$?"
else
    "${CTL}" display brightness +5% > /run/punar/keys-brightness.txt 2>&1
    check_eq "the brightness key with no backlight exits 6 (not present)" 6 "$?"
    if grep -q 'has no display backlight' /run/punar/keys-brightness.txt; then
        note "ok   and says the machine has no display backlight"
    else
        fail "the brightness refusal does not say why: $(head -c 200 /run/punar/keys-brightness.txt)"
    fi
    if [ "$(ipc osd state)" = brightness ]; then
        fail "the OSD drew a brightness row for a backlight that does not exist"
    else
        note "ok   no brightness row was drawn (the OSD is '$(ipc osd state)')"
    fi
fi
if ! wpctl inspect @DEFAULT_AUDIO_SOURCE@ >/dev/null 2>&1; then
    "${CTL}" audio mute --input > /run/punar/keys-mic.txt 2>&1
    check_eq "the microphone key with no microphone exits 6 (not present)" 6 "$?"
    if grep -q 'no microphone' /run/punar/keys-mic.txt; then
        note "ok   and says there is no microphone, not that PipeWire is down"
    else
        fail "the microphone refusal does not say why: $(head -c 200 /run/punar/keys-mic.txt)"
    fi
fi
# The microphone key against a REAL PipeWire source. The VM has no sound
# card, so after the absent case above this creates a virtual source (a
# null sink shaped as Audio/Source, which PipeWire treats like any other
# source), makes it the default, and the key must mute it and unmute it.
mic_muted() { wpctl get-volume @DEFAULT_AUDIO_SOURCE@ 2>/dev/null | grep -q MUTED; }
mic_ready() { wpctl inspect @DEFAULT_AUDIO_SOURCE@ >/dev/null 2>&1; }
if ! command -v pw-cli >/dev/null 2>&1; then
    fail "pw-cli is not in the image, so the microphone key cannot be proven against a real source"
elif mic_ready; then
    note "# this machine has a microphone of its own; it is used as it is"
else
    pw-cli create-node adapter '{ factory.name = support.null-audio-sink node.name = punar-keys-mic media.class = Audio/Source/Virtual audio.position = [ MONO ] object.linger = true }' \
        >/run/punar/keys-mic-create.txt 2>&1
    TEST_MIC="$(pw-cli ls Node 2>/dev/null | awk '
        /^[[:space:]]*id [0-9]+,/ { id = $2; sub(/,/, "", id) }
        /node.name = "punar-keys-mic"/ { print id; exit }')"
    if [ -n "${TEST_MIC}" ]; then
        wpctl set-default "${TEST_MIC}" >/dev/null 2>&1
    fi
    wait_for 10 mic_ready || fail "the virtual microphone did not become the default source ($(head -c 200 /run/punar/keys-mic-create.txt))"
fi
if mic_ready; then
    mic_was_muted=no
    mic_muted && mic_was_muted=yes
    "${CTL}" audio mute --input > /run/punar/keys-mic.txt 2>&1
    check_eq "the microphone key toggles a real source's mute" 0 "$?"
    if [ "${mic_was_muted}" = no ]; then
        if wait_for 5 mic_muted; then
            note "ok   the source is muted"
        else
            fail "the microphone key left the source unmuted: $(wpctl get-volume @DEFAULT_AUDIO_SOURCE@ 2>&1)"
        fi
    fi
    "${CTL}" audio mute --input >/dev/null 2>&1 || fail "the second microphone key press failed"
    if [ "${mic_was_muted}" = no ] && mic_muted; then
        fail "the second microphone key press did not unmute the source"
    fi
    if [ -n "${TEST_MIC}" ]; then
        pw-cli destroy "${TEST_MIC}" >/dev/null 2>&1 || true
        TEST_MIC=""
    fi
fi
if busctl --user list 2>/dev/null | grep -q '^org\.mpris\.MediaPlayer2\.'; then
    note "# a media player is running; the media key's absent case is not exercised"
else
    "${CTL}" media play-pause > /run/punar/keys-media.txt 2>&1
    check_eq "the play/pause key with no media player exits 6 (not present)" 6 "$?"
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
    # A LETTER bind while Russian is the active group: the M key types
    # "ь" here, and PUNAR+M must still maximize, because Hyprland resolves
    # binds against the first group (US), which is why the Latin lead exists.
    if keymap_has Russian; then
        press punar-m
        if wait_for 10 field_is "${PROBE_B}" .fullscreen 1; then
            note "ok   PUNAR+M maximized while Russian was the active layout (letter binds survive)"
        else
            fail "PUNAR+M did nothing while Russian was active: the letter binds do not survive a non-Latin layout"
        fi
        press punar-m
        wait_for 10 field_is "${PROBE_B}" .fullscreen 0 || fail "PUNAR+M did not restore the window under Russian"
        # The lock screen names the layout the password field types in NOW,
        # followed through Hyprland's activelayout event, not the first one.
        ipc lock lock >/dev/null
        if wait_for 10 lock_is locked; then
            if wait_for 10 lock_names Russian; then
                note "ok   the lock screen names the active layout: $(ipc lock keyboard)"
            else
                fail "the lock screen says '$(ipc lock keyboard)' while Russian is the active layout"
            fi
            ipc lock submit "punar" >/dev/null
            wait_for 15 lock_is unlocked || fail "the session did not unlock after the Russian lock check"
            focus_window "${PROBE_B}" || true
        else
            fail "the session did not lock under Russian"
        fi
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
    switch_started_ms="$(date +%s%3N)"
    press alt-tab
    if wait_for 10 is_active "${PROBE_B}"; then
        switch_secs=$(( $(date +%s) - switch_started ))
        # From the request on the console to the focus change, in ms. It
        # includes the host driver's serial polling (up to 250 ms) and the
        # chord's pacing (4 x 40 ms), so the switch itself is the rest; the
        # figure is recorded for the J14 comparison, not budgeted here.
        note "ok   Alt+Tab went back to the previous window ($(( $(date +%s%3N) - switch_started_ms )) ms from request to focus)"
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
    back_in_layout() { field_is "$1" .pinned false && field_is "$1" .floating false; }
    if wait_for 10 back_in_layout "${PROBE_B}"; then
        note "ok   PUNAR+O put the popped-out window back in the layout (unpinned, tiled)"
    else
        fail "PUNAR+O did not put the window back (floating=$(client_field "${PROBE_B}" .floating) pinned=$(client_field "${PROBE_B}" .pinned))"
    fi
else
    fail "no popped-out window to drag"
fi

# --- 9b. swap, split, the file manager, and walking the workspaces ----------
# Two fresh windows on an empty workspace laid out balanced (dwindle), so the
# geometry has one answer: side by side, swapped, stacked, side by side.
GRAMMAR_WS=7
"${CTL}" workspace focus "${GRAMMAR_WS}" >/dev/null 2>&1
if wait_for 10 on_workspace "${GRAMMAR_WS}"; then
    "${CTL}" layout balanced --workspace active >/dev/null 2>&1 \
        || fail "workspace ${GRAMMAR_WS} did not take the balanced preset"
    PROBE_D="$(open_probe punar-keys-d "${XDG_RUNTIME_DIR}/punar/keys-probe-d.txt")" || PROBE_D=""
    PROBES="${PROBES} ${PROBE_D}"
    PROBE_E="$(open_probe punar-keys-e "${XDG_RUNTIME_DIR}/punar/keys-probe-e.txt")" || PROBE_E=""
    PROBES="${PROBES} ${PROBE_E}"
else
    fail "workspace ${GRAMMAR_WS} did not take focus"
    PROBE_D=""; PROBE_E=""
fi
x_of() { client_field "$1" '.at[0]'; }
y_of() { client_field "$1" '.at[1]'; }
left_of() { [ "$(x_of "$1")" -lt "$(x_of "$2")" ]; }
stacked() { [ "$(x_of "$1")" = "$(x_of "$2")" ] && [ "$(y_of "$1")" != "$(y_of "$2")" ]; }
side_by_side() { left_of "$1" "$2" || left_of "$2" "$1"; }
if [ -n "${PROBE_D}" ] && [ -n "${PROBE_E}" ] && wait_for 5 side_by_side "${PROBE_D}" "${PROBE_E}"; then
    if left_of "${PROBE_D}" "${PROBE_E}"; then
        LEFT="${PROBE_D}"; RIGHT="${PROBE_E}"
    else
        LEFT="${PROBE_E}"; RIGHT="${PROBE_D}"
    fi
    focus_window "${LEFT}"
    press punar-alt-l
    if wait_for 10 left_of "${RIGHT}" "${LEFT}"; then
        note "ok   PUNAR+ALT+L swapped the window with its right-hand neighbour"
    else
        fail "PUNAR+ALT+L did not swap (x $(x_of "${LEFT}") vs $(x_of "${RIGHT}"))"
    fi
    press punar-d
    if wait_for 10 stacked "${LEFT}" "${RIGHT}"; then
        note "ok   PUNAR+D turned the side-by-side pair into a stacked one"
    else
        fail "PUNAR+D did not toggle the split (at $(client_field "${LEFT}" '.at | join(",")') and $(client_field "${RIGHT}" '.at | join(",")'))"
    fi
    press punar-d
    wait_for 10 left_of "${RIGHT}" "${LEFT}" || fail "a second PUNAR+D did not put the pair side by side again"
else
    fail "the two windows for swap and split did not open side by side"
fi

# PUNAR+E: the file manager, through `punarctl app open thunar`. It raises a
# window that is already open, so the proof is that a file manager window is
# the focused one afterwards.
file_managers() { clients | jq '[.[] | select((.class | ascii_downcase) == "thunar")] | length'; }
file_manager_focused() {
    [ "$(hyprctl -j activewindow 2>/dev/null | jq -r '.class // "" | ascii_downcase')" = thunar ]
}
had_file_managers="$(file_managers)"
press punar-e
if wait_for 30 file_manager_focused; then
    note "ok   PUNAR+E opened the file manager"
    if [ "$(file_managers)" -gt "${had_file_managers:-0}" ]; then
        PROBES="${PROBES} $(active_address)"
    fi
else
    fail "PUNAR+E did not bring up the file manager (focused class '$(hyprctl -j activewindow 2>/dev/null | jq -r '.class // ""')')"
fi
"${CTL}" layout default --workspace "${GRAMMAR_WS}" >/dev/null 2>&1 || true

# Next workspace and the wheel walk the OPEN workspaces upwards from 1
# (workspace 2 holds the quietly moved window, 7 the pair above), so the
# expected answer is read from the compositor rather than assumed.
next_open() {
    hyprctl -j workspaces 2>/dev/null \
        | jq -r --argjson cur "$1" '[.[] | select(.id > $cur) | .id] | sort | first // ""'
}
"${CTL}" workspace focus 1 >/dev/null 2>&1
wait_for 10 on_workspace 1 || fail "workspace 1 did not take focus again"
expected_ws="$(next_open 1)"
if [ -n "${expected_ws}" ]; then
    press punar-ctrl-tab
    if wait_for 10 on_workspace "${expected_ws}"; then
        note "ok   PUNAR+CTRL+TAB went to the next open workspace (${expected_ws})"
    else
        fail "PUNAR+CTRL+TAB left the session on workspace $(active_workspace), not ${expected_ws}"
    fi
    from_ws="$(active_workspace)"
    expected_ws="$(next_open "${from_ws}")"
    if [ -n "${expected_ws}" ]; then
        press punar-wheel-down
        if wait_for 10 on_workspace "${expected_ws}"; then
            note "ok   PUNAR+wheel scrolled to the next open workspace (${expected_ws})"
        else
            fail "PUNAR+wheel left the session on workspace $(active_workspace), not ${expected_ws}"
        fi
    else
        fail "no open workspace above ${from_ws} to scroll to"
    fi
else
    fail "no open workspace above 1 to walk to"
fi
# Moving a workspace between monitors (PUNAR+ALT+arrows) needs a second
# monitor, which this VM does not have; hyprland-verify.sh proves the binds
# parse and keybind-contract-test.sh that they exist.

# --- 9c. the Mac-style clipboard keys, in a terminal --------------------------
# Turned on as a person does (`punarctl keyboard clipboard-keys on`, which
# reloads the configuration). In a terminal PUNAR+V must paste (Shift+Insert)
# and PUNAR+C must copy (Ctrl+Insert), and never send Ctrl+C, which would
# interrupt the program. The probe is a real foot window (class foot, which
# the terminal tag names) reading one line: PUNAR+C first, then PUNAR+V,
# then Return. Interrupted, it writes nothing; pasted into, it writes the
# clipboard's text.
paste_bound() { hyprctl binds -j 2>/dev/null | jq -e 'any(.[]; .description == "Paste")' >/dev/null 2>&1; }
paste_unbound() { ! paste_bound; }
clip_address() { clients | jq -r '[.[] | select(.title == "punar-keys-clip")][0].address // ""'; }
clip_mapped() { [ -n "$(clip_address)" ]; }
if "${CTL}" keyboard clipboard-keys on >/dev/null 2>&1 && wait_for 10 paste_bound; then
    CLIPBOARD_KEYS_ON=yes
    note "ok   the Mac-style clipboard keys are bound once the setting is on"
    printf 'punarpaste' | wl-copy
    CLIP_OUT="${XDG_RUNTIME_DIR}/punar/keys-probe-clip.txt"
    rm -f "${CLIP_OUT}"
    foot --title punar-keys-clip "${PROBE_SCRIPT}" "${CLIP_OUT}" >/dev/null 2>&1 &
    PROBE_CLIP=""
    if wait_for 20 clip_mapped; then
        PROBE_CLIP="$(clip_address)"
        PROBES="${PROBES} ${PROBE_CLIP}"
    fi
    if [ -n "${PROBE_CLIP}" ] && focus_window "${PROBE_CLIP}"; then
        press punar-c
        press punar-v
        press return
        if wait_for 15 file_is "${CLIP_OUT}" punarpaste; then
            note "ok   in a terminal PUNAR+V pasted and PUNAR+C did not interrupt the program"
        else
            fail "the terminal probe wrote '$(cat "${CLIP_OUT}" 2>/dev/null)': PUNAR+C interrupted it, or PUNAR+V did not paste"
        fi
    else
        fail "the terminal probe for the clipboard keys did not open or take focus"
    fi
    "${CTL}" keyboard clipboard-keys off >/dev/null 2>&1
    CLIPBOARD_KEYS_ON=no
    wait_for 10 paste_unbound || fail "the clipboard keys stayed bound after clipboard-keys off"
else
    fail "the Mac-style clipboard keys were not bound after punarctl keyboard clipboard-keys on"
fi

# --- 9d. a look toggle, kept across a configuration reload ------------------
# PUNAR+CTRL+T runs `punarctl window look transparency toggle`: the live
# session turns translucent, the choice is written as data, and a reload
# (the same path as the next sign-in) keeps it. Pressed again, it goes back.
opacity() { hyprctl -j getoption decoration:active_opacity 2>/dev/null | jq -r '.float // ""'; }
translucent() { opacity | awk '{ exit !($1 > 0.95 && $1 < 0.97) }'; }
opaque() { opacity | awk '{ exit !($1 > 0.99) }'; }
press punar-ctrl-t
if wait_for 10 translucent; then
    note "ok   PUNAR+CTRL+T made the windows translucent ($(opacity))"
    check_eq "the look is kept as data" true "$("${CTL}" --json window look 2>/dev/null | jq -r '.transparency')"
    hyprctl reload >/dev/null 2>&1
    sleep 1
    if wait_for 10 translucent; then
        note "ok   the look survived a configuration reload"
    else
        fail "a reload dropped the look (active_opacity $(opacity))"
    fi
    press punar-ctrl-t
    wait_for 10 opaque || fail "a second PUNAR+CTRL+T did not make the windows opaque again ($(opacity))"
else
    fail "PUNAR+CTRL+T left active_opacity at '$(opacity)'"
fi

# --- 9e. French (AZERTY): the number row and the help key --------------------
# On AZERTY the number row types & é " … unshifted, so digit keysyms never
# match; the workspace keys are bound by key code and must still work. And
# `/` is Shift+: there, so PUNAR+/ cannot be pressed at all; PUNAR+F1 opens
# the same shortcut help on every layout.
shortcuts_open() { [ "$(ipc shortcuts state)" = open ]; }
if in_session keyboard layout set fr > /run/punar/keys-fr.txt 2>&1 && wait_for 10 layout_is fr; then
    "${CTL}" workspace focus 1 >/dev/null 2>&1
    wait_for 10 on_workspace 1 || fail "workspace 1 did not take focus before the AZERTY keys"
    press punar-2
    if wait_for 10 on_workspace 2; then
        note "ok   under AZERTY, PUNAR+2 (the key that types é) reached workspace 2"
    else
        fail "under AZERTY, PUNAR+2 left the session on workspace $(active_workspace)"
    fi
    press punar-f1
    if wait_for 10 shortcuts_open; then
        note "ok   under AZERTY, PUNAR+F1 opened the shortcut help"
        ipc shortcuts close >/dev/null
    else
        fail "under AZERTY, PUNAR+F1 did not open the shortcut help (state '$(ipc shortcuts state)')"
    fi
else
    fail "the French layout did not load: live '$(option input:kb_layout)' $(head -c 200 /run/punar/keys-fr.txt)"
fi

# --- 10. the layout goes back, and the compositor follows ----------------------
cleanup
check_eq "the device's layout after the exercise" "${ORIGINAL}" \
    "$("${CTL}" --json keyboard layout status 2>/dev/null | jq -r '.device // ""')"
finish
