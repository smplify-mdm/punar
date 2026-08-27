#!/bin/sh
# M2 in-VM multitasking exercise (milestone-2.md §7). Runs AS the punar
# user INSIDE the live session via punar-m2-check.service, which
# idle-ram.sh starts synchronously AFTER the canonical RAM sampling window
# (so the idle measurement is never polluted) and BEFORE the artifact
# export (so everything this script writes into /run/punar ships in the
# same tar — the export is `tar -C /run/punar .`, no list to extend).
#
# Session env (HYPRLAND_INSTANCE_SIGNATURE, WAYLAND_DISPLAY) is discovered
# from $XDG_RUNTIME_DIR — the simplest robust path: exactly one Hyprland
# instance and one quickshell instance exist in this image.
#
# Every assertion is a `hyprctl -j` + jq read or a `qs ipc` response — no
# new daemons, no polling loops beyond bounded waits (PERFORMANCE_BUDGETS).
# The script ALWAYS exits 0: the verdict lives in /run/punar/m2-report.txt
# (`PUNAR_M2_OK` / `PUNAR_M2_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The
# host gate (tools/boot-test.sh) parses the exported report and hard-fails
# on PUNAR_M2_FAIL.
#
# What is exercised (milestone-2.md §7; deliberately NOT exercised in CI:
# nothing — rows 1–11 are covered; row 12's budget gate is the existing
# check-budgets.sh, unchanged, measured before this script runs):
#   windows   spawn 3 foot windows (staggered), count via clients JSON
#   presets   punar-layout.sh focus/stack/balanced → general:layout +
#             per-workspace tiledLayout; preset cache file
#   groups    togglegroup + auto_group join, changegroupactive,
#             moveoutofgroup — via clients `grouped` arrays
#   floating  togglefloating/centerwindow/pin flags, then restored
#   naming    renameworkspace 1 Atlas → workspaces JSON; workspace
#             name:Atlas navigation
#   specials  terminal is absent at idle, PUNAR+T helper demand-starts one
#             footclient and toggles it; assistant/notes via monitors JSON
#   overview  qs -p /usr/share/punar/shell ipc call overview toggle/state; grim screenshot
#             punar-m2.png with the overview open (Plate D-007 proof)
#   state     ~/.local/state/punar/workspaces.json validated with jq
#             against the milestone-2.md §6 shape
#   restore   quickshell killed + relaunched, name cleared while it is
#             down → restored from the state file after restart
# Predicate functions below are invoked indirectly through `wait_for <secs>
# <fn>` — shellcheck cannot see that (same pattern as boot-test.sh's
# trap-invoked cleanup). File-wide: this directive precedes the first
# command.
# shellcheck disable=SC2329
set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m2-report.txt"
STATE_FILE="${HOME}/.local/state/punar/workspaces.json"
LAYOUT=/usr/lib/punar/punar-layout.sh
SHELL_CMD='qs -p /usr/share/punar/shell'
FAILED=0

: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }

# check_eq <name> <expected> <actual>
check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        note "FAIL $1 (expected '$2', got '$3')"
        FAILED=1
    fi
}

# wait_for <secs> <predicate-fn> [args...] — 1 s poll, bounded (TCG runs
# are slow; the bounds are generous, the KVM path exits on first success).
wait_for() {
    wf_secs="$1"
    shift
    wf_i=0
    while [ "${wf_i}" -lt "${wf_secs}" ]; do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        wf_i=$((wf_i + 1))
        sleep 1
    done
    return 1
}

finish() {
    if [ "${FAILED}" -eq 0 ]; then
        note "PUNAR_M2_OK"
    else
        note "PUNAR_M2_FAIL"
    fi
    # Full report onto stdout → journal+console → serial log, so a failed
    # export still leaves the per-assertion detail in serial.log.
    cat "${REPORT}"
    exit 0
}

note "# Punar M2 exercise report — $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- session env discovery ---------------------------------------------------
XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XDG_RUNTIME_DIR

HIS=""
for d in "${XDG_RUNTIME_DIR}/hypr/"*/; do
    [ -d "${d}" ] || continue
    HIS="$(basename "${d}")"
    break
done
if [ -z "${HIS}" ]; then
    note "FAIL no Hyprland instance under ${XDG_RUNTIME_DIR}/hypr"
    FAILED=1
    finish
fi
HYPRLAND_INSTANCE_SIGNATURE="${HIS}"
export HYPRLAND_INSTANCE_SIGNATURE

WAYLAND_DISPLAY=""
for s in "${XDG_RUNTIME_DIR}"/wayland-*; do
    case "${s}" in
        *.lock) ;;
        *) [ -e "${s}" ] && WAYLAND_DISPLAY="$(basename "${s}")" && break ;;
    esac
done
export WAYLAND_DISPLAY
note "# instance=${HIS} wayland=${WAYLAND_DISPLAY:-none}"

# The CI guest exposes only virtio-vga. Prove session startup chose the
# software path here; fake-sysfs unit coverage separately proves real GPUs
# clear both software-rendering variables.
GRAPHICS_REPORT="${XDG_RUNTIME_DIR}/punar-graphics-mode"
if [ -r "${GRAPHICS_REPORT}" ]; then
    graphics_line="$(cat "${GRAPHICS_REPORT}")"
    graphics_mode="$(printf '%s\n' "${graphics_line}" \
        | sed -n 's/^mode=\([^ ]*\).*/\1/p')"
    check_eq "virtio session graphics mode" "software" "${graphics_mode}"
    case "${graphics_line}" in
        *drivers=virtio_gpu*|*drivers=virtio_pci*|*drivers=virtio-pci*)
            note "ok   virtio DRM driver recorded = ${graphics_line}"
            ;;
        *)
            note "FAIL expected virtio DRM driver in '${graphics_line}'"
            FAILED=1
            ;;
    esac
else
    note "FAIL graphics decision report missing at ${GRAPHICS_REPORT}"
    FAILED=1
fi

hyprctl_alive() { hyprctl -j version | jq -e .tag; }
if ! wait_for 60 hyprctl_alive; then
    note "FAIL hyprctl not responding on instance ${HIS}"
    FAILED=1
    finish
fi

# --- helpers over hyprctl -j -------------------------------------------------
active_field()  { hyprctl -j activewindow  2>/dev/null | jq -r "$1"; }
ws_field()      { hyprctl -j workspaces    2>/dev/null | jq -r ".[] | select(.id == $1) | $2"; }
layout_option() { hyprctl -j getoption general:layout 2>/dev/null | jq -r .str; }

ws1_count_at_least() {
    hyprctl -j clients | jq -e --argjson n "$1" \
        '[ .[] | select(.workspace.id == 1) ] | length >= $n'
}

# --- 1. three foot windows on workspace 1, staggered -------------------------
hyprctl dispatch workspace 1 >/dev/null 2>&1
n=0
while [ "${n}" -lt 3 ]; do
    n=$((n + 1))
    hyprctl dispatch exec foot >/dev/null 2>&1
    if ! wait_for 120 ws1_count_at_least "${n}"; then
        note "FAIL foot window ${n} did not appear on workspace 1 within 120s"
        FAILED=1
    fi
done
count="$(hyprctl -j clients | jq '[ .[] | select(.workspace.id == 1) ] | length')"
check_eq "clients on workspace 1 after 3 spawns" 3 "${count}"

# --- 2. layout presets (milestone-2.md §4 mapping) ---------------------------
# focus → master, stack → monocle, then balanced → dwindle (the default
# feel, also what the state file should end on). Snapshots exported.
for pair in focus:master stack:monocle balanced:dwindle; do
    preset="${pair%%:*}"
    algo="${pair##*:}"
    if "${LAYOUT}" "${preset}" >/dev/null 2>&1; then
        check_eq "general:layout after preset ${preset}" "${algo}" "$(layout_option)"
        check_eq "workspace 1 tiledLayout after preset ${preset}" "${algo}" \
            "$(ws_field 1 .tiledLayout)"
        hyprctl -j workspaces > "${RUN_DIR}/m2-layout-${preset}.json" 2>/dev/null
    else
        note "FAIL punar-layout.sh ${preset} exited nonzero (script missing from image?)"
        FAILED=1
    fi
done
# Cycle grammar (milestone-2.md §7 row 6): next twice from balanced lands
# on rows (master); prev twice returns to balanced.
"${LAYOUT}" next >/dev/null 2>&1
"${LAYOUT}" next >/dev/null 2>&1
check_eq "layout-preset cache after next x2 from balanced" rows \
    "$(cat "${XDG_RUNTIME_DIR}/punar/layout-preset" 2>/dev/null || echo missing)"
check_eq "general:layout after next x2" master "$(layout_option)"
"${LAYOUT}" prev >/dev/null 2>&1
"${LAYOUT}" prev >/dev/null 2>&1
check_eq "layout-preset cache after prev x2" balanced \
    "$(cat "${XDG_RUNTIME_DIR}/punar/layout-preset" 2>/dev/null || echo missing)"
check_eq "general:layout restored to dwindle" dwindle "$(layout_option)"

# --- 3. groups ---------------------------------------------------------------
# togglegroup on the active window, then spawn a fourth foot: with
# group:auto_group (set explicitly; also the 0.56 default) it joins the
# focused group — deterministic, no direction guessing.
hyprctl keyword group:auto_group 1 >/dev/null 2>&1
hyprctl dispatch togglegroup >/dev/null 2>&1
check_eq "grouped count after togglegroup" 1 "$(active_field '.grouped | length')"
hyprctl dispatch exec foot >/dev/null 2>&1
grouped_two() { hyprctl -j activewindow | jq -e '.grouped | length == 2'; }
if wait_for 120 grouped_two; then
    note "ok   fourth window auto-joined the group (grouped length 2)"
else
    note "FAIL fourth window did not join the group within 120s"
    FAILED=1
fi
hyprctl -j clients > "${RUN_DIR}/m2-clients-grouped.json" 2>/dev/null

addr_before="$(active_field .address)"
hyprctl dispatch changegroupactive f >/dev/null 2>&1
sleep 1
addr_after="$(active_field .address)"
if [ -n "${addr_before}" ] && [ "${addr_before}" != "${addr_after}" ]; then
    note "ok   changegroupactive f switched the active window"
else
    note "FAIL changegroupactive f did not change the active window (${addr_before} -> ${addr_after})"
    FAILED=1
fi

hyprctl dispatch moveoutofgroup >/dev/null 2>&1
sleep 1
check_eq "grouped count after moveoutofgroup" 0 "$(active_field '.grouped | length')"

# --- 4. floating / center / pin ----------------------------------------------
hyprctl dispatch togglefloating >/dev/null 2>&1
sleep 1
check_eq "floating after togglefloating" true "$(active_field .floating)"
hyprctl dispatch centerwindow >/dev/null 2>&1
hyprctl dispatch pin >/dev/null 2>&1
sleep 1
check_eq "pinned after pin" true "$(active_field .pinned)"
hyprctl dispatch pin >/dev/null 2>&1
hyprctl dispatch settiled >/dev/null 2>&1
sleep 1
check_eq "floating restored by settiled" false "$(active_field .floating)"
check_eq "pinned restored by second pin" false "$(active_field .pinned)"

# --- 5. named workspaces -----------------------------------------------------
hyprctl dispatch renameworkspace 1 Atlas >/dev/null 2>&1
sleep 1
check_eq "workspace 1 name after rename" Atlas "$(ws_field 1 .name)"

hyprctl dispatch workspace 2 >/dev/null 2>&1
sleep 1
check_eq "activeworkspace after workspace 2" 2 \
    "$(hyprctl -j activeworkspace | jq -r .id)"
hyprctl dispatch workspace name:Atlas >/dev/null 2>&1
sleep 1
check_eq "activeworkspace after workspace name:Atlas" 1 \
    "$(hyprctl -j activeworkspace | jq -r .id)"

# --- 6. scratchpad special workspaces ----------------------------------------
special_name() { hyprctl -j monitors 2>/dev/null | jq -r '.[0].specialWorkspace.name'; }
special_is() { [ "$(special_name)" = "$1" ]; }

# hyprctl normally returns synchronously, but the first IPC immediately after
# a scratchpad client disconnect can briefly lose the compositor socket on a
# loaded CI guest. A key binding dispatches in-process and does not have this
# transport edge. Retry only a command that returned nonzero, then wait on the
# observable monitor state instead of assuming a one-second sleep is proof.
dispatch_special() {
    ds_pad="$1"
    ds_i=0
    while [ "${ds_i}" -lt 10 ]; do
        if hyprctl dispatch togglespecialworkspace "${ds_pad}" >/dev/null 2>&1; then
            return 0
        fi
        ds_i=$((ds_i + 1))
        sleep 0.2
    done
    return 1
}

# Resource contract: no hidden terminal window is billed to every session.
# The warm foot server remains; the first summon creates exactly one client,
# maps it onto special:term, and the second summon hides it. Record the cold
# path before setting a regression budget from repeated KVM evidence.
scratch_count() {
    hyprctl -j clients 2>/dev/null \
        | jq '[.[] | select(.class == "punar-scratch")] | length'
}
scratch_ready() {
    [ "$(scratch_count)" = "1" ] && [ "$(special_name)" = "special:term" ]
}
scratch_gone() { [ "$(scratch_count)" = "0" ]; }

check_eq "scratch terminal absent before first use" "0" "$(scratch_count)"
scratch_started_ms="$(date +%s%3N)"
/usr/lib/punar/punar-scratchpad.sh >/dev/null 2>&1
if wait_for 15 scratch_ready; then
    scratch_ready_ms="$(date +%s%3N)"
    note "ok   scratch terminal demand-started and shown in $((scratch_ready_ms - scratch_started_ms)) ms"
else
    note "FAIL scratch terminal did not demand-start on special:term"
    FAILED=1
fi
/usr/lib/punar/punar-scratchpad.sh >/dev/null 2>&1
sleep 1
check_eq "scratch terminal hidden by second toggle" "" "$(special_name)"
scratch_address="$(hyprctl -j clients 2>/dev/null \
    | jq -r '.[] | select(.class == "punar-scratch") | .address' | head -1)"
if [ -n "${scratch_address}" ]; then
    hyprctl dispatch closewindow "address:${scratch_address}" >/dev/null 2>&1
fi
if wait_for 15 scratch_gone; then
    note "ok   scratch terminal closed without a retained client"
else
    note "FAIL scratch terminal client remained after close"
    FAILED=1
fi

# Let Hyprland finish the empty-special-workspace close transaction before
# exercising the next IPC dispatch. Without this boundary the client is gone
# while the compositor can still be finalising special:term.
wait_for 5 special_is "" || true

for pad in assistant notes; do
    if dispatch_special "${pad}" && wait_for 15 special_is "special:${pad}"; then
        note "ok   special workspace shown (${pad}) = special:${pad}"
    else
        note "FAIL special workspace shown (${pad}) (got '$(special_name)')"
        FAILED=1
    fi
    if special_is "special:${pad}"; then
        if dispatch_special "${pad}" && wait_for 15 special_is ""; then
            note "ok   special workspace hidden (${pad}) = "
        else
            note "FAIL special workspace hidden (${pad}) (got '$(special_name)')"
            FAILED=1
        fi
    fi
done

# --- 7. overview (Plate D-007 surface; IPC contract milestone-2.md §5) -------
# Tolerate whitespace/quoting variance in the ipc client's echo of the
# string return value — the contract value is the literal open/closed.
ov_state() { qs -p /usr/share/punar/shell ipc call overview state 2>/dev/null | tr -d '[:space:]"'; }
check_eq "overview state before toggle" closed "$(ov_state)"
qs -p /usr/share/punar/shell ipc call overview toggle >/dev/null 2>&1
sleep 2
check_eq "overview state after toggle" open "$(ov_state)"
# Proof of rendering with the overview up — the file the CI uploads.
if grim "${RUN_DIR}/punar-m2.png" 2>/dev/null; then
    note "ok   grim captured punar-m2.png with the overview open"
else
    note "FAIL grim screenshot with overview open failed"
    FAILED=1
fi
qs -p /usr/share/punar/shell ipc call overview toggle >/dev/null 2>&1
sleep 2
check_eq "overview state after second toggle" closed "$(ov_state)"

# --- 8. state file (milestone-2.md §6 shape; writer = punar-shell) -----------
state_ok() {
    jq -e '.version == 1
           and .layoutPreset == "balanced"
           and ([ .workspaces[] | select(.id == 1 and .name == "Atlas") ] | length == 1)' \
        "${STATE_FILE}"
}
if wait_for 90 state_ok; then
    note "ok   workspaces.json valid (version 1, layoutPreset balanced, {id:1,name:Atlas})"
else
    note "FAIL workspaces.json missing or shape mismatch after 90s: $(cat "${STATE_FILE}" 2>/dev/null || echo absent)"
    FAILED=1
fi
cp "${STATE_FILE}" "${RUN_DIR}/m2-workspaces-state.json" 2>/dev/null || true

# --- 9. shell restart → name restoration (milestone-2.md §7 row 11) ----------
pkill -f '/usr/share/punar/shell' >/dev/null 2>&1
shell_dead() { ! pgrep -f '/usr/share/punar/shell'; }
if ! wait_for 30 shell_dead; then
    note "FAIL quickshell did not exit after pkill"
    FAILED=1
fi
# Clear the name while the shell is down so nothing rewrites the file.
hyprctl dispatch renameworkspace 1 >/dev/null 2>&1
sleep 1
cleared="$(ws_field 1 .name)"
if [ "${cleared}" = "Atlas" ]; then
    note "FAIL renameworkspace 1 (clear) left the name as Atlas"
    FAILED=1
else
    note "ok   workspace 1 name cleared while shell down (now '${cleared}')"
fi
hyprctl dispatch exec "${SHELL_CMD}" >/dev/null 2>&1
shell_alive() { [ "$(ov_state)" = "closed" ]; }
if ! wait_for 240 shell_alive; then
    note "FAIL relaunched quickshell IPC not responding within 240s"
    FAILED=1
fi
restored() { [ "$(ws_field 1 .name)" = "Atlas" ]; }
if wait_for 60 restored; then
    note "ok   workspace 1 name restored to Atlas from workspaces.json after shell restart"
else
    note "FAIL name not restored after shell restart (name '$(ws_field 1 .name)')"
    FAILED=1
fi

# --- final snapshots for the export ------------------------------------------
hyprctl -j workspaces > "${RUN_DIR}/m2-workspaces.json" 2>/dev/null
hyprctl -j clients    > "${RUN_DIR}/m2-clients.json"    2>/dev/null

finish
