#!/bin/sh
# Isolated construction/resident-cost measurement for the shell surfaces
# that are eligible for lazy loading.
#
# The production shell stays alive.  For each sample this script starts a
# separate, empty Quickshell configuration, measures its PSS, asks it to load
# and open exactly one REAL surface file, closes that surface, then measures
# the probe process again.  A fresh process prevents one surface's QML type
# cache, singleton state, scene-graph buffers or allocator history from being
# charged to the next.
#
# ALWAYS exits 0. tools/boot-test.sh hard-gates the final verdict in
# /run/punar/surfaces-costs.txt, including a missing/truncated report.

# Predicate functions are invoked indirectly by wait_for.
# shellcheck disable=SC2329
set -u

REPORT=/run/punar/surfaces-costs.txt
PROBE_PATH=/usr/share/punar/shell/surface-probe.qml
PROBE_CMD="qs -p ${PROBE_PATH}"
PROBE_LOG=/run/punar/surface-probe.log
IPC_ERRORS=/run/punar/surface-probe-ipc-errors.log
SURFACES="commandcenter systemcontrol shortcuts aipanel overview notifications"
SAMPLES=3
MIN_PROBE_PSS_KIB=16384
FAILED=0

mkdir -p /run/punar
: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }

wait_for() {
    wf_secs="$1"; shift; wf_i=0
    while [ "${wf_i}" -lt "${wf_secs}" ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        wf_i=$((wf_i + 1))
        sleep 1
    done
    return 1
}

# Safe early-exit definition; replaced below once session/process discovery is
# available. Without it, a machine missing Hyprland would fail before writing
# the verdict that tells the host why.
stop_probe() { :; }

finish() {
    stop_probe
    if [ "${FAILED}" -eq 0 ]; then
        note "PUNAR_SURFACE_COSTS_OK"
    else
        note "PUNAR_SURFACE_COSTS_FAIL"
    fi
    cat "${REPORT}"
    exit 0
}

note "# Punar isolated surface costs — $(date -u +%Y-%m-%dT%H:%M:%SZ)"
note "# One fresh probe process per row; three rows per surface."
note "# PSS is the probe process only. resident_delta_kib is closed-after-first-use"
note "# minus empty-probe PSS; isolated deltas share code and MUST NOT be summed."
note "# construct_ms = IPC handler begins -> Loader.Ready."
note "# handoff_ms = Loader.Ready -> the real surface show() begins."
note "# shell_map_ms = show() begins -> Hyprland openlayer in the probe shell."
note "# first_map_ms = construction begins -> Hyprland openlayer."
printf '# surface\tsample\tbase_pss_kib\tresident_pss_kib\tresident_delta_kib\tconstruct_ms\thandoff_ms\tshell_map_ms\tfirst_map_ms\n' >> "${REPORT}"

# --- discover the live user session -----------------------------------------
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
if [ -z "${WAYLAND_DISPLAY}" ]; then
    note "FAIL no Wayland socket under ${XDG_RUNTIME_DIR}"
    FAILED=1
    finish
fi
export WAYLAND_DISPLAY
note "# instance=${HIS} wayland=${WAYLAND_DISPLAY} uid=$(id -u) user=$(id -un)"

ipc() { ${PROBE_CMD} ipc call "$@" 2>> "${IPC_ERRORS}"; }

probe_diagnostics() {
    diagnostic_state="$(ipc surfaceprobe state 2>/dev/null | tr -d '[:space:]\"')"
    diagnostic_timing="$(ipc surfaceprobe timing 2>/dev/null | tr -d '[:space:]\"')"
    note "# probe state='${diagnostic_state}' timing='${diagnostic_timing}'"
    if [ -s "${IPC_ERRORS}" ]; then
        note "# probe IPC stderr (last 12 lines):"
        tail -n 12 "${IPC_ERRORS}" | sed 's/^/#   /' >> "${REPORT}"
    fi
    if [ -s "${PROBE_LOG}" ]; then
        note "# probe process log (last 30 lines):"
        tail -n 30 "${PROBE_LOG}" | sed 's/^/#   /' >> "${REPORT}"
    fi
}

# Identify the long-lived probe server without racing its short-lived `qs ipc`
# clients, whose cmdlines carry the same -p path plus the words "ipc call".
# Checking both comm and exe is deliberate: Hyprland normally launches through
# `/bin/sh -c`, and that wrapper's cmdline also contains PROBE_PATH. Measuring
# the wrapper produced plausible-looking ~600 KiB numbers instead of Quickshell.
probe_pid() {
    for proc_dir in /proc/[0-9]*; do
        [ -r "${proc_dir}/cmdline" ] || continue
        [ -r "${proc_dir}/comm" ] || continue
        probe_comm="$(tr -d '\n' < "${proc_dir}/comm" 2>/dev/null)"
        probe_exe="$(readlink "${proc_dir}/exe" 2>/dev/null || true)"
        case "${probe_comm}" in
            qs|quickshell) ;;
            *) continue ;;
        esac
        case "${probe_exe}" in
            */qs|*/quickshell) ;;
            *) continue ;;
        esac
        probe_cmdline="$(tr '\000' ' ' < "${proc_dir}/cmdline" 2>/dev/null)"
        case "${probe_cmdline}" in
            *"${PROBE_PATH}"*)
                case "${probe_cmdline}" in
                    *" ipc call "*) ;;
                    *) printf '%s\n' "${proc_dir#/proc/}"; return 0 ;;
                esac
                ;;
        esac
    done
    return 1
}

probe_ready() { [ "$(ipc surfaceprobe state | tr -d '[:space:]\"')" = "idle" ]; }
probe_gone() { ! probe_pid >/dev/null 2>&1; }

stop_probe() {
    stop_pid="$(probe_pid 2>/dev/null || true)"
    if [ -n "${stop_pid}" ]; then
        kill "${stop_pid}" >/dev/null 2>&1 || true
        wait_for 30 probe_gone || true
    fi
}

start_probe() {
    stop_probe
    : > "${PROBE_LOG}"
    : > "${IPC_ERRORS}"
    # Hyprland's exec path supplies the same session environment as the
    # production shell. Capture this measurement-only process's diagnostics;
    # ordinary successful reports remain data-only.
    hyprctl dispatch "hl.dsp.exec_cmd('exec ${PROBE_CMD} >>${PROBE_LOG} 2>&1')" >/dev/null 2>&1
    if ! wait_for 60 probe_ready; then
        return 1
    fi
    # Let startup allocations and the theme file views settle before the
    # empty-process baseline. No process runs inside any QML timestamp span.
    sleep 2
    return 0
}

pss_kib() {
    pss_pid="$1"
    awk '/^Pss:/ {print $2}' "/proc/${pss_pid}/smaps_rollup" 2>/dev/null
}

# Three one-second-spaced readings; the median rejects one allocator/page-fault
# wobble without manufacturing precision from a single /proc read.
median_pss_kib() {
    median_pid="$1"
    median_tmp="/run/punar/.surface-pss-${median_pid}-$$"
    : > "${median_tmp}"
    median_i=0
    while [ "${median_i}" -lt 3 ]; do
        pss_kib "${median_pid}" >> "${median_tmp}"
        median_i=$((median_i + 1))
        [ "${median_i}" -eq 3 ] || sleep 1
    done
    sort -n "${median_tmp}" | sed -n '2p'
    rm -f "${median_tmp}"
}

timing_ready() {
    timing_value="$(ipc surfaceprobe timing | tr -d '[:space:]\"')"
    case "${timing_value}" in
        [0-9]*,[0-9]*,[0-9]*,[0-9]*) return 0 ;;
        *) return 1 ;;
    esac
}

surface_closed() {
    [ "$(ipc surfaceprobe surfaceState | tr -d '[:space:]\"')" = "closed" ]
}

for surface in ${SURFACES}; do
    sample=1
    while [ "${sample}" -le "${SAMPLES}" ]; do
        if ! start_probe; then
            note "FAIL ${surface} sample ${sample}: probe did not become ready"
            FAILED=1
            finish
        fi

        pid="$(probe_pid 2>/dev/null || true)"
        if [ -z "${pid}" ]; then
            note "FAIL ${surface} sample ${sample}: probe PID is absent"
            FAILED=1
            finish
        fi
        probe_identity_comm="$(tr -d '\n' < "/proc/${pid}/comm" 2>/dev/null)"
        probe_identity_exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
        note "# ${surface} sample ${sample} probe_pid=${pid} comm=${probe_identity_comm} exe=${probe_identity_exe}"

        base_pss="$(median_pss_kib "${pid}")"
        case "${base_pss}" in
            ''|*[!0-9]*)
                note "FAIL ${surface} sample ${sample}: invalid empty-probe PSS '${base_pss}'"
                FAILED=1
                finish
                ;;
        esac
        if [ "${base_pss}" -lt "${MIN_PROBE_PSS_KIB}" ]; then
            note "FAIL ${surface} sample ${sample}: empty-probe PSS ${base_pss} KiB is below ${MIN_PROBE_PSS_KIB} KiB sanity floor"
            probe_diagnostics
            FAILED=1
            finish
        fi
        open_result="$(ipc surfaceprobe open "${surface}" | tr -d '[:space:]\"')"
        if [ "${open_result}" != "loading" ]; then
            note "FAIL ${surface} sample ${sample}: open returned '${open_result}'"
            probe_diagnostics
            FAILED=1
            finish
        fi

        if ! wait_for 45 timing_ready; then
            note "FAIL ${surface} sample ${sample}: no construction/openlayer timing ('$(ipc surfaceprobe timing | tr -d '[:space:]\"')')"
            probe_diagnostics
            FAILED=1
            finish
        fi
        timing="$(ipc surfaceprobe timing | tr -d '[:space:]\"')"

        old_ifs="${IFS}"
        IFS=,
        # The shape was validated by timing_ready immediately above.
        # shellcheck disable=SC2086
        set -- ${timing}
        IFS="${old_ifs}"
        started_at="$1"
        loaded_at="$2"
        opened_at="$3"
        mapped_at="$4"

        timestamps_valid=yes
        for timestamp in "${started_at}" "${loaded_at}" "${opened_at}" "${mapped_at}"; do
            case "${timestamp}" in
                ''|*[!0-9]*) timestamps_valid=no ;;
            esac
        done
        if [ "${timestamps_valid}" != "yes" ]; then
            note "FAIL ${surface} sample ${sample}: malformed timing '${timing}'"
            FAILED=1
            finish
        fi

        construct_ms=$((loaded_at - started_at))
        handoff_ms=$((opened_at - loaded_at))
        shell_map_ms=$((mapped_at - opened_at))
        first_map_ms=$((mapped_at - started_at))
        if [ "${construct_ms}" -lt 0 ] || [ "${handoff_ms}" -lt 0 ] \
                || [ "${shell_map_ms}" -lt 0 ]; then
            note "FAIL ${surface} sample ${sample}: timestamps ran backwards (${timing})"
            FAILED=1
            finish
        fi

        ipc surfaceprobe close >/dev/null 2>&1
        if ! wait_for 15 surface_closed; then
            note "FAIL ${surface} sample ${sample}: surface did not close"
            FAILED=1
        fi
        # Exit animation is Theme.durStandard (300 ms); sample the retained,
        # closed surface after its window has actually hidden.
        sleep 1
        resident_pss="$(median_pss_kib "${pid}")"
        case "${resident_pss}" in
            ''|*[!0-9]*)
                note "FAIL ${surface} sample ${sample}: invalid resident PSS '${resident_pss}'"
                FAILED=1
                finish
                ;;
        esac
        resident_delta=$((resident_pss - base_pss))

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${surface}" "${sample}" "${base_pss}" "${resident_pss}" \
            "${resident_delta}" "${construct_ms}" "${handoff_ms}" \
            "${shell_map_ms}" "${first_map_ms}" >> "${REPORT}"

        stop_probe
        sample=$((sample + 1))
    done
done

# Decision rows. With exactly three samples, the middle sorted value is the
# median. Keep each metric's median independent; this is a ranking instrument,
# not a fictional single run assembled from unrelated columns.
for surface in ${SURFACES}; do
    rows="$(awk -F '\t' -v s="${surface}" '$1 == s && $2 ~ /^[0-9]+$/ {n++} END {print n+0}' "${REPORT}")"
    if [ "${rows}" -ne "${SAMPLES}" ]; then
        note "FAIL ${surface}: expected ${SAMPLES} valid rows, got ${rows}"
        FAILED=1
        continue
    fi
    median_delta="$(awk -F '\t' -v s="${surface}" '$1 == s {print $5}' "${REPORT}" | sort -n | sed -n '2p')"
    median_construct="$(awk -F '\t' -v s="${surface}" '$1 == s {print $6}' "${REPORT}" | sort -n | sed -n '2p')"
    median_shell_map="$(awk -F '\t' -v s="${surface}" '$1 == s {print $8}' "${REPORT}" | sort -n | sed -n '2p')"
    median_first_map="$(awk -F '\t' -v s="${surface}" '$1 == s {print $9}' "${REPORT}" | sort -n | sed -n '2p')"
    note "median ${surface}: resident_delta_kib=${median_delta} construct_ms=${median_construct} shell_map_ms=${median_shell_map} first_map_ms=${median_first_map}"
done

finish
