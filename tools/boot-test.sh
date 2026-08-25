#!/usr/bin/env bash
# QEMU boot test for the Punar images (spec 74.3 "boot"; milestone-1.md §7–§10).
#
# Two modes, chosen with --mode or inferred from the image filename
# (*punar-desktop* -> desktop, anything else -> minimal):
#
# minimal (M0 smoke test — behavior unchanged from Milestone 0):
#   Boots the qcow2 headless under UEFI (OVMF/edk2) with the serial console
#   on ttyS0 captured to a log, and waits for a deterministic marker:
#     primary:  "PUNAR_BOOT_OK"  — punar-boot-marker.service at multi-user
#     fallback: a getty "login:" prompt on the serial console
#
# desktop (M1 graphical acceptance gate — milestone-1.md §7–§9):
#   Boots with the survey-decided VM shape for the minimum-target machine
#   (PERFORMANCE_BUDGETS.md §5.1: -m 8192 -smp 4) and -device virtio-vga
#   (no virgl; the guest renders via mesa llvmpipe), plus a dedicated
#   virtio-serial export channel (name=punar.export), then waits through
#   three phases on the serial console:
#     1. "PUNAR_DESKTOP_OK"      compositor up + punar-shell constructed
#                                (punar-desktop-marker.service)
#     2. "PUNAR_RAM_MEAN_MB=<n> PUNAR_RAM_MAX_MB=<n>"
#                                canonical idle-RAM measurement, performed
#                                IN THE GUEST by punar-idle-ram.service with
#                                the method fixed by PERFORMANCE_BUDGETS.md
#                                §2.1–2.2 (10 min stabilize after the
#                                graphical session is up, then a 5-minute
#                                window sampling MemTotal - MemAvailable
#                                every 10 s; mean and max). This script only
#                                waits for and records the guest's numbers —
#                                it does not sample, and it does not shorten
#                                the canonical stabilization.
#     3. "PUNAR_EXPORT_END" on the export channel — the guest streams
#        `tar -C /run/punar | base64` (screenshot.png, meminfo,
#        ram-samples.txt, and since M2 the m2-report.txt / punar-m2.png /
#        m2-*.json exercise artifacts) between PUNAR_EXPORT_BEGIN/END
#        sentinels. The M2 exercise (punar-m2-check.service, started by
#        idle-ram.sh strictly between the sampling window and the export)
#        runs inside this phase's wait — EXPORT_TIMEOUT covers it.
#     4. M2 verdict (milestone-2.md §7): parse the exported m2-report.txt.
#        PUNAR_M2_FAIL (or a truncated report) hard-fails the gate; a
#        MISSING report is a ::warning:: under KVM and info-only under TCG
#        (an emulated run that could not even export is already flagged).
#   Host-side results land in <proof-dir> (default
#   os/images/out/desktop-proof):
#     punar-desktop-screenshot.png  grim capture — proof of real rendering
#     punar-m2.png                  grim capture with the overview open (M2)
#     ram-report.txt                key=value idle-RAM numbers + environment
#     ram-samples.txt, meminfo      raw guest measurement data
#     m2-report.txt, m2-*.json      M2 exercise verdict + hyprctl snapshots
#     serial.log                    full serial console log (also on failure)
#   The budget VERDICT is not applied here: tests/performance/
#   check-budgets.sh reads ram-report.txt and gates against
#   PERFORMANCE_BUDGETS.md (fail > 1536 MB mean, warn > 1024 MB).
#   A missing/corrupt export or screenshot is a warning, not a failure —
#   the guest treats a failed grim the same way (its absence is a signal),
#   and the RAM gate rests on the serial numbers. The M2 verdict is the
#   one exception: an exported report that says PUNAR_M2_FAIL fails here.
#
# KVM is used when /dev/kvm is present and accessible; otherwise the test
# degrades to TCG software emulation with a visible warning (and a GitHub
# Actions ::warning:: annotation in CI) and longer default timeouts. In
# desktop mode a TCG run additionally labels the RAM numbers
# "(VM, emulated)" — indicative only, never a gate (budgets §5.2).
#
# Usage: tools/boot-test.sh [--mode minimal|desktop] [image.qcow2] [proof-dir]
# Environment:
#   PUNAR_BOOT_TIMEOUT     minimal: seconds to wait for the boot marker
#                          (default: 300 KVM, 1200 TCG)
#   PUNAR_DESKTOP_TIMEOUT  desktop: seconds to wait for PUNAR_DESKTOP_OK
#                          (default: 900 KVM, 3600 TCG)
#   PUNAR_RAM_TIMEOUT      desktop: seconds after PUNAR_DESKTOP_OK to wait
#                          for the RAM result line; must cover the guest's
#                          fixed 10 min + 5 min measurement
#                          (default: 1200 KVM, 2400 TCG)
#   PUNAR_EXPORT_TIMEOUT   desktop: seconds to wait for the export sentinel
#                          — must also cover the in-guest M2 exercise,
#                          which runs between the RAM result and the export
#                          (default: 900 KVM, 2400 TCG)
#   PUNAR_PROOF_DIR        desktop: where to land the collected files
#                          (default: os/images/out/desktop-proof)
#
# Requirements: qemu-system-x86_64 and an OVMF/edk2 x86_64 firmware pair
# (Ubuntu: apt install qemu-system-x86 ovmf; Arch: pacman -S qemu-base edk2-ovmf;
# macOS: brew install qemu — TCG only, Apple Silicon cannot KVM-accelerate x86).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    # Print this file's header comment (everything up to the first
    # non-comment line) as the help text.
    awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "${BASH_SOURCE[0]}"
}

warn() {
    echo "warning: $*" >&2
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::warning::$*"
    fi
}

die() {
    echo "error: $*" >&2
    exit 1
}

# --- argument parsing --------------------------------------------------------
MODE=""
ARG_IMAGE=""
ARG_PROOF_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            [ $# -ge 2 ] || die "--mode requires a value (minimal|desktop)"
            MODE="$2"
            shift 2
            ;;
        --mode=*)
            MODE="${1#--mode=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1 (see --help)"
            ;;
        *)
            if [ -z "${ARG_IMAGE}" ]; then
                ARG_IMAGE="$1"
            elif [ -z "${ARG_PROOF_DIR}" ]; then
                ARG_PROOF_DIR="$1"
            else
                die "unexpected argument: $1 (see --help)"
            fi
            shift
            ;;
    esac
done

IMAGE="${ARG_IMAGE:-${REPO_ROOT}/os/images/out/punar-dev-x86_64.qcow2}"
PROOF_DIR="${ARG_PROOF_DIR:-${PUNAR_PROOF_DIR:-${REPO_ROOT}/os/images/out/desktop-proof}}"

if [ -z "${MODE}" ]; then
    case "$(basename "${IMAGE}")" in
        *punar-desktop*) MODE="desktop" ;;
        *)               MODE="minimal" ;;
    esac
fi
case "${MODE}" in
    minimal|desktop) ;;
    *) die "invalid --mode '${MODE}' (expected minimal or desktop)" ;;
esac

[ -f "${IMAGE}" ] || die "image not found: ${IMAGE} (run tools/build-image.sh first)"
command -v qemu-system-x86_64 >/dev/null 2>&1 \
    || die "qemu-system-x86_64 not found (Ubuntu: apt install qemu-system-x86)"

# --- firmware ----------------------------------------------------------------
# Locate an OVMF/edk2 firmware code+vars pair. Paths are a controlled list
# (Ubuntu, Arch, Homebrew, MacPorts) and contain no colons.
OVMF_CODE=""
OVMF_VARS=""
for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.fd:/usr/share/edk2/x64/OVMF_VARS.fd" \
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd:/opt/homebrew/share/qemu/edk2-i386-vars.fd" \
    "/usr/local/share/qemu/edk2-x86_64-code.fd:/usr/local/share/qemu/edk2-i386-vars.fd"
do
    code="${pair%%:*}"
    vars="${pair##*:}"
    if [ -f "${code}" ] && [ -f "${vars}" ]; then
        OVMF_CODE="${code}"
        OVMF_VARS="${vars}"
        break
    fi
done
[ -n "${OVMF_CODE}" ] || die "no OVMF/edk2 UEFI firmware found (Ubuntu: apt install ovmf)"

# --- accelerator -------------------------------------------------------------
# KVM when present and accessible, else TCG + warning.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL="kvm"
    CPU="host"
    DEFAULT_BOOT_TIMEOUT=300
    DEFAULT_DESKTOP_TIMEOUT=900
    DEFAULT_RAM_TIMEOUT=1200
    # Covers the in-guest M2 exercise (a few minutes under KVM) that runs
    # before the guest starts streaming the export.
    DEFAULT_EXPORT_TIMEOUT=900
    echo "==> /dev/kvm present and accessible: using KVM acceleration"
else
    ACCEL="tcg"
    CPU="max"
    DEFAULT_BOOT_TIMEOUT=1200
    DEFAULT_DESKTOP_TIMEOUT=3600
    DEFAULT_RAM_TIMEOUT=2400
    # TCG: the in-guest M2 exercise before the export is the slow part
    # (window spawns, quickshell relaunch — bounded at 25 min in-guest).
    DEFAULT_EXPORT_TIMEOUT=2400
    warn "/dev/kvm unavailable: degrading to TCG software emulation (slow; boot may take many minutes)"
    if [ "${MODE}" = "desktop" ]; then
        warn "desktop mode under TCG: RAM numbers will be labeled '(VM, emulated)' and are indicative only (PERFORMANCE_BUDGETS.md §5.2)"
    fi
fi
BOOT_TIMEOUT="${PUNAR_BOOT_TIMEOUT:-${DEFAULT_BOOT_TIMEOUT}}"
DESKTOP_TIMEOUT="${PUNAR_DESKTOP_TIMEOUT:-${DEFAULT_DESKTOP_TIMEOUT}}"
RAM_TIMEOUT="${PUNAR_RAM_TIMEOUT:-${DEFAULT_RAM_TIMEOUT}}"
EXPORT_TIMEOUT="${PUNAR_EXPORT_TIMEOUT:-${DEFAULT_EXPORT_TIMEOUT}}"

# --- workdir + cleanup -------------------------------------------------------
WORKDIR="$(mktemp -d)"
SERIAL_LOG="${WORKDIR}/serial.log"
EXPORT_RAW="${WORKDIR}/export.b64"
VARS_COPY="${WORKDIR}/OVMF_VARS.fd"
QEMU_PID=""

# Invoked indirectly via the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

cp "${OVMF_VARS}" "${VARS_COPY}"

# --- shared helpers ----------------------------------------------------------

# wait_for_pattern <file> <grep -E regex> <timeout-secs> <description>
# Polls <file> for the pattern until the deadline; fails early if qemu dies.
# Sets WAIT_ELAPSED (seconds) either way. Prints a liveness note every ~2 min
# so long desktop phases do not look hung in CI logs.
WAIT_ELAPSED=0
wait_for_pattern() {
    local file="$1" regex="$2" timeout="$3" desc="$4"
    local start deadline now last_note
    start="$(date +%s)"
    deadline=$((start + timeout))
    last_note="${start}"
    while :; do
        now="$(date +%s)"
        WAIT_ELAPSED=$((now - start))
        if [ -f "${file}" ] && grep -aqE "${regex}" "${file}"; then
            return 0
        fi
        if [ "${now}" -ge "${deadline}" ]; then
            echo "error: no '${desc}' within ${timeout}s (accel=${ACCEL})" >&2
            return 1
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            echo "error: qemu exited while waiting for ${desc}" >&2
            return 1
        fi
        if [ $((now - last_note)) -ge 120 ]; then
            echo "    ... waiting for ${desc} (${WAIT_ELAPSED}s elapsed, timeout ${timeout}s)"
            last_note="${now}"
        fi
        sleep 2
    done
}

dump_serial_tail() {
    echo "==> Last 80 lines of serial console:" >&2
    if [ -f "${SERIAL_LOG}" ]; then
        tail -n 80 "${SERIAL_LOG}" >&2 || true
    else
        echo "(no serial output captured)" >&2
    fi
}

# Desktop mode: keep the serial log around for CI artifact upload even when
# the run fails — it is the primary diagnostic for a broken session chain.
preserve_serial_log() {
    if [ -f "${SERIAL_LOG}" ]; then
        mkdir -p "${PROOF_DIR}"
        cp "${SERIAL_LOG}" "${PROOF_DIR}/serial.log" || true
    fi
}

# =============================================================================
# minimal mode — M0 smoke test (unchanged semantics)
# =============================================================================
run_minimal() {
    local marker_primary='PUNAR_BOOT_OK'
    local marker_regex='PUNAR_BOOT_OK|login:'

    local qemu_args=(
        -machine "q35,accel=${ACCEL}"
        -cpu "${CPU}"
        -m 2048
        -smp 2
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${VARS_COPY}"
        -drive "file=${IMAGE},format=qcow2,if=virtio"
        -snapshot
        -display none
        -vga none
        -serial "file:${SERIAL_LOG}"
        -monitor none
        -nic none
        -no-reboot
    )

    echo "==> Booting ${IMAGE} (mode=minimal)"
    echo "    accel=${ACCEL} timeout=${BOOT_TIMEOUT}s firmware=${OVMF_CODE}"
    qemu-system-x86_64 "${qemu_args[@]}" &
    QEMU_PID=$!

    if ! wait_for_pattern "${SERIAL_LOG}" "${marker_regex}" "${BOOT_TIMEOUT}" "boot marker"; then
        dump_serial_tail
        exit 1
    fi

    if grep -aq "${marker_primary}" "${SERIAL_LOG}"; then
        echo "==> PASS: primary marker '${marker_primary}' after ${WAIT_ELAPSED}s (accel=${ACCEL})"
    else
        echo "==> PASS: fallback marker (login prompt) after ${WAIT_ELAPSED}s (accel=${ACCEL}); primary marker not seen"
    fi
    echo "==> Marker context from serial console:"
    grep -aE "${marker_regex}|MemTotal|MemAvailable" "${SERIAL_LOG}" | tail -n 10 || true
    exit 0
}

# =============================================================================
# desktop mode — M1 graphical gate + idle-RAM collection (milestone-1.md §7–§9)
# =============================================================================
run_desktop() {
    local desktop_marker='PUNAR_DESKTOP_OK'
    local ram_regex='PUNAR_RAM_MEAN_MB=[0-9]+ PUNAR_RAM_MAX_MB=[0-9]+'
    local desktop_ok_secs=""

    mkdir -p "${PROOF_DIR}"
    rm -f "${PROOF_DIR}/punar-desktop-screenshot.png" \
          "${PROOF_DIR}/punar-m2.png" \
          "${PROOF_DIR}/ram-report.txt" \
          "${PROOF_DIR}/ram-samples.txt" \
          "${PROOF_DIR}/meminfo" \
          "${PROOF_DIR}/m2-report.txt" \
          "${PROOF_DIR}"/m2-*.json \
          "${PROOF_DIR}/serial.log"

    # VM shape per PERFORMANCE_BUDGETS.md §5.1 (minimum target: 4 vCPU, 8 GB)
    # and milestone-1.md §6/§9: virtio-vga (guest KMS, llvmpipe rendering, no
    # virgl needed under -display none) + the punar.export virtio-serial
    # channel captured to a plain host file. -nic none matches the minimal
    # test; budgets §2.1 item 5 prefers idle-with-network — recorded as a
    # deviation in tests/performance/README.md until guest networking lands.
    local qemu_args=(
        -machine "q35,accel=${ACCEL}"
        -cpu "${CPU}"
        -m 8192
        -smp 4
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${VARS_COPY}"
        -drive "file=${IMAGE},format=qcow2,if=virtio"
        -snapshot
        -display none
        -vga none
        -device virtio-vga
        -serial "file:${SERIAL_LOG}"
        -monitor none
        -nic none
        -no-reboot
        -device virtio-serial-pci
        -chardev "file,id=punarexp,path=${EXPORT_RAW}"
        -device "virtserialport,chardev=punarexp,name=punar.export"
    )

    echo "==> Booting ${IMAGE} (mode=desktop)"
    echo "    accel=${ACCEL} timeouts: desktop=${DESKTOP_TIMEOUT}s ram=${RAM_TIMEOUT}s export=${EXPORT_TIMEOUT}s"
    echo "    firmware=${OVMF_CODE} proof-dir=${PROOF_DIR}"
    qemu-system-x86_64 "${qemu_args[@]}" &
    QEMU_PID=$!

    # Phase 1: graphical session up (greetd -> Hyprland -> punar-shell ->
    # desktop-ready.sh -> punar-desktop-marker.service).
    if ! wait_for_pattern "${SERIAL_LOG}" "${desktop_marker}" "${DESKTOP_TIMEOUT}" "${desktop_marker}"; then
        preserve_serial_log
        dump_serial_tail
        exit 1
    fi
    desktop_ok_secs="${WAIT_ELAPSED}"
    echo "==> ${desktop_marker} after ${desktop_ok_secs}s (accel=${ACCEL})"

    # Phase 2: the in-guest canonical measurement (fixed 10 min stabilize +
    # 5 min sampling window — PERFORMANCE_BUDGETS.md §2.1–2.2; ~16 min wall
    # clock, sleeps are wall-clock even under TCG).
    echo "==> Waiting for in-guest idle-RAM measurement (canonical ~16 min; punar-idle-ram.service)"
    if ! wait_for_pattern "${SERIAL_LOG}" "${ram_regex}" "${RAM_TIMEOUT}" "idle-RAM result (PUNAR_RAM_MEAN_MB)"; then
        preserve_serial_log
        dump_serial_tail
        exit 1
    fi

    local ram_line ram_mean ram_max
    ram_line="$(grep -aoE "${ram_regex}" "${SERIAL_LOG}" | tail -n 1)"
    ram_mean="${ram_line#PUNAR_RAM_MEAN_MB=}"
    ram_mean="${ram_mean%% *}"
    ram_max="${ram_line##*PUNAR_RAM_MAX_MB=}"
    echo "==> Idle RAM from guest: mean=${ram_mean} MB max=${ram_max} MB"

    # Phase 3: artifact export on the virtio-serial channel (milestone-1.md
    # §9). Non-fatal: the RAM gate rests on the serial numbers above, and the
    # guest deliberately continues without a screenshot too.
    local export_ok=0
    if wait_for_pattern "${EXPORT_RAW}" '^PUNAR_EXPORT_END$' "${EXPORT_TIMEOUT}" "PUNAR_EXPORT_END on export channel"; then
        export_ok=1
    else
        warn "desktop-test: no artifact export received on punar.export within ${EXPORT_TIMEOUT}s; screenshot/meminfo/ram-samples will be missing"
    fi

    if [ "${export_ok}" -eq 1 ]; then
        local guest_dir="${WORKDIR}/guest-export"
        mkdir -p "${guest_dir}"
        if awk '/^PUNAR_EXPORT_END$/{exit} inblock{print} /^PUNAR_EXPORT_BEGIN$/{inblock=1}' "${EXPORT_RAW}" \
                | base64 -d > "${WORKDIR}/export.tar" \
                && tar -xf "${WORKDIR}/export.tar" -C "${guest_dir}"; then
            if [ -f "${guest_dir}/screenshot.png" ]; then
                cp "${guest_dir}/screenshot.png" "${PROOF_DIR}/punar-desktop-screenshot.png"
                echo "==> Screenshot landed: ${PROOF_DIR}/punar-desktop-screenshot.png"
            else
                warn "desktop-test: export received but contains no screenshot.png (grim failed in guest?)"
            fi
            for f in ram-samples.txt meminfo m2-report.txt punar-m2.png; do
                if [ -f "${guest_dir}/${f}" ]; then
                    cp "${guest_dir}/${f}" "${PROOF_DIR}/${f}"
                fi
            done
            # M2 hyprctl -j snapshots (m2-layout-*.json, m2-clients*.json,
            # m2-workspaces*.json) — diagnostics for the phase-4 verdict.
            for f in "${guest_dir}"/m2-*.json; do
                if [ -f "${f}" ]; then
                    cp "${f}" "${PROOF_DIR}/"
                fi
            done
        else
            warn "desktop-test: failed to decode/untar the punar.export payload (corrupt channel capture?)"
        fi
    fi

    # ram-report.txt — the file tests/performance/check-budgets.sh gates on.
    # Environment labels per PERFORMANCE_BUDGETS.md §2.2/§5.2: VM under KVM,
    # VM-emulated under TCG (indicative only, never gated).
    local env_label="VM"
    if [ "${ACCEL}" != "kvm" ]; then
        env_label="VM-emulated"
    fi
    {
        echo "# Punar idle-RAM report — generated by tools/boot-test.sh (desktop mode)"
        echo "# Method: PERFORMANCE_BUDGETS.md §2.1–2.2, measured in-guest by punar-idle-ram.service"
        echo "# (MemTotal - MemAvailable; 10 min stabilize, 5 min window, 10 s cadence; mean+max)."
        echo "# PUNAR_DESKTOP_OK_HOST_SECS is host wall clock from qemu start to the marker —"
        echo "# an informational boot-to-desktop proxy (budgets §2.6), not a measured boot metric."
        echo "PUNAR_RAM_MEAN_MB=${ram_mean}"
        echo "PUNAR_RAM_MAX_MB=${ram_max}"
        echo "PUNAR_RAM_ACCEL=${ACCEL}"
        echo "PUNAR_RAM_ENV_LABEL=${env_label}"
        echo "PUNAR_RAM_IMAGE=$(basename "${IMAGE}")"
        echo "PUNAR_RAM_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "PUNAR_DESKTOP_OK_HOST_SECS=${desktop_ok_secs}"
    } > "${PROOF_DIR}/ram-report.txt"

    preserve_serial_log

    # Phase 4: M2 exercise verdict (milestone-2.md §7). The guest wrote
    # /run/punar/m2-report.txt (per-assertion ok/FAIL lines + a final
    # PUNAR_M2_OK / PUNAR_M2_FAIL line) via punar-m2-check.service; it
    # arrived in the phase-3 export. Hard gate: a delivered FAIL — or a
    # truncated report, meaning the guest crashed mid-exercise — fails
    # this script. A MISSING report degrades: the report is also echoed to
    # the serial console, so serial is checked as the fallback verdict;
    # with no verdict anywhere it is a ::warning:: under KVM and info-only
    # under TCG (an emulated run is already flagged and not M2-gated).
    local m2_report="${PROOF_DIR}/m2-report.txt"
    if [ -f "${m2_report}" ]; then
        if grep -q 'PUNAR_M2_FAIL' "${m2_report}"; then
            echo "error: M2 exercise reported PUNAR_M2_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m2_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M2_OK' "${m2_report}"; then
            echo "==> M2 exercise: PUNAR_M2_OK ($(grep -c '^ok' "${m2_report}" || true) assertions passed)"
        else
            echo "error: m2-report.txt carries no PUNAR_M2_OK/PUNAR_M2_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m2_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M2_FAIL' "${SERIAL_LOG}"; then
        echo "error: M2 exercise reported PUNAR_M2_FAIL on the serial console (export did not deliver m2-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M2_OK' "${SERIAL_LOG}"; then
        echo "==> M2 exercise: PUNAR_M2_OK (verdict from serial console; export did not deliver m2-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        warn "desktop-test: no m2-report.txt in the export and no M2 verdict on serial — the M2 exercise did not run"
    else
        echo "==> M2 exercise: no report under TCG (informational only; emulated runs are not M2-gated)"
    fi

    echo "==> PASS: desktop gate complete (accel=${ACCEL}, ${desktop_marker} after ${desktop_ok_secs}s)"
    echo "==> Idle RAM (${env_label}): mean=${ram_mean} MB max=${ram_max} MB — verdict is check-budgets.sh's"
    echo "==> Collected files in ${PROOF_DIR}:"
    ls -l "${PROOF_DIR}" || true
    exit 0
}

case "${MODE}" in
    minimal) run_minimal ;;
    desktop) run_desktop ;;
esac
