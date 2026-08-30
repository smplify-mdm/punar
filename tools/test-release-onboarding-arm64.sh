#!/bin/bash
# End-to-end release onboarding proof for a native ARM64 host.
#
# The release image is attached through the demo launcher's mandatory
# `-snapshot`, so the first account and every disk write are disposable. The
# only retained frames are the untouched first screen and the signed-in
# desktop. The one-time recovery receipt is never captured to an output
# artifact, and the synthetic password never appears in argv or logs.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-release-arm64.qcow2}"
OUTPUT="${2:-${REPO_ROOT}/os/images/out/arm64-onboarding-proof-$(date -u +%Y%m%dT%H%M%SZ)}"
QMP_HOST=127.0.0.1
QMP_PORT="${PUNAR_ONBOARDING_QMP_PORT:-4455}"
TEST_USERNAME=releasepilot
TEST_PASSWORD='amber river lantern'
TEST_DEVICE='punar-test'
VM_PID=""
TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/punar-onboarding.XXXXXX")"
SERIAL_LOG="${TEST_TMP}/serial.log"
FRAME="${TEST_TMP}/frame.ppm"

die() {
    echo "error: $*" >&2
    exit 1
}

cleanup() {
    if nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1; then
        { printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}'; } \
            | nc -w 2 "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1 || true
    fi
    if [ -n "${VM_PID}" ]; then
        wait "${VM_PID}" >/dev/null 2>&1 || true
    fi
    rm -rf "${TEST_TMP}"
}
trap cleanup EXIT INT TERM

[ -f "${IMAGE}" ] || die "release image not found: ${IMAGE}"
[ ! -e "${OUTPUT}" ] || die "refusing to overwrite proof directory: ${OUTPUT}"
command -v nc >/dev/null 2>&1 || die "nc is required"
command -v python3 >/dev/null 2>&1 || die "python3 is required"
if nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1; then
    die "QMP port ${QMP_PORT} is already in use"
fi
mkdir -p "${OUTPUT}"

qmp_hmp() {
    command_line=$1
    reply=$(
        printf '%s\n' \
            '{"execute":"qmp_capabilities"}' \
            "{\"execute\":\"human-monitor-command\",\"arguments\":{\"command-line\":\"${command_line}\"}}" \
            | nc -w 2 "${QMP_HOST}" "${QMP_PORT}" 2>/dev/null || true
    )
    case "${reply}" in
        *'"error"'*) die "QEMU rejected input command: ${command_line}" ;;
    esac
}

send_key() {
    qmp_hmp "sendkey $1"
    sleep 0.12
}

type_text() {
    text=$1
    index=0
    while [ "${index}" -lt "${#text}" ]; do
        character="${text:${index}:1}"
        case "${character}" in
            ' ') key=spc ;;
            '-') key=minus ;;
            [a-z0-9]) key="${character}" ;;
            *) die "test input contains an unsupported character" ;;
        esac
        send_key "${key}"
        index=$((index + 1))
    done
}

capture_frame() {
    rm -f "${FRAME}"
    request=$(printf \
        '{"execute":"screendump","arguments":{"filename":"%s"}}' \
        "${FRAME}")
    reply=$(
        { printf '%s\n' '{"execute":"qmp_capabilities"}' "${request}"; } \
            | nc -w 2 "${QMP_HOST}" "${QMP_PORT}" 2>/dev/null || true
    )
    case "${reply}" in
        *'"error"'*) return 1 ;;
    esac
    attempts=0
    while [ "${attempts}" -lt 20 ] && [ ! -s "${FRAME}" ]; do
        attempts=$((attempts + 1))
        sleep 0.1
    done
    [ -s "${FRAME}" ]
}

wait_for_state() {
    wanted=$1
    limit=$2
    elapsed=0
    while [ "${elapsed}" -lt "${limit}" ]; do
        if capture_frame \
                && python3 "${REPO_ROOT}/tools/framebuffer-probe.py" \
                    "${wanted}" "${FRAME}" >/dev/null 2>&1; then
            return 0
        fi
        sleep 2
        elapsed=$((elapsed + 2))
    done
    return 1
}

echo "==> Booting fixture-free release image for onboarding proof"
PUNAR_QMP_PORT="${QMP_PORT}" \
PUNAR_VM_DISPLAY=none \
PUNAR_VM_OPEN_VIEWER=0 \
    "${REPO_ROOT}/tools/demo-arm64-vm.sh" "${IMAGE}" \
    >"${SERIAL_LOG}" 2>&1 &
VM_PID=$!

attempts=0
while [ "${attempts}" -lt 300 ]; do
    nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1 && break
    kill -0 "${VM_PID}" 2>/dev/null || die "QEMU exited before QMP became ready"
    attempts=$((attempts + 1))
    sleep 0.1
done
nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1 \
    || die "QMP did not become ready"

wait_for_state onboarding 90 || {
    tail -80 "${SERIAL_LOG}" >&2 || true
    die "the release onboarding surface did not become visible"
}
python3 "${REPO_ROOT}/tools/framebuffer-probe.py" \
    png "${FRAME}" "${OUTPUT}/firstboot.png" >/dev/null
echo "ok   clean release onboarding rendered"

# The real keyboard path. Enter moves between fields and the compact-layout
# focus contract scrolls each destination into view.
type_text "${TEST_USERNAME}"
send_key ret
type_text "${TEST_PASSWORD}"
send_key ret
type_text "${TEST_PASSWORD}"
send_key ret
type_text "${TEST_DEVICE}"
send_key ret

# Account creation is a local transaction. Wait for the receipt structurally
# rather than guessing how long password hashing and identity materialization
# take. The receipt heading owns the default Enter action. Do not retain this
# state: it contains the one-time local recovery code.
wait_for_state receipt 60 || {
    tail -80 "${SERIAL_LOG}" >&2 || true
    die "first-account creation did not produce its recovery receipt"
}
echo "ok   first-account transaction completed"
send_key ret

wait_for_state desktop 120 || {
    tail -80 "${SERIAL_LOG}" >&2 || true
    die "first-account creation did not reach the desktop"
}
python3 "${REPO_ROOT}/tools/framebuffer-probe.py" \
    png "${FRAME}" "${OUTPUT}/desktop.png" >/dev/null
image_sha=$(shasum -a 256 "${IMAGE}" | awk '{print $1}')
{
    echo "PUNAR_ONBOARDING_IMAGE=$(basename "${IMAGE}")"
    echo "PUNAR_ONBOARDING_IMAGE_SHA256=${image_sha}"
    echo "PUNAR_ONBOARDING_ARCHITECTURE=arm64"
    echo "PUNAR_ONBOARDING_SNAPSHOT_DISK=yes"
    echo "PUNAR_ONBOARDING_SECRET_FRAMES_RETAINED=no"
    echo "PUNAR_ONBOARDING_FIRST_ACCOUNT=yes"
    echo "PUNAR_ONBOARDING_DESKTOP=yes"
    echo "PUNAR_ONBOARDING_OK"
} > "${OUTPUT}/report.txt"
chmod 0644 "${OUTPUT}/firstboot.png" "${OUTPUT}/desktop.png" "${OUTPUT}/report.txt"
echo "PUNAR_ONBOARDING_OK proof=${OUTPUT}"
