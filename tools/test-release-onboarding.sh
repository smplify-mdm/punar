#!/bin/bash
# End-to-end release onboarding proof, on either architecture.
#
# The release image is always attached with `-snapshot`, so the first account
# and every disk write are disposable. The only retained frames are the
# untouched first screen and the signed-in desktop. The one-time recovery
# receipt is never captured to an output artifact, and the synthetic password
# never appears in argv or logs.
#
# The ARM64 lane still boots through tools/demo-arm64-vm.sh, unchanged: that
# path is the one canonical CI has been running. The x86_64 lane launches
# QEMU directly, because tools/demo-vm.sh is a macOS-only human demo
# launcher (hardcoded Homebrew paths, VNC, a Unix-socket QMP) and cannot run
# on a Linux runner.
set -euo pipefail
umask 077

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-}"
ARCH="${PUNAR_QEMU_ARCH:-}"
if [ -z "${ARCH}" ]; then
    case "$(basename "${IMAGE:-punar-release-arm64}")" in
        *arm64*|*aarch64*) ARCH=arm64 ;;
        *) ARCH=x86_64 ;;
    esac
fi
case "${ARCH}" in
    arm64) DEFAULT_IMAGE="${REPO_ROOT}/os/images/out/punar-release-arm64.qcow2" ;;
    x86_64) DEFAULT_IMAGE="${REPO_ROOT}/os/images/out/punar-release-debian-x86_64.qcow2" ;;
    *) echo "error: invalid PUNAR_QEMU_ARCH '${ARCH}' (expected x86_64 or arm64)" >&2; exit 2 ;;
esac
IMAGE="${IMAGE:-${DEFAULT_IMAGE}}"
OUTPUT="${2:-${REPO_ROOT}/os/images/out/${ARCH}-onboarding-proof-$(date -u +%Y%m%dT%H%M%SZ)}"
QMP_HOST=127.0.0.1
QMP_PORT="${PUNAR_ONBOARDING_QMP_PORT:-4455}"
TEST_USERNAME=releasepilot
TEST_PASSWORD='amber river lantern'
TEST_DEVICE='punar-test'
VM_PID=""
TEST_TMP="$(mktemp -d "${TMPDIR:-/tmp}/punar-onboarding.XXXXXX")"
SERIAL_LOG="${TEST_TMP}/serial.log"
FRAME="${TEST_TMP}/frame.ppm"
VARS_COPY="${TEST_TMP}/OVMF_VARS.fd"
QEMU_BINARY=""
OVMF_CODE=""
OVMF_VARS=""

# Match tools/boot-test.sh: KVM only when host and guest architectures agree,
# HVF for the native Apple Silicon ARM lane, TCG otherwise. TCG is honest but
# slow, so the structural waits scale with it instead of failing a correct
# machine for being emulated.
HOST_ARCH="$(uname -m)"
case "${HOST_ARCH}" in
    aarch64) HOST_ARCH="arm64" ;;
    amd64)   HOST_ARCH="x86_64" ;;
esac
ACCEL=tcg
CPU=max
if [ "${HOST_ARCH}" = "${ARCH}" ] \
        && [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL=kvm
    CPU=host
elif [ "$(uname -s)" = Darwin ] && [ "${HOST_ARCH}" = arm64 ] \
        && [ "${ARCH}" = arm64 ]; then
    ACCEL=hvf
    CPU=host
fi
if [ "${ACCEL}" = tcg ]; then
    ONBOARDING_TIMEOUT=600
    RECEIPT_TIMEOUT=300
    DESKTOP_TIMEOUT=900
else
    ONBOARDING_TIMEOUT=90
    RECEIPT_TIMEOUT=60
    DESKTOP_TIMEOUT=120
fi


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
if [ "${ARCH}" = x86_64 ]; then
    QEMU_BINARY="$(command -v qemu-system-x86_64 || true)"
    [ -n "${QEMU_BINARY}" ] || die "qemu-system-x86_64 is required"
    if [ -n "${PUNAR_OVMF_CODE:-}" ] || [ -n "${PUNAR_OVMF_VARS:-}" ]; then
        [ -f "${PUNAR_OVMF_CODE:-}" ] && [ -f "${PUNAR_OVMF_VARS:-}" ] \
            || die "PUNAR_OVMF_CODE and PUNAR_OVMF_VARS must both name existing files"
        OVMF_CODE="${PUNAR_OVMF_CODE}"
        OVMF_VARS="${PUNAR_OVMF_VARS}"
    else
        for candidate in \
                "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
                "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
                "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
                "/usr/share/edk2/x64/OVMF_CODE.fd:/usr/share/edk2/x64/OVMF_VARS.fd"; do
            code="${candidate%%:*}"
            vars="${candidate##*:}"
            if [ -f "${code}" ] && [ -f "${vars}" ]; then
                OVMF_CODE="${code}"
                OVMF_VARS="${vars}"
                break
            fi
        done
        [ -n "${OVMF_CODE}" ] || die "x86_64 UEFI firmware (OVMF) was not found"
    fi
fi
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

echo "==> Booting fixture-free release image for onboarding proof (${ARCH}, ${ACCEL})"
if [ "${ARCH}" = arm64 ]; then
    PUNAR_QMP_PORT="${QMP_PORT}" \
    PUNAR_VM_DISPLAY=none \
    PUNAR_VM_OPEN_VIEWER=0 \
        "${REPO_ROOT}/tools/demo-arm64-vm.sh" "${IMAGE}" \
        >"${SERIAL_LOG}" 2>&1 &
    VM_PID=$!
else
    cp "${OVMF_VARS}" "${VARS_COPY}"
    "${QEMU_BINARY}" \
        -machine "q35,accel=${ACCEL}" \
        -cpu "${CPU}" \
        -m 4096 \
        -smp 4 \
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}" \
        -drive "if=pflash,format=raw,file=${VARS_COPY}" \
        -drive "file=${IMAGE},format=qcow2,if=virtio" \
        -snapshot \
        -display none \
        -vga none \
        -device virtio-vga \
        -device virtio-keyboard \
        -device virtio-tablet \
        -nic user,model=virtio-net-pci \
        -qmp "tcp:${QMP_HOST}:${QMP_PORT},server,nowait" \
        -name Punar \
        >"${SERIAL_LOG}" 2>&1 &
    VM_PID=$!
fi

attempts=0
while [ "${attempts}" -lt 300 ]; do
    nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1 && break
    kill -0 "${VM_PID}" 2>/dev/null || die "QEMU exited before QMP became ready"
    attempts=$((attempts + 1))
    sleep 0.1
done
nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1 \
    || die "QMP did not become ready"

wait_for_state onboarding "${ONBOARDING_TIMEOUT}" || {
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
wait_for_state receipt "${RECEIPT_TIMEOUT}" || {
    tail -80 "${SERIAL_LOG}" >&2 || true
    die "first-account creation did not produce its recovery receipt"
}
echo "ok   first-account transaction completed"
send_key ret

wait_for_state desktop "${DESKTOP_TIMEOUT}" || {
    tail -80 "${SERIAL_LOG}" >&2 || true
    die "first-account creation did not reach the desktop"
}
python3 "${REPO_ROOT}/tools/framebuffer-probe.py" \
    png "${FRAME}" "${OUTPUT}/desktop.png" >/dev/null
image_sha=$(shasum -a 256 "${IMAGE}" | awk '{print $1}')
{
    echo "PUNAR_ONBOARDING_IMAGE=$(basename "${IMAGE}")"
    echo "PUNAR_ONBOARDING_IMAGE_SHA256=${image_sha}"
    echo "PUNAR_ONBOARDING_ARCHITECTURE=${ARCH}"
    echo "PUNAR_ONBOARDING_ACCEL=${ACCEL}"
    echo "PUNAR_ONBOARDING_SNAPSHOT_DISK=yes"
    echo "PUNAR_ONBOARDING_SECRET_FRAMES_RETAINED=no"
    echo "PUNAR_ONBOARDING_FIRST_ACCOUNT=yes"
    echo "PUNAR_ONBOARDING_DESKTOP=yes"
    echo "PUNAR_ONBOARDING_OK"
} > "${OUTPUT}/report.txt"
chmod 0644 "${OUTPUT}/firstboot.png" "${OUTPUT}/desktop.png" "${OUTPUT}/report.txt"
echo "PUNAR_ONBOARDING_OK proof=${OUTPUT}"
