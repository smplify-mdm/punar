#!/usr/bin/env bash
# QEMU boot smoke test for the punar-dev image (spec 74.3, "boot").
#
# Boots the qcow2 headless under UEFI (OVMF/edk2) with the serial console on
# ttyS0 captured to a log, and waits for a deterministic marker:
#   primary:  "PUNAR_BOOT_OK"  — emitted by punar-boot-marker.service once
#             multi-user operation is reached (baked into the image from
#             os/images/mkosi.extra/)
#   fallback: a getty "login:" prompt on the serial console
# Fails if neither appears within the timeout, dumping the serial log tail.
#
# KVM is used when /dev/kvm is present and accessible; otherwise the test
# degrades to TCG software emulation with a visible warning (and a GitHub
# Actions ::warning:: annotation in CI) and a longer default timeout.
#
# Usage: tools/boot-test.sh [path/to/image.qcow2]
# Environment:
#   PUNAR_BOOT_TIMEOUT   seconds to wait for the marker
#                        (default: 300 with KVM, 1200 under TCG)
#
# Requirements: qemu-system-x86_64 and an OVMF/edk2 x86_64 firmware pair
# (Ubuntu: apt install qemu-system-x86 ovmf; Arch: pacman -S qemu-base edk2-ovmf;
# macOS: brew install qemu — TCG only, Apple Silicon cannot KVM-accelerate x86).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-dev-x86_64.qcow2}"
MARKER_PRIMARY='PUNAR_BOOT_OK'
MARKER_REGEX='PUNAR_BOOT_OK|login:'

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

[ -f "${IMAGE}" ] || die "image not found: ${IMAGE} (run tools/build-image.sh first)"
command -v qemu-system-x86_64 >/dev/null 2>&1 \
    || die "qemu-system-x86_64 not found (Ubuntu: apt install qemu-system-x86)"

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

# Accelerator selection: KVM when present and accessible, else TCG + warning.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL="kvm"
    CPU="host"
    DEFAULT_TIMEOUT=300
    echo "==> /dev/kvm present and accessible: using KVM acceleration"
else
    ACCEL="tcg"
    CPU="max"
    DEFAULT_TIMEOUT=1200
    warn "/dev/kvm unavailable: degrading to TCG software emulation (slow; boot may take many minutes)"
fi
TIMEOUT="${PUNAR_BOOT_TIMEOUT:-${DEFAULT_TIMEOUT}}"

WORKDIR="$(mktemp -d)"
SERIAL_LOG="${WORKDIR}/serial.log"
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

QEMU_ARGS=(
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

echo "==> Booting ${IMAGE}"
echo "    accel=${ACCEL} timeout=${TIMEOUT}s firmware=${OVMF_CODE}"
qemu-system-x86_64 "${QEMU_ARGS[@]}" &
QEMU_PID=$!

START="$(date +%s)"
DEADLINE=$((START + TIMEOUT))
RESULT=1
while [ "$(date +%s)" -lt "${DEADLINE}" ]; do
    if [ -f "${SERIAL_LOG}" ] && grep -aqE "${MARKER_REGEX}" "${SERIAL_LOG}"; then
        RESULT=0
        break
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        echo "error: qemu exited before a boot marker appeared" >&2
        break
    fi
    sleep 2
done
ELAPSED=$(($(date +%s) - START))

if [ "${RESULT}" -eq 0 ]; then
    if grep -aq "${MARKER_PRIMARY}" "${SERIAL_LOG}"; then
        echo "==> PASS: primary marker '${MARKER_PRIMARY}' after ${ELAPSED}s (accel=${ACCEL})"
    else
        echo "==> PASS: fallback marker (login prompt) after ${ELAPSED}s (accel=${ACCEL}); primary marker not seen"
    fi
    echo "==> Marker context from serial console:"
    grep -aE "${MARKER_REGEX}|MemTotal|MemAvailable" "${SERIAL_LOG}" | tail -n 10 || true
    exit 0
fi

echo "error: no boot marker within ${TIMEOUT}s (accel=${ACCEL})" >&2
echo "==> Last 80 lines of serial console:" >&2
if [ -f "${SERIAL_LOG}" ]; then
    tail -n 80 "${SERIAL_LOG}" >&2 || true
else
    echo "(no serial output captured)" >&2
fi
exit 1
