#!/usr/bin/env bash
# Native ARM64 UEFI/QEMU smoke test.
#
# This proves firmware -> AA64 systemd-boot -> Debian arm64 kernel -> real
# root -> multi-user.target on QEMU's generic `virt` machine. It does not
# prove Raspberry Pi firmware, peripherals, Secure Boot, or the desktop.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-dev-arm64.qcow2}"
PROOF_DIR="${2:-${REPO_ROOT}/os/images/out/arm64-boot-proof}"

die() {
    echo "error: $*" >&2
    exit 1
}

warn() {
    echo "warning: $*" >&2
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::warning::$*"
    fi
}

[ -f "${IMAGE}" ] || die "image not found: ${IMAGE}"
command -v qemu-system-aarch64 >/dev/null 2>&1 \
    || die "qemu-system-aarch64 is required"

FIRMWARE=""
for candidate in \
    /usr/share/AAVMF/AAVMF_CODE.fd \
    /usr/share/AAVMF/AAVMF_CODE.ms.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd
do
    if [ -f "${candidate}" ]; then
        FIRMWARE="${candidate}"
        break
    fi
done
[ -n "${FIRMWARE}" ] || die "no supported AArch64 UEFI firmware found"

HOST_ARCH="$(uname -m)"
ACCEL="tcg"
MACHINE="virt,accel=tcg"
CPU="max"
if [ "$(uname -s)" = "Darwin" ] && [ "${HOST_ARCH}" = "arm64" ]; then
    ACCEL="hvf"
    MACHINE="virt,accel=hvf,highmem=off"
    CPU="host"
elif [ -r /dev/kvm ] && { [ "${HOST_ARCH}" = "aarch64" ] || [ "${HOST_ARCH}" = "arm64" ]; }; then
    ACCEL="kvm"
    MACHINE="virt,accel=kvm"
    CPU="host"
else
    warn "ARM64 KVM/HVF unavailable; boot proof is TCG-emulated"
fi

TIMEOUT="${PUNAR_ARM64_BOOT_TIMEOUT:-}"
if [ -z "${TIMEOUT}" ]; then
    if [ "${ACCEL}" = "tcg" ]; then
        TIMEOUT=900
    else
        TIMEOUT=180
    fi
fi

mkdir -p "${PROOF_DIR}"
LOG="${PROOF_DIR}/serial.log"
: > "${LOG}"

QEMU_PID=""
cleanup() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "==> ARM64 boot test (${ACCEL}; firmware ${FIRMWARE})"
qemu-system-aarch64 \
    -machine "${MACHINE}" \
    -cpu "${CPU}" \
    -m 2048 \
    -smp 4 \
    -bios "${FIRMWARE}" \
    -drive "file=${IMAGE},format=qcow2,if=none,id=punardisk" \
    -device virtio-blk-pci,drive=punardisk,romfile= \
    -snapshot \
    -nic none \
    -nographic \
    -no-reboot \
    > "${LOG}" 2>&1 &
QEMU_PID=$!

started="$(date +%s)"
while :; do
    if grep -q 'PUNAR_BOOT_OK' "${LOG}"; then
        elapsed="$(( $(date +%s) - started ))"
        marker="$(grep -m1 'PUNAR_BOOT_OK' "${LOG}" | tr -d '\r')"
        echo "ok: ${marker} (${elapsed}s, ${ACCEL})"
        grep -m1 'MemTotal:' "${LOG}" | tr -d '\r' || true
        grep -m1 'MemAvailable:' "${LOG}" | tr -d '\r' || true
        exit 0
    fi
    if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
        tail -120 "${LOG}" >&2
        die "QEMU exited before PUNAR_BOOT_OK"
    fi
    now="$(date +%s)"
    if [ "$((now - started))" -ge "${TIMEOUT}" ]; then
        tail -120 "${LOG}" >&2
        die "timed out after ${TIMEOUT}s waiting for PUNAR_BOOT_OK"
    fi
    sleep 1
done
