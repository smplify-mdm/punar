#!/bin/bash
# Native ARM64 Punar desktop launcher for Apple Silicon and ARM64 Linux.
#
# The disk is always attached in snapshot mode: interactive testing cannot
# mutate the reproducible build artifact. QMP and optional VNC remain
# localhost-only, and the explicit input-device IDs make QMP press/release
# automation deterministic. macOS defaults to a direct Cocoa window.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-desktop-arm64.qcow2}"
VNC_DISPLAY="${PUNAR_VNC_DISPLAY:-1}"
QMP_PORT="${PUNAR_QMP_PORT:-4445}"
VNC_PORT="$((5900 + VNC_DISPLAY))"
DISPLAY_BACKEND="${PUNAR_VM_DISPLAY:-auto}"

die() {
    echo "error: $*" >&2
    exit 1
}

[ -f "${IMAGE}" ] || die "no such image: ${IMAGE}"
QEMU="$(command -v qemu-system-aarch64 || true)"
[ -n "${QEMU}" ] || die "qemu-system-aarch64 is required"

FIRMWARE=""
for candidate in \
    /opt/homebrew/share/qemu/edk2-aarch64-code.fd \
    /usr/local/share/qemu/edk2-aarch64-code.fd \
    /usr/share/qemu-efi-aarch64/QEMU_EFI.fd \
    /usr/share/edk2/aarch64/QEMU_EFI.fd; do
    if [ -f "${candidate}" ]; then
        FIRMWARE="${candidate}"
        break
    fi
done
[ -n "${FIRMWARE}" ] || die "AArch64 UEFI firmware was not found"

if nc -z 127.0.0.1 "${QMP_PORT}" >/dev/null 2>&1; then
    die "QMP port ${QMP_PORT} is already in use"
fi

HOST_ARCH="$(uname -m)"
HOST_OS="$(uname -s)"
ACCEL=tcg
CPU=max
if [ "${HOST_OS}" = Darwin ] && [ "${HOST_ARCH}" = arm64 ]; then
    ACCEL=hvf
    CPU=host
elif [ -r /dev/kvm ] && { [ "${HOST_ARCH}" = arm64 ] || [ "${HOST_ARCH}" = aarch64 ]; }; then
    ACCEL=kvm
    CPU=host
fi

if [ "${DISPLAY_BACKEND}" = auto ]; then
    if [ "${HOST_OS}" = Darwin ]; then
        # Avoid a VNC encode/decode hop for the normal Apple-silicon demo.
        # This is still a software-rendered virtio framebuffer in the guest;
        # Cocoa only makes presenting it and forwarding input more direct.
        DISPLAY_BACKEND=cocoa
    else
        DISPLAY_BACKEND=vnc
    fi
fi
case "${DISPLAY_BACKEND}" in
    cocoa)
        [ "${HOST_OS}" = Darwin ] \
            || die "PUNAR_VM_DISPLAY=cocoa is only available on macOS"
        DISPLAY_ARGS=(-display "cocoa,show-cursor=on,zoom-to-fit=on")
        DISPLAY_LABEL="native Cocoa window"
        ;;
    vnc)
        DISPLAY_ARGS=(-display "vnc=127.0.0.1:${VNC_DISPLAY}")
        DISPLAY_LABEL="VNC 127.0.0.1:${VNC_PORT} (display :${VNC_DISPLAY})"
        ;;
    none)
        DISPLAY_ARGS=(-display none)
        DISPLAY_LABEL="headless"
        ;;
    *)
        die "invalid PUNAR_VM_DISPLAY '${DISPLAY_BACKEND}' (expected auto, cocoa, vnc, or none)"
        ;;
esac
if [ "${DISPLAY_BACKEND}" = vnc ] \
    && nc -z 127.0.0.1 "${VNC_PORT}" >/dev/null 2>&1; then
    die "VNC port ${VNC_PORT} is already in use"
fi

NETWORK=(-nic "user,model=virtio-net-pci")
if [ "${PUNAR_VM_OFFLINE:-0}" = 1 ]; then
    NETWORK=(-nic none)
fi

echo "==> booting native ARM64 $(basename "${IMAGE}") (${ACCEL})"
echo "    display ${DISPLAY_LABEL}"
echo "    QMP  127.0.0.1:${QMP_PORT}"
echo "    disk changes are disposable (-snapshot)"
echo "    graphics are software-rendered in this VM; judge bare-metal GPU smoothness separately"

exec "${QEMU}" \
    -name punar-arm64-milestone \
    -machine "virt,accel=${ACCEL},highmem=on" \
    -cpu "${CPU}" \
    -smp "${PUNAR_VM_CPUS:-4}" \
    -m "${PUNAR_VM_MEMORY_MB:-3072}" \
    -bios "${FIRMWARE}" \
    -drive "file=${IMAGE},if=virtio,format=qcow2,snapshot=on,cache=unsafe,aio=threads" \
    -device virtio-gpu-pci,id=punar-gpu \
    -device qemu-xhci,id=punar-xhci \
    -device usb-kbd,id=punar-kbd \
    -device usb-tablet,id=punar-pointer \
    "${DISPLAY_ARGS[@]}" \
    -qmp "tcp:127.0.0.1:${QMP_PORT},server=on,wait=off" \
    "${NETWORK[@]}" \
    -monitor none \
    -serial stdio
