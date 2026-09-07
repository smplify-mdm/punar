#!/bin/bash
# Native ARM64 Punar desktop launcher for Apple Silicon and ARM64 Linux.
#
# By default the disk is attached in snapshot mode: interactive testing cannot
# mutate the reproducible build artifact. QMP and optional VNC remain
# localhost-only, and the explicit input-device IDs make QMP press/release
# automation deterministic. macOS defaults to a direct Cocoa window.
#
# SNAPSHOT MODE THROWS AWAY THE ACCOUNT YOU JUST CREATED. That is correct for a
# demo and actively misleading for testing anything about identity: onboarding
# runs again on the next boot, so a password set in one session is not the
# password of the account in the next, and a lock screen will correctly reject
# it. PUNAR_VM_PERSIST=1 keeps the writes instead, in a qcow2 overlay whose
# backing file is the build artifact — the artifact still cannot be mutated,
# and there is still nothing to clean up but one small file.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# The interactive launcher is a product demo, so its default must be the
# release image. `punar-desktop-arm64.qcow2` deliberately combines the
# desktop and dev profiles for boot-gate exercises; those exercises create
# synthetic agent history and must never be mistaken for user data.
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-release-arm64.qcow2}"
VNC_DISPLAY="${PUNAR_VNC_DISPLAY:-1}"
QMP_PORT="${PUNAR_QMP_PORT:-4445}"
VNC_PORT="$((5900 + VNC_DISPLAY))"
DISPLAY_BACKEND="${PUNAR_VM_DISPLAY:-auto}"
VNC_PASSWORD="${PUNAR_VNC_PASSWORD:-}"
OPEN_VIEWER="${PUNAR_VM_OPEN_VIEWER:-1}"

die() {
    echo "error: $*" >&2
    exit 1
}

[ -f "${IMAGE}" ] || die "no such image: ${IMAGE}"
case "$(basename "${IMAGE}")" in
    punar-desktop-arm64.qcow2)
        [ "${PUNAR_VM_ALLOW_CI_FIXTURES:-0}" = 1 ] || die \
            "punar-desktop-arm64.qcow2 is the CI exercise image and contains synthetic test activity; use punar-release-arm64.qcow2 (the default), or set PUNAR_VM_ALLOW_CI_FIXTURES=1 only when debugging the gates"
        echo "warning: CI exercise image selected; synthetic test activity will be visible" >&2
        ;;
esac
QEMU="$(command -v qemu-system-aarch64 || true)"
[ -n "${QEMU}" ] || die "qemu-system-aarch64 is required"

# Persistence is an overlay, never a mutation. The overlay is named after the
# digest of the image it backs, so rebuilding the image produces a NEW overlay
# rather than silently reinterpreting old writes against different blocks —
# which is corruption, and the quiet kind.
# Expanded below as ${DISK_ARGS[@]+"..."}: macOS ships bash 3.2, where a plain
# "${arr[@]}" on an EMPTY array is an unbound-variable error under `set -u`.
DISK_ARGS=(-snapshot)
BOOT_DISK="${IMAGE}"
PERSIST_NOTE="disk changes are disposable (-snapshot); onboarding runs again on every boot"
if [ "${PUNAR_VM_PERSIST:-0}" = 1 ]; then
    command -v qemu-img >/dev/null 2>&1 || die "PUNAR_VM_PERSIST=1 needs qemu-img"
    IMAGE_DIGEST="$(shasum -a 256 "${IMAGE}" 2>/dev/null | cut -c1-12)"
    [ -n "${IMAGE_DIGEST}" ] || IMAGE_DIGEST="$(sha256sum "${IMAGE}" | cut -c1-12)"
    BOOT_DISK="${IMAGE%.qcow2}.persist-${IMAGE_DIGEST}.qcow2"
    if [ ! -f "${BOOT_DISK}" ]; then
        qemu-img create -q -f qcow2 -F qcow2 -b "${IMAGE}" "${BOOT_DISK}" \
            || die "could not create the persistent overlay ${BOOT_DISK}"
        echo "==> created a persistent overlay: $(basename "${BOOT_DISK}")"
        echo "    delete that file to return to a factory-fresh machine"
    fi
    DISK_ARGS=()
    PERSIST_NOTE="disk changes PERSIST in $(basename "${BOOT_DISK}"); the build artifact is untouched"
fi

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
        if [ -n "${VNC_PASSWORD}" ]; then
            DISPLAY_ARGS=(-display "vnc=127.0.0.1:${VNC_DISPLAY},password=on")
        else
            DISPLAY_ARGS=(-display "vnc=127.0.0.1:${VNC_DISPLAY}")
        fi
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

NETWORK=(
    -netdev "user,id=punarnet"
    -device "virtio-net-pci,netdev=punarnet,romfile="
)
if [ "${PUNAR_VM_OFFLINE:-0}" = 1 ]; then
    NETWORK=(-nic none)
fi

echo "==> booting native ARM64 $(basename "${IMAGE}") (${ACCEL})"
echo "    display ${DISPLAY_LABEL}"
echo "    QMP  127.0.0.1:${QMP_PORT}"
echo "    ${PERSIST_NOTE}"
echo "    graphics are software-rendered in this VM; judge bare-metal GPU smoothness separately"

# QEMU starts with VNC authentication enabled but no usable password. Set it
# through the localhost-only QMP channel as soon as the monitor is ready,
# keeping the password out of argv. macOS Screen Sharing can complete the TCP
# handshake but does not reliably interoperate with QEMU's RFB security modes;
# TigerVNC is the supported macOS VNC client.
if [ "${DISPLAY_BACKEND}" = vnc ] && [ -n "${VNC_PASSWORD}" ]; then
    (
        attempt=0
        while [ "${attempt}" -lt 50 ]; do
            nc -z 127.0.0.1 "${QMP_PORT}" >/dev/null 2>&1 && break
            sleep 0.1
            attempt=$((attempt + 1))
        done
        {
            printf '%s\n' '{"execute":"qmp_capabilities"}'
            sleep 0.1
            printf '%s\n' "{\"execute\":\"change-vnc-password\",\"arguments\":{\"password\":\"${VNC_PASSWORD}\"}}"
        } | nc -w 2 127.0.0.1 "${QMP_PORT}" >/dev/null 2>&1 || true
    ) &
fi

if [ "${DISPLAY_BACKEND}" = vnc ] && [ "${HOST_OS}" = Darwin ] \
    && [ "${OPEN_VIEWER}" != 0 ]; then
    (
        attempt=0
        while [ "${attempt}" -lt 50 ]; do
            nc -z 127.0.0.1 "${VNC_PORT}" >/dev/null 2>&1 && break
            sleep 0.1
            attempt=$((attempt + 1))
        done
        if [ -d /Applications/TigerVNC.app ]; then
            open -b com.tigervnc.tigervnc --args "127.0.0.1:${VNC_PORT}" \
                >/dev/null 2>&1 || true
        else
            echo "warning: TigerVNC is required for QEMU VNC on macOS" >&2
            echo "warning: install it or use PUNAR_VM_DISPLAY=cocoa" >&2
        fi
    ) &
fi

exec "${QEMU}" \
    -name punar-arm64-milestone \
    -machine "virt,accel=${ACCEL},highmem=on" \
    -cpu "${CPU}" \
    -smp "${PUNAR_VM_CPUS:-4}" \
    -m "${PUNAR_VM_MEMORY_MB:-3072}" \
    -bios "${FIRMWARE}" \
    -drive "file=${BOOT_DISK},if=none,id=punardisk,format=qcow2,cache=unsafe,aio=threads" \
    -device virtio-blk-pci,drive=punardisk,romfile= \
    ${DISK_ARGS[@]+"${DISK_ARGS[@]}"} \
    -device virtio-gpu-pci,id=punar-gpu,romfile= \
    -device qemu-xhci,id=punar-xhci \
    -device usb-kbd,id=punar-kbd \
    -device usb-tablet,id=punar-pointer \
    "${DISPLAY_ARGS[@]}" \
    -qmp "tcp:127.0.0.1:${QMP_PORT},server=on,wait=off" \
    "${NETWORK[@]}" \
    -monitor none \
    -serial stdio
