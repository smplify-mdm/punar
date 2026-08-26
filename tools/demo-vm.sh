#!/bin/bash
# Punar demo VM launcher (macOS host).
#
# Boots the CI-built punar-desktop image so a human can drive it. Not a test
# harness — tools/boot-test.sh is the gate; this exists to put the desktop on
# screen.
#
# Three things learned the hard way, all encoded below:
#  1. QEMU's cocoa display creates a window in a process with no Aqua session
#     when launched from a sandboxed agent — the window exists and is
#     invisible. VNC is used instead, always.
#  2. macOS Screen Sharing cannot talk to QEMU's VNC server (it demands
#     Apple's auth extensions). TigerVNC is the client that works.
#  3. EFI NVRAM persists the previous boot's variables; a stale entry drops the
#     machine into the UEFI shell instead of booting. The vars file is
#     recreated from the pristine template on EVERY launch.
set -euo pipefail

IMAGE="${1:?usage: punar-demo-vm.sh <path-to-punar-desktop-x86_64.qcow2>}"
[ -f "$IMAGE" ] || { echo "no such image: $IMAGE" >&2; exit 1; }

QEMU=/opt/homebrew/bin/qemu-system-x86_64
CODE=/opt/homebrew/share/qemu/edk2-x86_64-code.fd
VARS_TEMPLATE=/opt/homebrew/share/qemu/edk2-i386-vars.fd

RUN_DIR="$(dirname "$0")"
VARS="${RUN_DIR}/punar-vars.fd"
QMP=/tmp/punar-qmp.sock
VNC_PORT=5900

# (3) pristine NVRAM every launch
rm -f "$VARS"
cp "$VARS_TEMPLATE" "$VARS"
rm -f "$QMP"

echo "==> booting $(basename "$IMAGE")"
echo "    VNC  127.0.0.1:${VNC_PORT}   (display :0)"
echo "    QMP  ${QMP}"

# No KVM on macOS; HVF cannot run an x86_64 guest on Apple Silicon, so this is
# TCG emulation and it is SLOW — first boot to desktop takes minutes, not the
# 18 s the KVM CI path measures. That difference is the whole argument for the
# aarch64 image in the "Try Punar" plan.
exec "$QEMU" \
    -machine q35 \
    -m 4096 \
    -smp 4 \
    -drive "if=pflash,format=raw,readonly=on,file=${CODE}" \
    -drive "if=pflash,format=raw,file=${VARS}" \
    -drive "file=${IMAGE},format=qcow2,if=virtio" \
    -snapshot \
    -device virtio-vga \
    -device virtio-tablet \
    -device virtio-keyboard \
    -vnc "127.0.0.1:0" \
    -qmp "unix:${QMP},server,nowait" \
    -nic user,model=virtio-net-pci \
    -name "Punar"
