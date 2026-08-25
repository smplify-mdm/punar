#!/bin/sh
# Punar graphical session entry (started by greetd; milestone-1.md §4, §6).
#
# VM graphics environment must be exported HERE, not in hyprland.conf:
# aquamarine reads these before Hyprland parses any config.
#
# This is the dev-image (QEMU virtio-vga, no virgl) rendering path:
# guest-side mesa software GL. Revisit for real hardware.

# Wayland session identity for portals/logind consumers.
XDG_SESSION_TYPE=wayland
export XDG_SESSION_TYPE

# Disable DRM buffer modifiers — the aquamarine flag the Hyprland wiki
# recommends for VMs/limited devices (milestone-1.md §6).
AQ_NO_MODIFIERS=1
export AQ_NO_MODIFIERS

# Force mesa's software rasterizer (llvmpipe) for EGL/GLES.
LIBGL_ALWAYS_SOFTWARE=1
export LIBGL_ALWAYS_SOFTWARE

# Documented fallback only, deliberately NOT set (milestone-1.md §6):
# AQ_NO_KMS_REQUIREMENT=1 — virtio-vga provides a connector, so not needed.

# Pin the system config explicitly (it is also on Hyprland's default search
# path at /etc/xdg/hypr, but a stray user config must not change the dev
# image's session semantics).
exec Hyprland --config /etc/xdg/hypr/hyprland.conf
