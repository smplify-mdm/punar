#!/bin/sh
# Punar graphical session entry (started by greetd; milestone-1.md §4, §6).
#
# Graphics environment must be selected HERE, not in hyprland.lua:
# aquamarine reads it before Hyprland parses any config. The helper keeps the
# proven virtio-vga/no-virgl software path in VMs without disabling the GPU on
# bare metal.

# Wayland session identity for portals/logind consumers.
XDG_SESSION_TYPE=wayland
export XDG_SESSION_TYPE

# greetd does not consistently import /etc/locale.conf across distribution
# PAM stacks. Keep an explicitly configured user locale, but promote the
# ASCII-only C/POSIX fallback to UTF-8 so terminals, filenames and developer
# tools behave correctly from the first session.
case "${LANG:-}" in
    ''|C|POSIX) LANG=C.UTF-8 ;;
esac
export LANG

# Desktop entries generated for verified on-demand vendor applications live
# in a mutable, world-readable product directory rather than the signed root
# slot. Preserve both Flatpak export directories and any administrator-provided
# XDG data path so every supported install source appears in one live index.
punar_user_data="${XDG_DATA_HOME:-${HOME}/.local/share}"
XDG_DATA_DIRS="${punar_user_data}/flatpak/exports/share:/var/lib/flatpak/exports/share:/var/lib/punar-applications:${XDG_DATA_DIRS:-/usr/local/share:/usr/share}"
export XDG_DATA_DIRS

# Installed by the image staging step.
# shellcheck disable=SC1091
. /usr/lib/punar/punar-graphics-env.sh
punar_configure_graphics

# Leave a session-scoped, privacy-safe proof for diagnostics and the VM gate.
# It contains only the selected mode, kernel DRM module names, and Punar's
# fallback renderer policy (never user or device identifiers).
printf 'punar-session: graphics=%s drivers=%s qt_quick_backend=%s llvmpipe_threads=%s\n' \
    "${PUNAR_GRAPHICS_MODE}" "${PUNAR_DRM_DRIVERS}" \
    "${QT_QUICK_BACKEND:-default}" "${LP_NUM_THREADS:-default}" >&2
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR}" ]; then
    umask 077
    printf 'mode=%s drivers=%s qt_quick_backend=%s llvmpipe_threads=%s\n' \
        "${PUNAR_GRAPHICS_MODE}" "${PUNAR_DRM_DRIVERS}" \
        "${QT_QUICK_BACKEND:-default}" "${LP_NUM_THREADS:-default}" \
        > "${XDG_RUNTIME_DIR}/punar-graphics-mode"
fi

# Documented fallback only, deliberately NOT set (milestone-1.md §6):
# AQ_NO_KMS_REQUIREMENT=1 — virtio-vga provides a connector, so not needed.

# QEMU's Cocoa and VNC display backends expose an unaccelerated virtio GPU.
# The CPU is hardware-virtualized on Apple Silicon, but every animated frame
# is still rasterized by llvmpipe and copied to the host. Keep the product's
# short spatial motion on real GPUs; on the proven software path, layer a
# tiny Lua runtime config over the same system config and disable compositor
# animation. This changes no bare-metal behavior and makes local VM input
# feel immediate instead of queueing frames behind a 300 ms transition. The
# helper returns the product config unchanged on real GPUs.
punar_select_hyprland_config

exec Hyprland --config "${PUNAR_HYPRLAND_CONFIG}"
