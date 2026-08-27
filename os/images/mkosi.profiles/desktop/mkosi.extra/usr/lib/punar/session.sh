#!/bin/sh
# Punar graphical session entry (started by greetd; milestone-1.md §4, §6).
#
# Graphics environment must be selected HERE, not in hyprland.conf:
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

# Installed by the image staging step.
# shellcheck disable=SC1091
. /usr/lib/punar/punar-graphics-env.sh
punar_configure_graphics

# Leave a session-scoped, privacy-safe proof for diagnostics and the VM gate.
# It contains only the selected mode and kernel DRM module names.
printf 'punar-session: graphics=%s drivers=%s\n' \
    "${PUNAR_GRAPHICS_MODE}" "${PUNAR_DRM_DRIVERS}" >&2
if [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -d "${XDG_RUNTIME_DIR}" ]; then
    umask 077
    printf 'mode=%s drivers=%s\n' \
        "${PUNAR_GRAPHICS_MODE}" "${PUNAR_DRM_DRIVERS}" \
        > "${XDG_RUNTIME_DIR}/punar-graphics-mode"
fi

# Documented fallback only, deliberately NOT set (milestone-1.md §6):
# AQ_NO_KMS_REQUIREMENT=1 — virtio-vga provides a connector, so not needed.

# Pin the system config explicitly (it is also on Hyprland's default search
# path at /etc/xdg/hypr, but a stray user config must not change the dev
# image's session semantics).
exec Hyprland --config /etc/xdg/hypr/hyprland.conf
