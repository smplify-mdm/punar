#!/bin/sh
# Ephemeral pre-login compositor. greetd supplies a PAM/logind session for the
# locked greeter account; this process and its one Quickshell child disappear
# before the human desktop starts.
set -eu

XDG_SESSION_TYPE=wayland
XDG_CURRENT_DESKTOP=Hyprland
XDG_SESSION_DESKTOP=Hyprland
export XDG_SESSION_TYPE XDG_CURRENT_DESKTOP XDG_SESSION_DESKTOP

# Greeter/shell.qml is a separate Quickshell configuration, while Theme is a
# shared package module one directory above it. Make that package root an
# explicit QML import path so singleton state and typed color bindings resolve
# exactly as they do in the normal desktop shell.
QML_IMPORT_PATH=/usr/share/punar/shell
export QML_IMPORT_PATH

case "${LANG:-}" in
    ''|C|POSIX) LANG=C.UTF-8 ;;
esac
export LANG

# Aquamarine reads these before Hyprland parses its config. A real GPU stays
# accelerated; QEMU/virtio without virgl uses the measured software fallback.
# shellcheck disable=SC1091
. /usr/lib/punar/punar-graphics-env.sh
punar_configure_graphics

if [ "${PUNAR_GRAPHICS_MODE}" = software ]; then
    PUNAR_REDUCED_MOTION=1
    export PUNAR_REDUCED_MOTION
fi

exec Hyprland --config /etc/xdg/hypr/punar-greeter.lua
