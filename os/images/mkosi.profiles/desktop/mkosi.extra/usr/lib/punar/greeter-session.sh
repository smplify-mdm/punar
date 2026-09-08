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


# LEAVE THE TERMINAL BLACK BEHIND US. greetd hands VT1 from this compositor to
# the desktop's, and in the moment between them the bare virtual terminal is
# what is on screen — whatever text it last held, plus a cursor. Clearing it
# once here means that gap shows black rather than the tail of the boot log.
#
# Scrollback is cleared too (\033[3J), because a terminal that is merely
# scrolled to a blank page still has the boot log one keystroke away on a
# machine whose lock screen is meant to be a boundary.
#
# Guarded on every failure: greetd owns this VT and grants it to the session
# user, but a compositor that will not start because it could not write an
# escape sequence would be a far worse bug than the flicker this removes.
punar_clear_vt() {
    punar_vt="/dev/tty${XDG_VTNR:-1}"
    [ -w "${punar_vt}" ] || return 0
    printf '\033[H\033[2J\033[3J\033[?25l' > "${punar_vt}" 2>/dev/null || true
}
punar_clear_vt

exec Hyprland --config /etc/xdg/hypr/punar-greeter.lua
