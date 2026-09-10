#!/bin/sh
# Punar Mail launcher.
#
# IT SETS NO QML IMPORT PATH. Theme needs /usr/share/punar/shell on the import
# path, and exporting it here — the way greeter-session.sh does — would have
# been the obvious move and the wrong one: this wrapper is not the only launch
# path. Every m*-check.sh drives a surface with a bare `qs -p …`, so a
# wrapper-only export leaves Theme unresolved in exactly the CI path meant to
# prove the surface works. That requirement is a `//@ pragma Env` line inside
# Mail/shell.qml, where it cannot be bypassed.
#
# IT DOES ESTABLISH THE GRAPHICS ENVIRONMENT, and that asymmetry is deliberate
# rather than inconsistent. A pragma cannot do this one: the mode is DETECTED
# at launch from the DRM devices actually present, so it is a property of the
# machine rather than of the file. Without it, `qs` on a machine with no usable
# GPU dies with
#
#     libEGL warning: egl: failed to create dri2 screen
#
# and the window never maps. Chromium never hit this because the SHELL launches
# it and the shell is a child of Hyprland, which session.sh had already
# configured; an application started from a .desktop entry, a systemd unit, a
# terminal or a CI probe inherits nothing of the kind. Punar's own applications
# should not depend on who their parent happened to be.
#
# On a machine with a working GPU the helper detects hardware and sets nothing,
# so this costs a device with a real graphics stack precisely nothing.
set -eu

# shellcheck disable=SC1091
. /usr/lib/punar/punar-graphics-env.sh
punar_configure_graphics

exec qs -p /usr/share/punar/shell/Mail "$@"
