#!/bin/sh
# Development-only Punar Mail window probe.
#
# It sets no QML import path. Theme needs /usr/share/punar/shell on the import
# path, and exporting it here would cover only this launcher. The matching
# `//@ pragma Env` in Mail/shell.qml covers direct CI and developer launches as
# well. Graphics mode remains a machine property detected at launch.
set -eu

# shellcheck disable=SC1091
. /usr/lib/punar/punar-graphics-env.sh
punar_configure_graphics

PUNAR_MAIL_FIXTURES=1 exec qs -p /usr/share/punar/shell/Mail "$@"
