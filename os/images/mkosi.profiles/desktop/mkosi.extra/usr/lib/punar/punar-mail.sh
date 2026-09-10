#!/bin/sh
# Punar Mail launcher.
#
# The greeter's pattern, verbatim: Mail/shell.qml is its own Quickshell
# configuration root, while Theme is a shared package module one directory
# above it. That package root has to be an explicit QML import path or the
# singleton's colour properties resolve to nothing in an independent engine —
# a failure the greeter already met and recorded in its own header.
#
# One process per invocation is deliberate for the spike. Whether Mail ends up
# with a separate sync daemon is a live design question
# (docs/design/mail-calendar-contacts.md), and a launcher that assumed the
# answer would be the wrong place to decide it.
set -eu

QML_IMPORT_PATH=/usr/share/punar/shell
export QML_IMPORT_PATH

exec qs -p /usr/share/punar/shell/Mail "$@"
