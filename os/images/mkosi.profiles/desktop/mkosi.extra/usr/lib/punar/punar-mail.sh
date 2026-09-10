#!/bin/sh
# Punar Mail launcher.
#
# IT DELIBERATELY SETS NO ENVIRONMENT. Theme needs /usr/share/punar/shell on the
# QML import path, and the obvious move — exporting it here, the way
# greeter-session.sh does — would have been wrong: this wrapper is not the only
# launch path. Every m*-check.sh in this repository drives a surface with a bare
# `qs -p /usr/share/punar/shell/...`, so a wrapper-only export leaves Theme
# unresolved in exactly the CI path meant to prove the surface works. The
# requirement is a `//@ pragma Env` line inside Mail/shell.qml instead, where it
# cannot be bypassed.
#
# What remains here is one thing a pragma cannot do: be an Exec= target that
# accepts a mailto: URI and passes it through.
set -eu

exec qs -p /usr/share/punar/shell/Mail "$@"
