#!/bin/bash
# Gracefully stop the local disposable Punar demo VM through QEMU's monitor.
set -euo pipefail

QMP=/tmp/punar-qmp.sock

if [ ! -S "$QMP" ]; then
    echo "no local Punar VM is running"
    exit 0
fi

QEMU_PID=$(lsof -t "$QMP" 2>/dev/null | head -1 || true)
REPLY=$(
    { printf '%s\n' '{"execute":"qmp_capabilities"}' '{"execute":"quit"}'; } \
        | nc -U "$QMP" 2>/dev/null || true
)
case "$REPLY" in
    *'"return": {}'*) ;;
    *)
        echo "the Punar QEMU monitor did not accept a graceful stop" >&2
        exit 1
        ;;
esac

if [ -n "$QEMU_PID" ]; then
    i=0
    while [ "$i" -lt 20 ] && kill -0 "$QEMU_PID" 2>/dev/null; do
        i=$((i + 1))
        sleep 0.5
    done
    if kill -0 "$QEMU_PID" 2>/dev/null; then
        echo "Punar VM is still stopping (pid ${QEMU_PID})"
        exit 0
    fi
fi

echo "Punar VM stopped"
