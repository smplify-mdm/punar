#!/bin/bash
# Capture the exact framebuffer of the running local Punar demo VM. Prefer the
# ARM launcher's localhost TCP QMP endpoint, then fall back to the x86 demo's
# Unix socket.
set -euo pipefail

QMP_SOCKET="${PUNAR_QMP_SOCKET:-/tmp/punar-qmp.sock}"
QMP_HOST="${PUNAR_QMP_HOST:-127.0.0.1}"
QMP_PORT="${PUNAR_QMP_PORT:-4445}"

qmp_request() {
    if nc -z "${QMP_HOST}" "${QMP_PORT}" >/dev/null 2>&1; then
        nc -w 2 "${QMP_HOST}" "${QMP_PORT}" 2>/dev/null
    elif [ -S "${QMP_SOCKET}" ]; then
        nc -U "${QMP_SOCKET}" 2>/dev/null
    else
        echo "no local Punar VM is running (checked ${QMP_SOCKET} and ${QMP_HOST}:${QMP_PORT})" >&2
        return 1
    fi
}

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [output.png]" >&2
    exit 1
fi

if [ "$#" -eq 1 ]; then
    OUTPUT=$1
else
    OUTPUT="${TMPDIR%/}/punar-local-$(date +%Y%m%d-%H%M%S).png"
fi

case "$OUTPUT" in
    *.png) ;;
    *)
        echo "output must end in .png: $OUTPUT" >&2
        exit 1
        ;;
esac

OUTPUT_DIR=$(dirname "$OUTPUT")
if [ ! -d "$OUTPUT_DIR" ]; then
    echo "output directory does not exist: $OUTPUT_DIR" >&2
    exit 1
fi
if [ -e "$OUTPUT" ]; then
    echo "refusing to overwrite: $OUTPUT" >&2
    exit 1
fi

# QEMU writes PPM; macOS ships the PNG converter. Keep the intermediate in a
# private, uniquely resolved directory so cleanup can never target user data.
CAPTURE_TMP=$(mktemp -d "${TMPDIR%/}/punar-frame.XXXXXX")
CAPTURE_PPM="${CAPTURE_TMP}/frame.ppm"
cleanup() {
    rm -f "$CAPTURE_PPM"
    rmdir "$CAPTURE_TMP" 2>/dev/null || true
}
trap cleanup EXIT

REQUEST=$(printf \
    '{"execute":"screendump","arguments":{"filename":"%s"}}' \
    "$CAPTURE_PPM")
REPLY=$(
    { printf '%s\n' '{"execute":"qmp_capabilities"}' "$REQUEST"; } \
        | qmp_request || true
)
if [[ "${REPLY}" == *'"error"'* ]]; then
    echo "QEMU refused the framebuffer capture" >&2
    echo "$REPLY" >&2
    exit 1
fi

i=0
while [ "$i" -lt 20 ] && [ ! -s "$CAPTURE_PPM" ]; do
    i=$((i + 1))
    sleep 0.1
done
if [ ! -s "$CAPTURE_PPM" ]; then
    echo "QEMU did not produce a framebuffer image" >&2
    exit 1
fi

sips -s format png "$CAPTURE_PPM" --out "$OUTPUT" >/dev/null
echo "$OUTPUT"
