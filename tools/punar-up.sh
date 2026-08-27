#!/bin/bash
# One command: fetch the newest CI-built Punar desktop image and boot it.
#
#   ./tools/punar-up.sh              # newest successful run on main
#   ./tools/punar-up.sh <run-id>     # a specific run
#
# The image is ~2 GB, cached under ./image/ and re-downloaded only when the
# run id changes. Verifies SHA256SUMS before booting — the artifact travelled
# over the network and the manifest is right there.
set -euo pipefail

REPO=smplify-mdm/punar
HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE="${TMPDIR:-/tmp}/punar-demo-image"
mkdir -p "$CACHE"

RUN_ID="${1:-}"
if [ -z "$RUN_ID" ]; then
    echo "==> finding the newest run with a desktop image..."
    RUN_ID=$(gh run list --repo "$REPO" --branch main --limit 20 \
        --json databaseId,conclusion \
        --jq 'map(select(.conclusion=="success"))[0].databaseId')
    [ -n "$RUN_ID" ] && [ "$RUN_ID" != "null" ] || {
        echo "no fully-successful run found. Pass a run id explicitly:" >&2
        gh run list --repo "$REPO" --limit 8 >&2
        exit 1
    }
fi
echo "==> run ${RUN_ID}"

# A run id is an identity, not a quality signal. Refuse an explicit in-flight
# or failed run as firmly as the implicit path does; a local demo is a release
# checkpoint, not a way to look past a red gate.
RUN_STATE=$(gh run view "$RUN_ID" --repo "$REPO" --json status,conclusion \
    --jq '.status + " " + (.conclusion // "")')
if [ "$RUN_STATE" != "completed success" ]; then
    echo "run ${RUN_ID} is not a green milestone (${RUN_STATE}) — refusing to boot" >&2
    exit 1
fi

STAMP="${CACHE}/.run-id"
IMG="${CACHE}/punar-desktop-x86_64.qcow2"
if [ ! -f "$IMG" ] || [ "$(cat "$STAMP" 2>/dev/null || echo none)" != "$RUN_ID" ]; then
    echo "==> downloading punar-desktop-image (~2 GB)..."
    rm -rf "${CACHE:?}"/*
    gh run download "$RUN_ID" --repo "$REPO" -n punar-desktop-image -D "$CACHE"
    echo "$RUN_ID" > "$STAMP"
else
    echo "==> using cached image from run ${RUN_ID}"
fi

if [ -f "${CACHE}/SHA256SUMS" ]; then
    echo "==> verifying checksum"
    ( cd "$CACHE" && shasum -a 256 -c SHA256SUMS 2>/dev/null | grep -E "qcow2.*OK" ) \
        || { echo "CHECKSUM MISMATCH — refusing to boot" >&2; exit 1; }
fi

[ -f "${CACHE}/build-info.txt" ] && { echo "--- build-info ---"; cat "${CACHE}/build-info.txt"; echo "------------------"; }

echo "==> starting the VM (VNC 127.0.0.1:5900)"
"${HERE}/demo-vm.sh" "$IMG" &
QEMU_PID=$!
sleep 4
if kill -0 "$QEMU_PID" 2>/dev/null; then
    echo "==> opening TigerVNC"
    open -b com.tigervnc.tigervnc --args 127.0.0.1:5900 2>/dev/null \
        || echo "   (open TigerVNC manually and connect to 127.0.0.1:5900)"
else
    echo "QEMU exited immediately — see the output above" >&2
    exit 1
fi
echo
echo "The guest is emulated (TCG) on Apple Silicon, so first boot to the"
echo "desktop takes minutes rather than the 18 s the KVM CI path measures."
wait "$QEMU_PID"
