#!/usr/bin/env bash
# Runs INSIDE the punar image-builder container (see builder/Containerfile),
# invoked by tools/build-image.sh. Not intended to run on a host directly,
# though it only assumes: bash, mkosi, qemu-img, sha256sum, and that the
# os/images directory is the parent of this script's directory.
set -euo pipefail

IMAGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${IMAGES_DIR}"

# shellcheck source=/dev/null
. "${IMAGES_DIR}/snapshot.env"

MIRROR="https://archive.archlinux.org/repos/${PUNAR_SNAPSHOT_DATE}"
QCOW="out/punar-dev-x86_64.qcow2"

echo "==> mkosi build (mirror: ${MIRROR})"
mkosi --force --mirror "${MIRROR}" build

# mkosi names the disk output <ImageId>.raw; glob defensively in case a
# future mkosi appends version/architecture suffixes.
RAW="out/punar-dev.raw"
if [ ! -f "${RAW}" ]; then
    shopt -s nullglob
    for candidate in out/*.raw; do
        RAW="${candidate}"
        break
    done
    shopt -u nullglob
fi
if [ ! -f "${RAW}" ]; then
    echo "error: no .raw output from mkosi found in out/" >&2
    ls -la out/ >&2 || true
    exit 1
fi

echo "==> Converting ${RAW} -> ${QCOW} (compressed qcow2)"
qemu-img convert -O qcow2 -c "${RAW}" "${QCOW}"
rm -f "${RAW}"

echo "==> Writing build metadata"
{
    echo "image: punar-dev (minimal Arch payload, mkosi; ADR-001)"
    echo "snapshot: ${PUNAR_SNAPSHOT_DATE} (Arch Linux Archive date snapshot)"
    echo "mkosi: $(mkosi --version)"
    echo "qemu-img: $(qemu-img --version | head -n 1)"
    echo "git-sha: ${PUNAR_GIT_SHA:-unknown}"
    echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "note: unsigned Milestone 0 development image; VM-only (no linux-firmware)"
} > out/build-info.txt

(cd out && sha256sum "$(basename "${QCOW}")" > SHA256SUMS)

echo "==> Build complete"
ls -lh out/
