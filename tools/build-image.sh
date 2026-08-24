#!/usr/bin/env bash
# Build the punar-dev VM image (qcow2) via the containerized mkosi toolchain.
#
# Canonical execution environment: x86_64 CI runners (.github/workflows/ci.yml,
# job "image"). On the maintainer's arm64 Mac this same path runs under Docker
# Desktop's linux/amd64 emulation — it works but is slow (tens of minutes) and
# non-authoritative; per spec 1.22, treat local emulated results as such.
# See docs/development/image-pipeline.md.
#
# Requirements: docker with a running daemon. Network access to
# archive.archlinux.org. The build container runs --privileged (mkosi
# sandboxing + pacman inside a container need it).
#
# Output: os/images/out/punar-dev-x86_64.qcow2 (+ SHA256SUMS, build-info.txt)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES_DIR="${REPO_ROOT}/os/images"

# shellcheck source=/dev/null
. "${IMAGES_DIR}/snapshot.env"

BUILDER_TAG="punar-image-builder:${PUNAR_SNAPSHOT_DATE//\//-}"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required (Docker Desktop on macOS, docker-ce on Linux)" >&2
    exit 1
fi

HOST_ARCH="$(uname -m)"
if [ "${HOST_ARCH}" != "x86_64" ]; then
    echo "warning: host architecture is ${HOST_ARCH}; building via --platform linux/amd64 emulation" >&2
    echo "warning: expect a slow build; CI (x86_64) is the canonical build environment" >&2
fi

GIT_SHA="${GITHUB_SHA:-$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)}"

echo "==> Building builder container image: ${BUILDER_TAG}"
echo "    base:     ${PUNAR_BUILDER_BASE}"
echo "    snapshot: ${PUNAR_SNAPSHOT_DATE}"
docker build \
    --platform linux/amd64 \
    --build-arg "BASE_IMAGE=${PUNAR_BUILDER_BASE}" \
    --build-arg "SNAPSHOT_DATE=${PUNAR_SNAPSHOT_DATE}" \
    --tag "${BUILDER_TAG}" \
    --file "${IMAGES_DIR}/builder/Containerfile" \
    "${IMAGES_DIR}/builder"

echo "==> Building punar-dev image (mkosi)"
docker run --rm --privileged \
    --platform linux/amd64 \
    --volume "${IMAGES_DIR}:/work" \
    --workdir /work \
    --env "PUNAR_GIT_SHA=${GIT_SHA}" \
    "${BUILDER_TAG}" \
    /work/scripts/container-build.sh

echo "==> Done. Output in ${IMAGES_DIR}/out:"
ls -lh "${IMAGES_DIR}/out"
