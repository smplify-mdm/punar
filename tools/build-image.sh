#!/usr/bin/env bash
# Build the Punar VM images (qcow2) via the containerized mkosi toolchain.
#
# Images (milestone-1.md §3):
#   punar-dev      — minimal CI image (profile "dev").
#   punar-desktop  — graphical CI/demo image (profiles "desktop,dev").
#   punar-release  — production-safe graphical image (profile "desktop").
#
# Usage:
#   tools/build-image.sh [dev|desktop|release|all]     (default: all)
# or set PUNAR_IMAGES=dev|desktop|release|all. `all` retains the CI pair and
# does not implicitly add the release artifact. Set PUNAR_BUILD_MODE=summary for the
# cheap config-validation path (staging + `mkosi summary`, no image build).
#
# Canonical execution environment: x86_64 CI runners (.github/workflows/ci.yml,
# job "image"). On the maintainer's arm64 Mac this same path runs under Docker
# Desktop's linux/amd64 emulation — it works but is slow (tens of minutes) and
# non-authoritative; per spec 1.22, treat local emulated results as such.
# See docs/development/image-pipeline.md.
#
# Requirements: docker with a running daemon. Network access to
# archive.archlinux.org. The build container runs --privileged (mkosi
# sandboxing + pacman inside a container need it). The whole repo root is
# mounted into the container: the desktop profile stages Hyprland/foot/font
# configs from os/modules/desktop and the shell from shell/ at build time.
#
# Output: os/images/out/punar-{dev,desktop,release}-x86_64.qcow2 as selected
#         (+ SHA256SUMS and build-info.txt in build mode)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES_DIR="${REPO_ROOT}/os/images"

PUNAR_IMAGES="${1:-${PUNAR_IMAGES:-all}}"
PUNAR_BUILD_MODE="${PUNAR_BUILD_MODE:-build}"

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

if [ "${HOST_ARCH}" = "x86_64" ]; then
    echo "==> Proving systemd-repart installer primitives (native x86_64)"
    docker run --rm --privileged \
        --platform linux/amd64 \
        --volume "${REPO_ROOT}:/work" \
        --workdir /work \
        "${BUILDER_TAG}" \
        ./tests/images/repart-spike.sh
else
    echo "warning: skipping x86_64 V-REPART under emulation; native x86_64 CI is authoritative" >&2
fi

echo "==> Running containerized mkosi (images: ${PUNAR_IMAGES}, mode: ${PUNAR_BUILD_MODE})"
docker run --rm --privileged \
    --platform linux/amd64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work/os/images \
    --env "PUNAR_GIT_SHA=${GIT_SHA}" \
    --env "PUNAR_IMAGES=${PUNAR_IMAGES}" \
    --env "PUNAR_BUILD_MODE=${PUNAR_BUILD_MODE}" \
    "${BUILDER_TAG}" \
    /work/os/images/scripts/container-build.sh

if [ "${PUNAR_BUILD_MODE}" = "build" ]; then
    echo "==> Done. Output in ${IMAGES_DIR}/out:"
    ls -lh "${IMAGES_DIR}/out"
fi
