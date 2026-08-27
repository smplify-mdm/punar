#!/usr/bin/env bash
# Build the native ARM64 migration image with the digest- and snapshot-pinned
# Debian toolchain. This path is intentionally separate from build-image.sh
# until the x86_64 regression baseline also crosses to Debian and both
# architectures use one package/boot abstraction.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARM64_DIR="${REPO_ROOT}/os/images/arm64"
BUILDER_DIR="${REPO_ROOT}/os/images/builder-debian"

# shellcheck source=/dev/null
. "${ARM64_DIR}/snapshot.env"

PUNAR_BUILD_MODE="${PUNAR_BUILD_MODE:-build}"
PUNAR_ARM64_IMAGES="${PUNAR_ARM64_IMAGES:-minimal}"
BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"

if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker is required" >&2
    exit 1
fi

case "$(uname -m)" in
    arm64|aarch64) ;;
    *)
        echo "warning: this host is not ARM64; Docker will emulate the native builder" >&2
        echo "warning: an ARM64 runner or Apple Silicon Mac is the authoritative fast path" >&2
        ;;
esac

case "${PUNAR_BUILD_MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${PUNAR_BUILD_MODE})" >&2; exit 2 ;;
esac
case "${PUNAR_ARM64_IMAGES}" in
    minimal|desktop|all) ;;
    *) echo "error: PUNAR_ARM64_IMAGES must be minimal, desktop, or all (got: ${PUNAR_ARM64_IMAGES})" >&2; exit 2 ;;
esac

GIT_SHA="${GITHUB_SHA:-$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)}"

echo "==> Building native ARM64 Debian builder"
echo "    base:     ${PUNAR_DEBIAN_BUILDER_BASE}"
echo "    snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
docker build \
    --platform linux/arm64 \
    --build-arg "BASE_IMAGE=${PUNAR_DEBIAN_BUILDER_BASE}" \
    --build-arg "SNAPSHOT_ID=${PUNAR_DEBIAN_SNAPSHOT}" \
    --tag "${BUILDER_TAG}" \
    --file "${BUILDER_DIR}/Containerfile" \
    "${BUILDER_DIR}"

echo "==> Running native ARM64 mkosi (${PUNAR_BUILD_MODE})"
docker run --rm --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work/os/images/arm64 \
    --env "PUNAR_BUILD_MODE=${PUNAR_BUILD_MODE}" \
    --env "PUNAR_ARM64_IMAGES=${PUNAR_ARM64_IMAGES}" \
    --env "PUNAR_GIT_SHA=${GIT_SHA}" \
    "${BUILDER_TAG}" \
    /work/os/images/arm64/container-build.sh
