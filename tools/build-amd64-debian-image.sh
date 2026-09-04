#!/usr/bin/env bash
# Build the parallel Debian/amd64 substrate candidate. This never replaces the
# shipping Arch/x86_64 output; ADR-005 requires runtime parity before cutover.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${REPO_ROOT}/os/images/amd64-debian"
BUILDER_DIR="${REPO_ROOT}/os/images/builder-debian"

# shellcheck source=/dev/null
. "${TARGET_DIR}/snapshot.env"

PUNAR_BUILD_MODE="${PUNAR_BUILD_MODE:-build}"
case "${PUNAR_BUILD_MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${PUNAR_BUILD_MODE})" >&2; exit 2 ;;
esac

command -v docker >/dev/null 2>&1 \
    || { echo "error: docker is required" >&2; exit 1; }

BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-amd64"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
GIT_SHA="${GITHUB_SHA:-$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || echo unknown)}"

echo "==> Building pinned Debian/amd64 builder"
echo "    base:     ${PUNAR_DEBIAN_BUILDER_BASE}"
echo "    snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
docker build \
    --platform linux/amd64 \
    --build-arg "BASE_IMAGE=${PUNAR_DEBIAN_BUILDER_BASE}" \
    --build-arg "SNAPSHOT_ID=${PUNAR_DEBIAN_SNAPSHOT}" \
    --tag "${BUILDER_TAG}" \
    --file "${BUILDER_DIR}/Containerfile" \
    "${BUILDER_DIR}"

if [ "$(uname -m)" = x86_64 ]; then
    echo "==> Proving systemd-repart installer primitives (native x86_64)"
    docker run --rm --privileged \
        --platform linux/amd64 \
        --volume "${REPO_ROOT}:/work" \
        --workdir /work \
        "${BUILDER_TAG}" \
        ./tests/images/repart-spike.sh
else
    echo "warning: host is not x86_64; the canonical native CI lane owns runtime proof" >&2
fi

echo "==> Running Debian/amd64 mkosi (${PUNAR_BUILD_MODE})"
docker run --rm --privileged \
    --platform linux/amd64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work/os/images/amd64-debian \
    --env "PUNAR_BUILD_MODE=${PUNAR_BUILD_MODE}" \
    --env "PUNAR_GIT_SHA=${GIT_SHA}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" \
    /work/os/images/amd64-debian/container-build.sh
