#!/usr/bin/env bash
# Runs inside the native Debian builder container. The ARM64 lane stays
# independent from container-build.sh while the substrate migration is being
# proven; sharing code before the package/boot adapters converge would hide
# architecture-specific assumptions instead of removing them.
set -euo pipefail

ARM64_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$(cd "${ARM64_DIR}/.." && pwd)"
cd "${ARM64_DIR}"

# shellcheck source=/dev/null
. "${ARM64_DIR}/snapshot.env"

MODE="${PUNAR_BUILD_MODE:-build}"
case "${MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${MODE})" >&2; exit 2 ;;
esac

echo "==> mkosi ${MODE}: native arm64, Debian sid snapshot ${PUNAR_DEBIAN_SNAPSHOT}"
mkosi --force \
    --snapshot "${PUNAR_DEBIAN_SNAPSHOT}" \
    --source-date-epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
    "${MODE}"

if [ "${MODE}" = "summary" ]; then
    exit 0
fi

raw="${IMAGES_DIR}/out/punar-dev-arm64.raw"
if [ ! -f "${raw}" ]; then
    shopt -s nullglob
    candidates=("${IMAGES_DIR}"/out/punar-dev-arm64*.raw)
    shopt -u nullglob
    if [ "${#candidates[@]}" -eq 1 ]; then
        raw="${candidates[0]}"
    else
        echo "error: expected one punar-dev-arm64 raw disk, found ${#candidates[@]}" >&2
        ls -la "${IMAGES_DIR}/out" >&2 || true
        exit 1
    fi
fi

qcow="${IMAGES_DIR}/out/punar-dev-arm64.qcow2"
echo "==> Converting ${raw} -> ${qcow}"
qemu-img convert -O qcow2 -c "${raw}" "${qcow}"
rm -f "${raw}"
# mkosi's convenience symlink points at the raw disk we intentionally replace
# with the compressed qcow2. Do not leave a dangling artifact beside it.
rm -f "${IMAGES_DIR}/out/punar-dev-arm64"

{
    echo "image: punar-dev-arm64 (minimal native ARM64 migration lane)"
    echo "substrate: Debian sid"
    echo "snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
    echo "architecture: arm64"
    echo "mkosi: $(mkosi --version)"
    echo "qemu-img: $(qemu-img --version | head -n 1)"
    echo "git-sha: ${PUNAR_GIT_SHA:-unknown}"
    echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "scope: UEFI QEMU virt boot proof; not yet desktop, Pi, Secure Boot, or A/B"
} > "${IMAGES_DIR}/out/arm64-build-info.txt"

(
    cd "${IMAGES_DIR}/out"
    sha256sum punar-dev-arm64.qcow2 > SHA256SUMS.arm64
)

echo "==> Native ARM64 image complete"
ls -lh "${qcow}" "${IMAGES_DIR}/out/arm64-build-info.txt" \
    "${IMAGES_DIR}/out/SHA256SUMS.arm64"
