#!/usr/bin/env bash
# Build the isolated Debian/amd64 substrate candidate inside the pinned Debian
# builder. The shipping Arch artifacts are neither read nor overwritten.
set -euo pipefail

TARGET_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGES_DIR="$(cd "${TARGET_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${IMAGES_DIR}/../.." && pwd)"
cd "${TARGET_DIR}"

# shellcheck source=/dev/null
. "${TARGET_DIR}/snapshot.env"

MODE="${PUNAR_BUILD_MODE:-build}"
case "${MODE}" in
    build|summary) ;;
    *) echo "error: PUNAR_BUILD_MODE must be build or summary (got: ${MODE})" >&2; exit 2 ;;
esac

MKOSI_REPART_DIR="$(mktemp -d /run/punar-mkosi-repart-amd64-debian.XXXXXX)"
MKOSI_RAW_OUTPUT_DIR="$(mktemp -d /var/tmp/punar-mkosi-output-amd64-debian.XXXXXX)"
BTRFS_DEVICE_UUID="ef4a2286-ac11-53c0-a40d-8d2bae7511cc"

cleanup_build() {
    rm -rf "${MKOSI_REPART_DIR}"
    local raw
    for raw in "${MKOSI_RAW_OUTPUT_DIR}"/*.raw; do
        [ -f "${raw}" ] || continue
        truncate --size 0 -- "${raw}" || true
        rm -f -- "${raw}"
    done
    rm -rf "${MKOSI_RAW_OUTPUT_DIR}"
}
trap cleanup_build EXIT

install -d "${IMAGES_DIR}/out"
"${REPO_ROOT}/tools/render-mkosi-repart.sh" \
    "${MKOSI_REPART_DIR}" "${IMAGES_DIR}/repart.d/install"

echo "==> mkosi ${MODE}: Debian/amd64 candidate, snapshot ${PUNAR_DEBIAN_SNAPSHOT}"
mkosi --force \
    --snapshot "${PUNAR_DEBIAN_SNAPSHOT}" \
    --source-date-epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
    --output-directory "${MKOSI_RAW_OUTPUT_DIR}" \
    --environment "SYSTEMD_REPART_MKFS_OPTIONS_BTRFS=--device-uuid=${BTRFS_DEVICE_UUID}" \
    --environment "PUNAR_IMAGE_ID=punar-desktop" \
    --environment "PUNAR_IMAGE_VERSION=${PUNAR_BASE_IMAGE_VERSION}" \
    --environment "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" \
    --repart-directory "${MKOSI_REPART_DIR}" \
    --profile dev \
    --image-id punar-dev-debian-x86_64 \
    --hostname punar-dev-debian-x86-64 \
    "${MODE}"

if [ "${MODE}" = summary ]; then
    echo "==> Debian/amd64 candidate summary complete"
    exit 0
fi

RAW="${MKOSI_RAW_OUTPUT_DIR}/punar-dev-debian-x86_64.raw"
QCOW="${IMAGES_DIR}/out/punar-dev-debian-x86_64.qcow2"
TMP_QCOW="${QCOW}.tmp"
[ -f "${RAW}" ] || { echo "error: expected ${RAW}" >&2; exit 1; }

echo "==> Verifying candidate A/B layout and shared-state mounts"
"${REPO_ROOT}/tests/images/check-repart-layout.sh" "${RAW}" x86_64
rm -f -- "${TMP_QCOW}"
qemu-img convert -O qcow2 -c "${RAW}" "${TMP_QCOW}"
mv -f -- "${TMP_QCOW}" "${QCOW}"
truncate --size 0 -- "${RAW}"
rm -f -- "${RAW}" "${MKOSI_RAW_OUTPUT_DIR}/punar-dev-debian-x86_64"

{
    echo "image: punar-dev-debian-x86_64"
    echo "substrate: Debian sid"
    echo "snapshot: ${PUNAR_DEBIAN_SNAPSHOT}"
    echo "architecture: x86_64"
    echo "status: migration candidate; shipping Arch baseline remains authoritative"
    echo "mkosi: $(mkosi --version)"
    echo "qemu-img: $(qemu-img --version | head -n 1)"
    echo "git-sha: ${PUNAR_GIT_SHA:-unknown}"
    echo "built-at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "${IMAGES_DIR}/out/debian-amd64-build-info.txt"
(
    cd "${IMAGES_DIR}/out"
    sha256sum -- punar-dev-debian-x86_64.qcow2 > SHA256SUMS.debian-amd64
)

HOST_UID="${PUNAR_HOST_UID:-0}"
HOST_GID="${PUNAR_HOST_GID:-0}"
[[ "${HOST_UID}" =~ ^[0-9]+$ ]] \
    || { echo "error: invalid PUNAR_HOST_UID: ${HOST_UID}" >&2; exit 2; }
[[ "${HOST_GID}" =~ ^[0-9]+$ ]] \
    || { echo "error: invalid PUNAR_HOST_GID: ${HOST_GID}" >&2; exit 2; }
install -d -m 0755 -o "${HOST_UID}" -g "${HOST_GID}" \
    "${IMAGES_DIR}/out/debian-amd64-boot-proof"
chown "${HOST_UID}:${HOST_GID}" \
    "${QCOW}" \
    "${IMAGES_DIR}/out/SHA256SUMS.debian-amd64" \
    "${IMAGES_DIR}/out/debian-amd64-build-info.txt"
chown -R "${HOST_UID}:${HOST_GID}" "${IMAGES_DIR}/cache/debian-amd64"

echo "==> Debian/amd64 candidate image build complete"
ls -lh "${QCOW}" "${IMAGES_DIR}/out/SHA256SUMS.debian-amd64"
