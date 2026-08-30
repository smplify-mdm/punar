#!/usr/bin/env bash
# Fetch exactly the official Raspberry Pi firmware tag/commit pinned by the
# image definition. The consumer still verifies critical files and complete
# module/board trees before producing an artifact; this helper establishes the
# repository identity and performs a sparse checkout only.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${PUNAR_RPI_PIN_FILE:-${REPO_ROOT}/os/images/raspberry-pi/firmware.env}"
OUTPUT="${1:-}"

die() {
    echo "error: $*" >&2
    exit 1
}

[ -n "${OUTPUT}" ] || die "usage: $0 OUTPUT_DIRECTORY"
command -v git >/dev/null 2>&1 || die "required command is missing: git"
[ -f "${PIN_FILE}" ] || die "firmware pin file is missing: ${PIN_FILE}"
# shellcheck source=/dev/null
. "${PIN_FILE}"
for variable in PUNAR_RPI_FIRMWARE_REPOSITORY PUNAR_RPI_FIRMWARE_TAG \
    PUNAR_RPI_FIRMWARE_COMMIT; do
    [ -n "${!variable:-}" ] || die "firmware pin is missing ${variable}"
done

OUTPUT_PARENT="$(cd "$(dirname "${OUTPUT}")" && pwd)"
OUTPUT="${OUTPUT_PARENT}/$(basename "${OUTPUT}")"
[ ! -e "${OUTPUT}" ] || die "refusing to overwrite firmware checkout: ${OUTPUT}"

success=false
cleanup() {
    if [ "${success}" != true ] && [ -d "${OUTPUT}" ]; then
        rm -rf "${OUTPUT}"
    fi
}
trap cleanup EXIT

git init --quiet "${OUTPUT}"
git -C "${OUTPUT}" remote add origin "${PUNAR_RPI_FIRMWARE_REPOSITORY}"
git -C "${OUTPUT}" sparse-checkout init --cone
git -C "${OUTPUT}" sparse-checkout set boot modules
git -C "${OUTPUT}" -c protocol.version=2 fetch --quiet --depth=1 \
    --filter=blob:none origin \
    "refs/tags/${PUNAR_RPI_FIRMWARE_TAG}:refs/tags/${PUNAR_RPI_FIRMWARE_TAG}"

tag_commit="$(git -C "${OUTPUT}" rev-parse \
    "refs/tags/${PUNAR_RPI_FIRMWARE_TAG}^{commit}")"
[ "${tag_commit}" = "${PUNAR_RPI_FIRMWARE_COMMIT}" ] \
    || die "official firmware tag no longer resolves to the pinned commit"
git -C "${OUTPUT}" checkout --quiet --detach "${PUNAR_RPI_FIRMWARE_COMMIT}"
[ "$(git -C "${OUTPUT}" rev-parse HEAD)" = "${PUNAR_RPI_FIRMWARE_COMMIT}" ] \
    || die "firmware checkout did not land on the pinned commit"
[ -z "$(git -C "${OUTPUT}" status --porcelain --untracked-files=no)" ] \
    || die "filesystem cannot represent the case-sensitive firmware tree without drift"
[ -d "${OUTPUT}/boot" ] && [ -d "${OUTPUT}/modules" ] \
    || die "firmware sparse checkout is incomplete"

success=true
echo "PUNAR_RPI_FIRMWARE_OK tag=${PUNAR_RPI_FIRMWARE_TAG} commit=${PUNAR_RPI_FIRMWARE_COMMIT}"
