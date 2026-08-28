#!/usr/bin/env bash
# Verify a signed local release fixture, write it to inactive slot B of a
# disposable raw image, re-read every written byte, and arm systemd-boot's
# native boot counter. This is a CI/proof harness, not the privileged daemon
# update endpoint.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE_IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-release-arm64.qcow2}"
RELEASE_DIR="${2:-${REPO_ROOT}/os/images/out/repository/releases/2026.08.28.3}"
OUTPUT_IMAGE="${3:-${REPO_ROOT}/os/images/out/punar-update-proof-arm64.raw}"
SLOT_B_UUID="2b1b91a9-cf2c-4e9c-a723-5ec997971662"
SLOT_B_FS_UUID="724e1a3b-d966-54b7-9a97-8886985eee18"
BUILDER_TAG="punar-debian-builder:20260820T000000Z-arm64"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

die() {
    echo "error: $*" >&2
    exit 1
}

for command in docker jq qemu-img shasum; do
    command -v "${command}" >/dev/null 2>&1 || die "required command is missing: ${command}"
done

SOURCE_IMAGE="$(cd "$(dirname "${SOURCE_IMAGE}")" && pwd)/$(basename "${SOURCE_IMAGE}")"
RELEASE_DIR="$(cd "${RELEASE_DIR}" && pwd)"
OUTPUT_IMAGE="$(cd "$(dirname "${OUTPUT_IMAGE}")" && pwd)/$(basename "${OUTPUT_IMAGE}")"
case "${SOURCE_IMAGE}" in "${REPO_ROOT}"/*) ;; *) die "source image must be inside the repository" ;; esac
case "${RELEASE_DIR}" in "${REPO_ROOT}"/*) ;; *) die "release directory must be inside the repository" ;; esac
case "${OUTPUT_IMAGE}" in "${REPO_ROOT}"/*) ;; *) die "output image must be inside the repository" ;; esac
[ -f "${SOURCE_IMAGE}" ] || die "source image not found: ${SOURCE_IMAGE}"
[ -f "${RELEASE_DIR}/release.json" ] || die "release.json is missing"
[ -f "${RELEASE_DIR}/release.json.sig" ] || die "release.json.sig is missing"
[ ! -e "${OUTPUT_IMAGE}" ] || die "refusing to overwrite existing output: ${OUTPUT_IMAGE}"
[ "${OUTPUT_IMAGE}" != "${SOURCE_IMAGE}" ] || die "output must not be the source image"
docker image inspect "${BUILDER_TAG}" >/dev/null 2>&1 || die "ARM64 builder image is missing"

REPOSITORY_ROOT="$(cd "${RELEASE_DIR}/../.." && pwd)"
KEY_DIR="${REPOSITORY_ROOT}/keys"
[ -d "${KEY_DIR}" ] || die "release key directory is missing"

container_path() {
    printf '/work/%s' "${1#"${REPO_ROOT}"/}"
}

echo "==> Verifying the detached manifest signature before trusting its JSON"
docker run --rm --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    /work/target/debug/punar-release-tool verify-release \
    "$(container_path "${KEY_DIR}")" \
    "$(container_path "${RELEASE_DIR}/release.json")" \
    "$(container_path "${RELEASE_DIR}/release.json.sig")"

VERSION="$(jq -er '.version' "${RELEASE_DIR}/release.json")"
ARCHITECTURE="$(jq -er '.architecture' "${RELEASE_DIR}/release.json")"
BOOT_PLATFORM="$(jq -er '.boot_platform' "${RELEASE_DIR}/release.json")"
PAYLOAD_NAME="$(jq -er '.payload.filename' "${RELEASE_DIR}/release.json")"
PAYLOAD_DIGEST="$(jq -er '.payload.digest_sha256' "${RELEASE_DIR}/release.json")"
PAYLOAD_SIZE="$(jq -er '.payload.size_bytes' "${RELEASE_DIR}/release.json")"
UNCOMPRESSED_SIZE="$(jq -er '.payload.uncompressed_size_bytes' "${RELEASE_DIR}/release.json")"
UKI_NAME="$(jq -er '.boot_artifact.filename' "${RELEASE_DIR}/release.json")"
UKI_DIGEST="$(jq -er '.boot_artifact.digest_sha256' "${RELEASE_DIR}/release.json")"
UKI_SIZE="$(jq -er '.boot_artifact.size_bytes' "${RELEASE_DIR}/release.json")"

[ "${ARCHITECTURE}" = aarch64 ] || die "this proof currently requires an aarch64 release"
[ "${BOOT_PLATFORM}" = uefi ] || die "this proof currently requires a UEFI release"
[[ "${VERSION}" =~ ^[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.[0-9]+$ ]] \
    || die "manifest version is not canonical"
for filename in "${PAYLOAD_NAME}" "${UKI_NAME}"; do
    [ "${filename}" = "$(basename "${filename}")" ] || die "artifact filename is not a basename"
done
PAYLOAD="${RELEASE_DIR}/${PAYLOAD_NAME}"
UKI="${RELEASE_DIR}/${UKI_NAME}"
[ -f "${PAYLOAD}" ] || die "payload is missing"
[ -f "${UKI}" ] || die "UKI is missing"

verify_host_artifact() {
    local path="$1"
    local expected_digest="$2"
    local expected_size="$3"
    local actual_digest actual_size
    actual_digest="$(shasum -a 256 "${path}" | awk '{print $1}')"
    actual_size="$(wc -c < "${path}" | tr -d ' ')"
    [ "${actual_digest}" = "${expected_digest}" ] || die "artifact digest mismatch: $(basename "${path}")"
    [ "${actual_size}" = "${expected_size}" ] || die "artifact size mismatch: $(basename "${path}")"
}

echo "==> Verifying the signed payload and UKI digests"
verify_host_artifact "${PAYLOAD}" "${PAYLOAD_DIGEST}" "${PAYLOAD_SIZE}"
verify_host_artifact "${UKI}" "${UKI_DIGEST}" "${UKI_SIZE}"

cleanup_failed_output() {
    if [ "$?" -ne 0 ] && [ -f "${OUTPUT_IMAGE}" ]; then
        unlink "${OUTPUT_IMAGE}"
    fi
}
trap cleanup_failed_output EXIT

echo "==> Creating a disposable sparse raw image; the source qcow2 remains unchanged"
qemu-img convert -O raw -S 4k "${SOURCE_IMAGE}" "${OUTPUT_IMAGE}"

REPORT_DIR="${REPO_ROOT}/artifacts/update-proof"
mkdir -p "${REPORT_DIR}"
REPORT="${REPORT_DIR}/arm64-${VERSION}.txt"

echo "==> Writing inactive slot B, detaching, reopening, and re-hashing all bytes"
docker run --rm --privileged --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" --workdir /work \
    --env "PUNAR_IMAGE=$(container_path "${OUTPUT_IMAGE}")" \
    --env "PUNAR_PAYLOAD=$(container_path "${PAYLOAD}")" \
    --env "PUNAR_UKI=$(container_path "${UKI}")" \
    --env "PUNAR_VERSION=${VERSION}" \
    --env "PUNAR_UNCOMPRESSED_SIZE=${UNCOMPRESSED_SIZE}" \
    --env "PUNAR_SLOT_B_UUID=${SLOT_B_UUID}" \
    --env "PUNAR_SLOT_B_FS_UUID=${SLOT_B_FS_UUID}" \
    --env "PUNAR_REPORT=$(container_path "${REPORT}")" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" bash -ceu '
        for command in sfdisk losetup zstd sha256sum dd mount umount mountpoint \
            blkid e2fsck objcopy grep find sync install awk cmp mknod; do
            command -v "${command}" >/dev/null 2>&1 \
                || { echo "error: required container command is missing: ${command}" >&2; exit 1; }
        done
        for loop_minor in {0..31}; do
            [ -b "/dev/loop${loop_minor}" ] \
                || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
        done
        [ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237

        work="$(mktemp -d /run/punar-update-proof.XXXXXX)"
        root_loop=""
        esp_loop=""
        cleanup() {
            mountpoint -q "${work}/root" && umount "${work}/root" || true
            mountpoint -q "${work}/esp" && umount "${work}/esp" || true
            [ -z "${root_loop}" ] || losetup --detach "${root_loop}" || true
            [ -z "${esp_loop}" ] || losetup --detach "${esp_loop}" || true
            rm -rf "${work}"
        }
        trap cleanup EXIT
        mkdir -p "${work}/root" "${work}/esp"

        sfdisk --json "${PUNAR_IMAGE}" > "${work}/table.json"
        read -r esp_start esp_size root_start root_size < <(
            python3 - "${work}/table.json" <<"PY"
import json
import sys

parts = json.load(open(sys.argv[1], encoding="utf-8"))["partitiontable"]["partitions"]
if len(parts) != 4 or parts[0].get("name") != "PUNAR-ESP" or parts[2].get("name") != "PUNAR-ROOT-B":
    raise SystemExit("unexpected partition layout")
print(parts[0]["start"], parts[0]["size"], parts[2]["start"], parts[2]["size"])
PY
        )
        slot_bytes="$((root_size * 512))"
        [ "${slot_bytes}" = "${PUNAR_UNCOMPRESSED_SIZE}" ] \
            || { echo "error: payload does not exactly fill slot B" >&2; exit 1; }

        expected_raw_digest="$(zstd -dc "${PUNAR_PAYLOAD}" | sha256sum | awk "{print \$1}")"
        root_loop="$(losetup --find --show \
            --offset "$((root_start * 512))" --sizelimit "${slot_bytes}" "${PUNAR_IMAGE}")"
        zstd -dc "${PUNAR_PAYLOAD}" \
            | dd of="${root_loop}" bs=4M iflag=fullblock oflag=direct conv=fsync status=none
        losetup --detach "${root_loop}"
        root_loop=""
        sync

        root_loop="$(losetup --find --show --read-only \
            --offset "$((root_start * 512))" --sizelimit "${slot_bytes}" "${PUNAR_IMAGE}")"
        readback_digest="$(dd if="${root_loop}" bs=4M iflag=fullblock,direct count="$((slot_bytes / 4194304))" status=none \
            | sha256sum | awk "{print \$1}")"
        [ "${readback_digest}" = "${expected_raw_digest}" ] \
            || { echo "error: slot B post-write digest mismatch" >&2; exit 1; }
        e2fsck -fn "${root_loop}"
        [ "$(blkid -p -s UUID -o value "${root_loop}")" = "${PUNAR_SLOT_B_FS_UUID}" ] \
            || { echo "error: slot B has the wrong filesystem UUID" >&2; exit 1; }
        [ "$(blkid -p -s LABEL -o value "${root_loop}")" = PUNAR-ROOT-B ] \
            || { echo "error: slot B has the wrong filesystem label" >&2; exit 1; }
        mount -o ro "${root_loop}" "${work}/root"
        grep -Fqi "UUID=${PUNAR_SLOT_B_FS_UUID} / ext4" "${work}/root/etc/fstab" \
            || { echo "error: slot B fstab still names slot A" >&2; exit 1; }
        [ -f "${work}/root/etc/os-release" ]
        umount "${work}/root"
        losetup --detach "${root_loop}"
        root_loop=""

        esp_loop="$(losetup --find --show \
            --offset "$((esp_start * 512))" --sizelimit "$((esp_size * 512))" "${PUNAR_IMAGE}")"
        mount "${esp_loop}" "${work}/esp"
        old_uki="$(find "${work}/esp/EFI/Linux" -maxdepth 1 -type f -name "*.efi" -print -quit)"
        [ -n "${old_uki}" ] || { echo "error: no last-known-good UKI exists" >&2; exit 1; }
        new_name="punar_${PUNAR_VERSION}+3-0.efi"
        default_selector="punar_${PUNAR_VERSION}*.efi"
        install -m 0644 "${PUNAR_UKI}" "${work}/esp/EFI/Linux/${new_name}.new"
        sync -f "${work}/esp/EFI/Linux/${new_name}.new"
        mv "${work}/esp/EFI/Linux/${new_name}.new" "${work}/esp/EFI/Linux/${new_name}"
        # The default is a glob by design. The Boot Loader Specification
        # stores retry state in the filename, and systemd-bless-boot removes
        # that suffix after success. A selector naming +3-0 exactly would be
        # stale after either the first decrement or the final blessing.
        printf "default %s\ntimeout 0\n" "${default_selector}" > "${work}/esp/loader/loader.conf.new"
        sync -f "${work}/esp/loader/loader.conf.new"
        mv "${work}/esp/loader/loader.conf.new" "${work}/esp/loader/loader.conf"
        sync -f "${work}/esp"

        [ "$(find "${work}/esp/EFI/Linux" -maxdepth 1 -type f -name "*.efi" | wc -l | tr -d " ")" -eq 2 ]
        [ -f "${old_uki}" ]
        [ "$(sha256sum "${work}/esp/EFI/Linux/${new_name}" | awk "{print \$1}")" \
            = "$(sha256sum "${PUNAR_UKI}" | awk "{print \$1}")" ]
        grep -Fxq "default ${default_selector}" "${work}/esp/loader/loader.conf"
        objcopy --only-section=.cmdline --output-target=binary \
            "${work}/esp/EFI/Linux/${new_name}" "${work}/cmdline"
        tr -d "\000" < "${work}/cmdline" | grep -Fqi "root=PARTUUID=${PUNAR_SLOT_B_UUID}"

        {
            printf "PUNAR_UPDATE_APPLY_OK\n"
            printf "version=%s\n" "${PUNAR_VERSION}"
            printf "target_slot=B\n"
            printf "slot_bytes=%s\n" "${slot_bytes}"
            printf "slot_readback_sha256=%s\n" "${readback_digest}"
            printf "last_known_good_uki=%s\n" "$(basename "${old_uki}")"
            printf "pending_uki=%s\n" "${new_name}"
            printf "default_selector=%s\n" "${default_selector}"
            printf "boot_tries_left=3\n"
            printf "boot_tries_done=0\n"
        } > "${PUNAR_REPORT}"
        chown "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" "${PUNAR_REPORT}"
    '

trap - EXIT
echo "PUNAR_UPDATE_APPLY_OK version=${VERSION} target_slot=B boot_tries=3"
echo "    scratch image: ${OUTPUT_IMAGE}"
echo "    proof report:  ${REPORT}"
