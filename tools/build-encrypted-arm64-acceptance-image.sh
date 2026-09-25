#!/usr/bin/env bash
# Derive a local, encrypted ARM64 acceptance disk from one clean release image.
#
# This is intentionally not a release artifact or a substitute for the Punar
# installer. It preserves the release image's populated PUNAR-DATA subvolumes,
# wraps that partition in LUKS2 with a freshly generated local key, updates the
# populated A slot to mount the mapper, and leaves the source image untouched.
# Slot B is deliberately unformatted in a clean Punar image; a future verified
# update writes that slot as one complete artifact rather than mutating it here.
# The result exists only so credential-bearing desktop flows can be exercised
# in a VM under the same encrypted-storage invariant as an installed machine.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARM64_DIR="${REPO_ROOT}/os/images/arm64"
OUT_DIR="${REPO_ROOT}/os/images/out"

# shellcheck source=/dev/null
. "${ARM64_DIR}/snapshot.env"

SOURCE_IMAGE="${1:-${OUT_DIR}/punar-release-arm64.qcow2}"
OUTPUT_IMAGE="${2:-${OUT_DIR}/punar-mail-acceptance-arm64.qcow2}"
KEY_FILE="${OUTPUT_IMAGE%.qcow2}.luks-key"
MANIFEST="${OUTPUT_IMAGE%.qcow2}.json"
BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
BUILD_COMPLETE=0

die() {
    echo "error: $*" >&2
    exit 1
}

container_path() {
    local path="$1"
    case "${path}" in
        "${REPO_ROOT}"/*) printf '/work/%s\n' "${path#"${REPO_ROOT}"/}" ;;
        *) die "path must stay inside ${REPO_ROOT}: ${path}" ;;
    esac
}

[ "$#" -le 2 ] || die "usage: $0 [SOURCE_QCOW2] [OUTPUT_QCOW2]"
command -v docker >/dev/null 2>&1 || die "docker is required"
command -v openssl >/dev/null 2>&1 || die "openssl is required"
command -v shasum >/dev/null 2>&1 || command -v sha256sum >/dev/null 2>&1 \
    || die "a SHA-256 utility is required"

mkdir -p "${OUT_DIR}"
SOURCE_IMAGE="$(cd "$(dirname "${SOURCE_IMAGE}")" && pwd)/$(basename "${SOURCE_IMAGE}")"
OUTPUT_IMAGE="$(cd "$(dirname "${OUTPUT_IMAGE}")" && pwd)/$(basename "${OUTPUT_IMAGE}")"
KEY_FILE="${OUTPUT_IMAGE%.qcow2}.luks-key"
MANIFEST="${OUTPUT_IMAGE%.qcow2}.json"

[ -f "${SOURCE_IMAGE}" ] || die "source image is missing: ${SOURCE_IMAGE}"
[ "${SOURCE_IMAGE}" != "${OUTPUT_IMAGE}" ] || die "source and output must differ"
[ ! -e "${OUTPUT_IMAGE}" ] || die "output already exists: ${OUTPUT_IMAGE}"
[ ! -e "${KEY_FILE}" ] || die "key file already exists: ${KEY_FILE}"
[ ! -e "${MANIFEST}" ] || die "manifest already exists: ${MANIFEST}"

cleanup_failed_build() {
    if [ "${BUILD_COMPLETE}" -ne 1 ]; then
        rm -f -- "${OUTPUT_IMAGE}.tmp" "${OUTPUT_IMAGE}" "${KEY_FILE}" "${MANIFEST}"
    fi
}
trap cleanup_failed_build EXIT INT TERM

SOURCE_CONTAINER="$(container_path "${SOURCE_IMAGE}")"
OUTPUT_CONTAINER="$(container_path "${OUTPUT_IMAGE}")"
KEY_CONTAINER="$(container_path "${KEY_FILE}")"
MANIFEST_CONTAINER="$(container_path "${MANIFEST}")"

umask 077
# `cryptsetup --key-file` treats a trailing newline as key material while its
# interactive prompt does not. Keep this printable key newline-free so the
# person testing the VM can type the exact value at boot.
openssl rand -hex 24 | tr -d '\n' > "${KEY_FILE}"
chmod 0600 "${KEY_FILE}"

echo "==> Building encrypted ARM64 Mail acceptance disk"
echo "    source: $(basename "${SOURCE_IMAGE}")"
echo "    output: $(basename "${OUTPUT_IMAGE}")"
echo "    key:    $(basename "${KEY_FILE}") (mode 0600; value is never logged)"

if ! docker run --rm --interactive --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env "PUNAR_SOURCE_IMAGE=${SOURCE_CONTAINER}" \
    --env "PUNAR_OUTPUT_IMAGE=${OUTPUT_CONTAINER}" \
    --env "PUNAR_KEY_FILE=${KEY_CONTAINER}" \
    --env "PUNAR_MANIFEST=${MANIFEST_CONTAINER}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" \
    bash -s <<'CONTAINER'
set -euo pipefail

for command in qemu-img sfdisk jq losetup mount umount cryptsetup mkfs.btrfs \
    btrfs tar blkid awk sha256sum; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "error: builder is missing ${command}" >&2
        exit 1
    }
done

work="$(mktemp -d /var/tmp/punar-mail-acceptance.XXXXXX)"
raw="${work}/disk.raw"
layout="${work}/layout.json"
archive="${work}/data.tar"
old_data="${work}/old-data"
new_data="${work}/new-data"
root_mount="${work}/root"
mapper="punar-mail-acceptance-$$"
root_a=''
data_loop=''
data_mounted=0
root_mounted=0
mapper_open=0

cleanup() {
    if [ "${root_mounted}" -eq 1 ]; then
        umount "${root_mount}" 2>/dev/null || true
    fi
    if [ "${data_mounted}" -eq 1 ]; then
        umount "${new_data}" 2>/dev/null || umount "${old_data}" 2>/dev/null || true
    fi
    if [ "${mapper_open}" -eq 1 ]; then
        cryptsetup close "${mapper}" 2>/dev/null || true
    fi
    for loop in "${data_loop}" "${root_a}"; do
        [ -n "${loop}" ] && losetup -d "${loop}" 2>/dev/null || true
    done
    if [ -f "${raw}" ]; then
        truncate --size 0 -- "${raw}" || true
    fi
    rm -rf -- "${work}"
}
trap cleanup EXIT INT TERM

qemu-img convert -p -O raw "${PUNAR_SOURCE_IMAGE}" "${raw}"
sfdisk --json "${raw}" > "${layout}"
sector="$(jq -er '.partitiontable.sectorsize // 512' "${layout}")"
[ "$(jq -er '.partitiontable.partitions | length' "${layout}")" -eq 4 ] || {
    echo 'error: expected the four-partition Punar A/B layout' >&2
    exit 1
}

loop_for_partition() {
    local index="$1"
    local start size
    start="$(jq -er ".partitiontable.partitions[${index}].start" "${layout}")"
    size="$(jq -er ".partitiontable.partitions[${index}].size" "${layout}")"
    losetup --find --show \
        --offset "$((start * sector))" \
        --sizelimit "$((size * sector))" \
        "${raw}"
}

root_a="$(loop_for_partition 1)"
data_loop="$(loop_for_partition 3)"
[ "$(blkid -p -s TYPE -o value "${root_a}")" = ext4 ] || {
    echo 'error: slot A is not ext4' >&2
    exit 1
}
[ "$(blkid -p -s TYPE -o value "${data_loop}")" = btrfs ] || {
    echo 'error: source PUNAR-DATA is not btrfs' >&2
    exit 1
}

mkdir -p "${old_data}" "${new_data}" "${root_mount}"
mount -o ro,subvolid=5,nodev,nosuid "${data_loop}" "${old_data}"
data_mounted=1
for subvolume in @var @home @var-tmp; do
    btrfs subvolume show "${old_data}/${subvolume}" >/dev/null || {
        echo "error: source data volume is missing ${subvolume}" >&2
        exit 1
    }
done
tar --acls --xattrs --numeric-owner --sparse -cpf "${archive}" -C "${old_data}" .
umount "${old_data}"
data_mounted=0

cryptsetup luksFormat --batch-mode --type luks2 --pbkdf argon2id \
    --key-file "${PUNAR_KEY_FILE}" "${data_loop}"
cryptsetup open --key-file "${PUNAR_KEY_FILE}" "${data_loop}" "${mapper}"
mapper_open=1
mkfs.btrfs -f -L PUNAR-DATA "/dev/mapper/${mapper}"
mount -o subvolid=5,nodev,nosuid "/dev/mapper/${mapper}" "${new_data}"
data_mounted=1
for subvolume in @var @home @var-tmp; do
    btrfs subvolume create "${new_data}/${subvolume}" >/dev/null
done
tar --acls --xattrs --numeric-owner --sparse -xpf "${archive}" -C "${new_data}"
sync
for subvolume in @var @home @var-tmp; do
    btrfs subvolume show "${new_data}/${subvolume}" >/dev/null || {
        echo "error: encrypted data volume is missing ${subvolume}" >&2
        exit 1
    }
done
umount "${new_data}"
data_mounted=0
cryptsetup close "${mapper}"
mapper_open=0
luks_uuid="$(cryptsetup luksUUID "${data_loop}")"
[ -n "${luks_uuid}" ] || {
    echo 'error: encrypted data volume has no LUKS UUID' >&2
    exit 1
}

update_root() {
    local loop="$1"
    local slot="$2"
    mount "${loop}" "${root_mount}"
    root_mounted=1
    [ -f "${root_mount}/etc/fstab" ] || {
        echo "error: slot ${slot} has no fstab" >&2
        exit 1
    }
    awk '
        $2 == "/var" || $2 == "/home" || $2 == "/var/tmp" {
            $1 = "/dev/mapper/punar-data"
        }
        { print }
    ' "${root_mount}/etc/fstab" > "${root_mount}/etc/fstab.punar-new"
    mv "${root_mount}/etc/fstab.punar-new" "${root_mount}/etc/fstab"
    chmod 0644 "${root_mount}/etc/fstab"
    printf 'punar-data UUID=%s none luks,discard\n' "${luks_uuid}" \
        > "${root_mount}/etc/crypttab"
    chmod 0600 "${root_mount}/etc/crypttab"
    for mountpoint in /var /home /var/tmp; do
        awk -v wanted="${mountpoint}" \
            '$2 == wanted && $1 == "/dev/mapper/punar-data" { found = 1 } END { exit !found }' \
            "${root_mount}/etc/fstab" || {
            echo "error: slot ${slot} does not map ${mountpoint} through LUKS" >&2
            exit 1
        }
    done
    sync
    umount "${root_mount}"
    root_mounted=0
}

update_root "${root_a}" A
losetup -d "${data_loop}"
data_loop=''
losetup -d "${root_a}"
root_a=''

temporary_output="${PUNAR_OUTPUT_IMAGE}.tmp"
[ ! -e "${temporary_output}" ] || {
    echo "error: temporary output already exists: ${temporary_output}" >&2
    exit 1
}
qemu-img convert -p -O qcow2 -c "${raw}" "${temporary_output}"
qemu-img check "${temporary_output}"
mv "${temporary_output}" "${PUNAR_OUTPUT_IMAGE}"
source_sha="$(sha256sum "${PUNAR_SOURCE_IMAGE}" | awk '{print $1}')"
output_sha="$(sha256sum "${PUNAR_OUTPUT_IMAGE}" | awk '{print $1}')"
jq -cn \
    --arg source "$(basename "${PUNAR_SOURCE_IMAGE}")" \
    --arg source_sha256 "${source_sha}" \
    --arg image "$(basename "${PUNAR_OUTPUT_IMAGE}")" \
    --arg image_sha256 "${output_sha}" \
    --arg luks_uuid "${luks_uuid}" \
    --arg key_file "$(basename "${PUNAR_KEY_FILE}")" \
    '{v:1,kind:"punar_local_encrypted_acceptance_image",architecture:"arm64",
      source:$source,source_sha256:$source_sha256,image:$image,
      image_sha256:$image_sha256,luks_uuid:$luks_uuid,key_file:$key_file}' \
    > "${PUNAR_MANIFEST}"
chmod 0600 "${PUNAR_MANIFEST}"
chown "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" \
    "${PUNAR_OUTPUT_IMAGE}" "${PUNAR_MANIFEST}"
CONTAINER
then
    echo "error: encrypted acceptance image build failed; source image was not changed" >&2
    exit 1
fi

if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${OUTPUT_IMAGE}"
else
    sha256sum "${OUTPUT_IMAGE}"
fi
BUILD_COMPLETE=1
echo "==> Encrypted acceptance disk ready"
echo "    disk changes must use PUNAR_VM_PERSIST=1 during the account test"
