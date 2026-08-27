#!/usr/bin/env bash
# V-REPART: executable proof for the four systemd-repart assumptions in
# docs/design/installer.md section 11. Run as root inside either pinned image
# builder container; the test creates only disposable sparse disks under /run.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "error: V-REPART needs root for loop devices and LUKS mappings" >&2
    exit 1
fi

for command in systemd-repart losetup mount umount mountpoint btrfs cryptsetup \
    blkid sfdisk sha256sum truncate dd head awk grep python3 mknod; do
    command -v "${command}" >/dev/null 2>&1 \
        || { echo "error: required command is missing: ${command}" >&2; exit 1; }
done

# systemd-repart creates short-lived loop nodes when its target is a regular
# file. Docker Desktop may then leave the kernel device present but its /dev
# node absent for the next privileged container. Recreate only missing nodes
# inside this disposable device namespace.
for loop_minor in {0..31}; do
    [ -b "/dev/loop${loop_minor}" ] \
        || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
done
[ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237

WORK_DIR="$(mktemp -d /run/punar-repart-spike.XXXXXX)"
LOOP_DEVICE=""
CRYPT_NAME="punar-repart-spike-$$"

cleanup() {
    if [ -e "/dev/mapper/${CRYPT_NAME}" ]; then
        cryptsetup close "${CRYPT_NAME}" || true
    fi
    if mountpoint -q "${WORK_DIR}/mnt"; then
        umount "${WORK_DIR}/mnt" || true
    fi
    if [ -n "${LOOP_DEVICE}" ]; then
        losetup --detach "${LOOP_DEVICE}" || true
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

new_disk() {
    local path="$1"
    local size="$2"

    truncate --size "${size}" "${path}"
}

attach_disk() {
    local path="$1"
    local partition_start
    local partition_size

    read -r partition_start partition_size < <(
        sfdisk --json "${path}" \
            | python3 -c 'import json,sys; p=json.load(sys.stdin)["partitiontable"]["partitions"][0]; print(p["start"], p["size"])'
    )
    LOOP_DEVICE="$(losetup \
        --find \
        --show \
        --offset "$((partition_start * 512))" \
        --sizelimit "$((partition_size * 512))" \
        "${path}")"
}

detach_disk() {
    losetup --detach "${LOOP_DEVICE}"
    LOOP_DEVICE=""
}

partition_path() {
    printf '%s\n' "${LOOP_DEVICE}"
}

echo "V-REPART toolchain: $(systemd-repart --version | head -n 1)"

# 1. Measure repeated --definitions priority. Pinned systemd 261.2 gives the
# first directory priority, contrary to the design's original assumption. The
# committed renderer supplies explicit later-wins overlay semantics instead.
mkdir -p "${WORK_DIR}/shadow-base" "${WORK_DIR}/shadow-later" \
    "${WORK_DIR}/shadow-rendered"
printf '%s\n' \
    '[Partition]' \
    'Type=linux-generic' \
    'Label=PUNAR-SHADOW-BASE' \
    'SizeMinBytes=32M' \
    'SizeMaxBytes=32M' \
    > "${WORK_DIR}/shadow-base/10-shadow.conf"
printf '%s\n' \
    '[Partition]' \
    'Type=linux-generic' \
    'Label=PUNAR-SHADOW-LATER' \
    'SizeMinBytes=32M' \
    'SizeMaxBytes=32M' \
    > "${WORK_DIR}/shadow-later/10-shadow.conf"
new_disk "${WORK_DIR}/shadow.raw" 64M
shadow_json="$(systemd-repart \
    --dry-run=no \
    --empty=force \
    --pretty=no \
    --json=short \
    --definitions="${WORK_DIR}/shadow-base" \
    --definitions="${WORK_DIR}/shadow-later" \
    "${WORK_DIR}/shadow.raw")"
if grep -Fq 'PUNAR-SHADOW-BASE' <<<"${shadow_json}"; then
    echo "V-REPART OBSERVED: repeated --definitions uses first-directory priority"
elif grep -Fq 'PUNAR-SHADOW-LATER' <<<"${shadow_json}"; then
    echo "V-REPART OBSERVED: repeated --definitions uses later-directory priority"
else
    echo "error: could not determine repeated --definitions priority" >&2
    exit 1
fi

"/work/tools/render-repart-definitions.sh" \
    "${WORK_DIR}/shadow-rendered" \
    "${WORK_DIR}/shadow-base" \
    "${WORK_DIR}/shadow-later"
new_disk "${WORK_DIR}/shadow-rendered.raw" 64M
rendered_json="$(systemd-repart \
    --dry-run=no \
    --empty=force \
    --pretty=no \
    --json=short \
    --definitions="${WORK_DIR}/shadow-rendered" \
    "${WORK_DIR}/shadow-rendered.raw")"
grep -Fq 'PUNAR-SHADOW-LATER' <<<"${rendered_json}"
if grep -Fq 'PUNAR-SHADOW-BASE' <<<"${rendered_json}"; then
    echo "error: renderer did not apply the later overlay" >&2
    exit 1
fi
echo "V-REPART PASS: explicit renderer provides later-directory-wins overlays"

# 2. The shared data partition must be one btrfs filesystem with three real
# subvolumes. This is run offline, the mode systemd documents for direct
# subvolume creation with current btrfs-progs.
mkdir -p "${WORK_DIR}/subvol-definitions" "${WORK_DIR}/mnt"
printf '%s\n' \
    '[Partition]' \
    'Type=linux-generic' \
    'Label=PUNAR-SUBVOLUMES' \
    'Format=btrfs' \
    'MakeDirectories=/@var /@home /@var-tmp' \
    'Subvolumes=/@var /@home /@var-tmp' \
    'SizeMinBytes=384M' \
    'SizeMaxBytes=384M' \
    > "${WORK_DIR}/subvol-definitions/10-subvolumes.conf"
new_disk "${WORK_DIR}/subvolumes.raw" 416M
systemd-repart \
    --dry-run=no \
    --offline=no \
    --empty=force \
    --pretty=no \
    --definitions="${WORK_DIR}/subvol-definitions" \
    "${WORK_DIR}/subvolumes.raw" >/dev/null
attach_disk "${WORK_DIR}/subvolumes.raw"
mount "$(partition_path)" "${WORK_DIR}/mnt"
subvolumes="$(btrfs subvolume list "${WORK_DIR}/mnt")"
printf '%s\n' "${subvolumes}"
for expected in '@var' '@home' '@var-tmp'; do
    grep -Eq " path ${expected}$" <<<"${subvolumes}" \
        || { echo "error: missing btrfs subvolume ${expected}" >&2; exit 1; }
done
umount "${WORK_DIR}/mnt"
detach_disk
echo "V-REPART PASS: btrfs subvolumes are materialized"

# 3. Encrypt=key-file must produce a LUKS2 container that the same key opens,
# with the requested filesystem inside. EncryptKDF=minimal is appropriate for
# this high-entropy disposable test key and keeps the architecture matrix fast.
mkdir -p "${WORK_DIR}/encrypted-definitions"
head -c 64 /dev/urandom > "${WORK_DIR}/install.key"
chmod 0600 "${WORK_DIR}/install.key"
printf '%s\n' \
    '[Partition]' \
    'Type=linux-generic' \
    'Label=PUNAR-ENCRYPTED' \
    'Format=ext4' \
    'Encrypt=key-file' \
    'EncryptKDF=minimal' \
    'SizeMinBytes=192M' \
    'SizeMaxBytes=192M' \
    > "${WORK_DIR}/encrypted-definitions/10-encrypted.conf"
new_disk "${WORK_DIR}/encrypted.raw" 224M
systemd-repart \
    --dry-run=no \
    --offline=yes \
    --empty=force \
    --pretty=no \
    --key-file="${WORK_DIR}/install.key" \
    --definitions="${WORK_DIR}/encrypted-definitions" \
    "${WORK_DIR}/encrypted.raw" >/dev/null
attach_disk "${WORK_DIR}/encrypted.raw"
encrypted_partition="$(partition_path)"
[ "$(blkid --probe --output value --match-tag TYPE "${encrypted_partition}")" = "crypto_LUKS" ]
cryptsetup luksDump "${encrypted_partition}" | grep -Eq '^Version:[[:space:]]+2$'
cryptsetup open \
    --key-file "${WORK_DIR}/install.key" \
    "${encrypted_partition}" "${CRYPT_NAME}"
[ "$(blkid --probe --output value --match-tag TYPE "/dev/mapper/${CRYPT_NAME}")" = "ext4" ]
cryptsetup close "${CRYPT_NAME}"
detach_disk
echo "V-REPART PASS: key-file encryption creates an openable LUKS2 filesystem"

# 4. The install payload lives below /run and is copied block-for-block into
# slot A. Compare the exact payload digest with the first payload-sized bytes
# of the created partition, rather than trusting repart's success status.
mkdir -p "${WORK_DIR}/copy-definitions"
dd if=/dev/zero of="${WORK_DIR}/payload.raw" bs=1M count=8 status=none
printf 'PUNAR-COPYBLOCKS-V1\n' \
    | dd of="${WORK_DIR}/payload.raw" conv=notrunc status=none
printf '%s\n' \
    '[Partition]' \
    'Type=linux-generic' \
    'Label=PUNAR-COPYBLOCKS' \
    "CopyBlocks=${WORK_DIR}/payload.raw" \
    'SizeMinBytes=16M' \
    'SizeMaxBytes=16M' \
    > "${WORK_DIR}/copy-definitions/10-copy.conf"
new_disk "${WORK_DIR}/copy.raw" 48M
systemd-repart \
    --dry-run=no \
    --offline=yes \
    --empty=force \
    --pretty=no \
    --definitions="${WORK_DIR}/copy-definitions" \
    "${WORK_DIR}/copy.raw" >/dev/null
attach_disk "${WORK_DIR}/copy.raw"
payload_digest="$(sha256sum "${WORK_DIR}/payload.raw" | awk '{print $1}')"
partition_digest="$(dd if="$(partition_path)" bs=1M count=8 status=none | sha256sum | awk '{print $1}')"
[ "${payload_digest}" = "${partition_digest}" ]
detach_disk
echo "V-REPART PASS: CopyBlocks accepts a /run path and copies exact bytes"

echo "V-REPART PASS: required capabilities hold with the explicit merge fallback"
