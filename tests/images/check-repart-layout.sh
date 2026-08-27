#!/usr/bin/env bash
# Inspect a built raw Punar disk, including contents. This is the executable
# A/B layout contract shared by x86_64 and ARM64 image builds.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 IMAGE.raw x86_64|arm64" >&2
    exit 2
fi
if [ "$(id -u)" -ne 0 ]; then
    echo "error: layout inspection needs root for disposable loop mounts" >&2
    exit 1
fi

IMAGE="$(readlink -f "$1")"
ARCH="$2"
[ -f "${IMAGE}" ] || { echo "error: raw image not found: ${IMAGE}" >&2; exit 2; }

case "${ARCH}" in
    x86_64) ROOT_TYPE='4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709' ;;
    arm64) ROOT_TYPE='B921B045-1DF0-41C3-AF44-4C6F280D3FAE' ;;
    *) echo "error: architecture must be x86_64 or arm64" >&2; exit 2 ;;
esac

for command in sfdisk python3 losetup mount umount mountpoint blkid btrfs \
    objcopy awk grep cmp dd readlink find cp tr mknod; do
    command -v "${command}" >/dev/null 2>&1 \
        || { echo "error: required command is missing: ${command}" >&2; exit 1; }
done

for loop_minor in {0..31}; do
    [ -b "/dev/loop${loop_minor}" ] \
        || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
done
[ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237

WORK_DIR="$(mktemp -d /run/punar-layout-check.XXXXXX)"
LOOP_DEVICE=""
mkdir -p "${WORK_DIR}/mnt"

cleanup() {
    if mountpoint -q "${WORK_DIR}/mnt"; then
        umount "${WORK_DIR}/mnt" || true
    fi
    if [ -n "${LOOP_DEVICE}" ]; then
        losetup --detach "${LOOP_DEVICE}" || true
    fi
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

sfdisk --json "${IMAGE}" > "${WORK_DIR}/table.json"
python3 - "${WORK_DIR}/table.json" > "${WORK_DIR}/partitions.tsv" <<'PY'
import json
import sys

table = json.load(open(sys.argv[1], encoding="utf-8"))["partitiontable"]
parts = table["partitions"]
if table.get("label") != "gpt":
    raise SystemExit("disk is not GPT")
if table.get("sectorsize") != 512:
    raise SystemExit("disk sector size is not 512")
if len(parts) != 4:
    raise SystemExit(f"expected exactly 4 partitions, found {len(parts)}")
for index, part in enumerate(parts, 1):
    print(
        index,
        part["start"],
        part["size"],
        part["type"].upper(),
        part["uuid"].upper(),
        part.get("name", ""),
        part.get("attrs", "-"),
        sep="\t",
    )
PY

field() {
    local partition="$1"
    local column="$2"
    awk -F '\t' -v p="${partition}" -v c="${column}" '$1 == p {print $c; exit}' \
        "${WORK_DIR}/partitions.tsv"
}

expected_types=(
    'C12A7328-F81F-11D2-BA4B-00A0C93EC93B'
    "${ROOT_TYPE}"
    "${ROOT_TYPE}"
    '0FC63DAF-8483-4772-8E79-3D69D8477DE4'
)
expected_uuids=(
    '8BB56554-B5F1-4058-90AC-8DC91A8E2BD4'
    '1BEABFE0-9CB8-4B49-91EF-D372B845E7EA'
    '2B1B91A9-CF2C-4E9C-A723-5EC997971662'
    '21D4AF4F-A19C-4C6A-B4E8-DD50E9F7ECB9'
)
expected_names=('PUNAR-ESP' 'PUNAR-ROOT-A' 'PUNAR-ROOT-B' 'PUNAR-DATA')
expected_sizes=(2097152 16777216 16777216 33554432)
expected_btrfs_device_uuid='ef4a2286-ac11-53c0-a40d-8d2bae7511cc'

for partition in 1 2 3 4; do
    array_index=$((partition - 1))
    [ "$(field "${partition}" 3)" = "${expected_sizes[${array_index}]}" ]
    [ "$(field "${partition}" 4)" = "${expected_types[${array_index}]}" ]
    [ "$(field "${partition}" 5)" = "${expected_uuids[${array_index}]}" ]
    [ "$(field "${partition}" 6)" = "${expected_names[${array_index}]}" ]
done
[ "$(field 2 5)" != "$(field 3 5)" ]
grep -Eq '(^|,)63($|,)' <<<"$(field 3 7)"
echo "PUNAR_LAYOUT PASS: GPT geometry, types, labels and literal PARTUUIDs"

attach_partition() {
    local partition="$1"
    local start
    local size

    start="$(field "${partition}" 2)"
    size="$(field "${partition}" 3)"
    LOOP_DEVICE="$(losetup \
        --find \
        --show \
        --offset "$((start * 512))" \
        --sizelimit "$((size * 512))" \
        "${IMAGE}")"
}

detach_partition() {
    losetup --detach "${LOOP_DEVICE}"
    LOOP_DEVICE=""
}

mount_partition() {
    local options="$1"
    mount -o "${options}" "${LOOP_DEVICE}" "${WORK_DIR}/mnt"
}

unmount_partition() {
    umount "${WORK_DIR}/mnt"
}

# Slot A: populated ext4 root, generated mount contract, and no mutable state.
attach_partition 2
[ "$(blkid --probe --output value --match-tag TYPE "${LOOP_DEVICE}")" = ext4 ]
mount_partition ro
[ -f "${WORK_DIR}/mnt/etc/os-release" ]
[ -f "${WORK_DIR}/mnt/etc/fstab" ]
for mount_target in / /efi /var /home /var/tmp; do
    awk -v target="${mount_target}" '$2 == target {found=1} END {exit !found}' \
        "${WORK_DIR}/mnt/etc/fstab"
done
grep -Eq '[[:space:]]/efi[[:space:]].*(^|,)noexec(,|[[:space:]])' \
    "${WORK_DIR}/mnt/etc/fstab"
grep -Eq '[[:space:]]/efi[[:space:]].*(^|,)nosuid(,|[[:space:]])' \
    "${WORK_DIR}/mnt/etc/fstab"
grep -Eq '[[:space:]]/efi[[:space:]].*(^|,)nodev(,|[[:space:]])' \
    "${WORK_DIR}/mnt/etc/fstab"
for subvolume in '@var' '@home' '@var-tmp'; do
    grep -Eq "[[:space:],]subvol=${subvolume}(,|[[:space:]])" \
        "${WORK_DIR}/mnt/etc/fstab"
done
grep -Eq '[[:space:]]/var/tmp[[:space:]].*(^|,)nosuid(,|[[:space:]])' \
    "${WORK_DIR}/mnt/etc/fstab"
grep -Eq '[[:space:]]/var/tmp[[:space:]].*(^|,)nodev(,|[[:space:]])' \
    "${WORK_DIR}/mnt/etc/fstab"
if find "${WORK_DIR}/mnt/var" -mindepth 1 -print -quit | grep -q .; then
    echo "error: slot A contains mutable /var state" >&2
    exit 1
fi
if find "${WORK_DIR}/mnt/home" -mindepth 1 -print -quit | grep -q .; then
    echo "error: slot A contains mutable /home state" >&2
    exit 1
fi
cp "${WORK_DIR}/mnt/etc/fstab" "${WORK_DIR}/fstab"
unmount_partition
detach_partition
echo "PUNAR_LAYOUT PASS: slot A is populated and excludes mutable trees"

# Slot B: inactive, unformatted and sampled zero-filled at beginning/middle/end.
attach_partition 3
if blkid --probe "${LOOP_DEVICE}" >/dev/null 2>&1; then
    echo "error: inactive slot B unexpectedly contains a filesystem signature" >&2
    exit 1
fi
slot_b_bytes=$(( $(field 3 3) * 512 ))
for offset in 0 $((slot_b_bytes / 2)) $((slot_b_bytes - 1048576)); do
    dd if="${LOOP_DEVICE}" iflag=skip_bytes,count_bytes \
        skip="${offset}" count=1048576 status=none \
        | cmp -n 1048576 - /dev/zero
done
detach_partition
echo "PUNAR_LAYOUT PASS: slot B is inactive, unformatted and zero-filled"

# Shared data: no top-level fstab mount and exactly the three required btrfs
# subvolumes. Seeded package state must live in @var, outside both root slots.
attach_partition 4
[ "$(blkid --probe --output value --match-tag TYPE "${LOOP_DEVICE}")" = btrfs ]
data_fs_uuid="$(blkid --probe --output value --match-tag UUID "${LOOP_DEVICE}")"
btrfs_device_uuid="$(btrfs inspect-internal dump-super -f "${LOOP_DEVICE}" \
    | awk '$1 == "dev_item.uuid" {print $2; exit}')"
[ "${btrfs_device_uuid}" = "${expected_btrfs_device_uuid}" ] \
    || { echo "error: unexpected btrfs device UUID: ${btrfs_device_uuid}" >&2; exit 1; }
mount_partition ro
subvolumes="$(btrfs subvolume list "${WORK_DIR}/mnt")"
subvolume_count="$(grep -c ' path ' <<<"${subvolumes}")"
[ "${subvolume_count}" -eq 3 ] \
    || { echo "error: expected exactly 3 btrfs subvolumes, found ${subvolume_count}" >&2; exit 1; }
for expected in '@var' '@home' '@var-tmp'; do
    grep -Eq " path ${expected}$" <<<"${subvolumes}"
done
unmount_partition
mount_partition 'ro,subvol=@var'
[ -d "${WORK_DIR}/mnt/lib" ]
unmount_partition
detach_partition
if awk -v source="UUID=${data_fs_uuid}" \
    '$1 == source && $4 !~ /(^|,)subvol=/ {bad=1} END {exit bad ? 0 : 1}' \
    "${WORK_DIR}/fstab"; then
    echo "error: fstab exposes the btrfs top level" >&2
    exit 1
fi
echo "PUNAR_LAYOUT PASS: shared btrfs state has three isolated subvolumes"

# ESP: bootloader/UKI exist and the UKI binds this image to literal slot A.
attach_partition 1
[ "$(blkid --probe --output value --match-tag TYPE "${LOOP_DEVICE}")" = vfat ]
mount_partition ro
uki="$(find "${WORK_DIR}/mnt/EFI/Linux" -maxdepth 1 -type f -name '*.efi' -print -quit)"
[ -n "${uki}" ] || { echo "error: ESP contains no UKI" >&2; exit 1; }
uki_count="$(find "${WORK_DIR}/mnt/EFI/Linux" -maxdepth 1 -type f -name '*.efi' | wc -l | tr -d ' ')"
[ "${uki_count}" -eq 1 ] \
    || { echo "error: ESP must contain exactly one UKI, found ${uki_count}" >&2; exit 1; }
objcopy --only-section=.cmdline --output-target=binary \
    "${uki}" "${WORK_DIR}/cmdline"
cmdline="$(tr -d '\000' < "${WORK_DIR}/cmdline")"
grep -Fqi "root=PARTUUID=${expected_uuids[1]}" <<<"${cmdline}"
unmount_partition
detach_partition
echo "PUNAR_LAYOUT PASS: ESP UKI selects literal slot A"

echo "PUNAR_LAYOUT_OK architecture=${ARCH}"
