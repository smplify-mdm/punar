#!/usr/bin/env bash
# Build the raw FAT boot-slot artifact consumed by punard's native Raspberry
# Pi installer adapter. This is a build-time tool: it accepts only a pinned
# raspberrypi/firmware tree, a separately generated matching initramfs, and an
# already-staged copy of the exact kernel modules in the root payload.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${PUNAR_RPI_PIN_FILE:-${REPO_ROOT}/os/images/raspberry-pi/firmware.env}"
FIRMWARE_ROOT="${1:-}"
INITRAMFS="${2:-}"
ROOT_MODULES="${3:-}"
OUTPUT="${4:-}"
BOOTFS_BYTES="${PUNAR_RPI_BOOTFS_BYTES:-268435456}"
ROOT_A_PARTUUID="1beabfe0-9cb8-4b49-91ef-d372b845e7ea"
ROOT_B_PARTUUID="2b1b91a9-cf2c-4e9c-a723-5ec997971662"
MIN_BOOTFS_BYTES=$((64 * 1024 * 1024))
MAX_BOOTFS_BYTES=$((1024 * 1024 * 1024))
MAX_KERNEL_BYTES=$((64 * 1024 * 1024))
MAX_INITRAMFS_BYTES=$((128 * 1024 * 1024))

die() {
    echo "error: $*" >&2
    exit 1
}

usage() {
    echo "usage: $0 FIRMWARE_ROOT INITRAMFS ROOT_MODULES_DIR OUTPUT.img" >&2
    exit 2
}

[ -n "${FIRMWARE_ROOT}" ] && [ -n "${INITRAMFS}" ] \
    && [ -n "${ROOT_MODULES}" ] && [ -n "${OUTPUT}" ] || usage

for command in sha256sum find sort awk mkfs.vfat mcopy mmd mdir mtype fsck.vfat \
    truncate stat cmp; do
    command -v "${command}" >/dev/null 2>&1 \
        || die "required command is missing: ${command}"
done

[ -f "${PIN_FILE}" ] || die "firmware pin file is missing: ${PIN_FILE}"
# shellcheck source=/dev/null
. "${PIN_FILE}"
for variable in PUNAR_RPI_FIRMWARE_COMMIT PUNAR_RPI_KERNEL_RELEASE \
    PUNAR_RPI_KERNEL_SHA256 PUNAR_RPI_START4_SHA256 PUNAR_RPI_FIXUP4_SHA256 \
    PUNAR_RPI_LICENCE_SHA256 PUNAR_RPI_MODULES_TREE_SHA256 \
    PUNAR_RPI_BOARD_ASSETS_TREE_SHA256; do
    value="${!variable:-}"
    [ -n "${value}" ] || die "firmware pin is missing ${variable}"
done

case "${BOOTFS_BYTES}" in
    ''|*[!0-9]*) die "PUNAR_RPI_BOOTFS_BYTES must be an integer" ;;
esac
[ "${BOOTFS_BYTES}" -ge "${MIN_BOOTFS_BYTES}" ] \
    && [ "${BOOTFS_BYTES}" -le "${MAX_BOOTFS_BYTES}" ] \
    && [ $((BOOTFS_BYTES % 4096)) -eq 0 ] \
    || die "boot filesystem must be 64 MiB..1 GiB and 4096-byte aligned"

FIRMWARE_ROOT="$(cd "${FIRMWARE_ROOT}" && pwd)"
INITRAMFS="$(cd "$(dirname "${INITRAMFS}")" && pwd)/$(basename "${INITRAMFS}")"
ROOT_MODULES="$(cd "${ROOT_MODULES}" && pwd)"
OUTPUT_PARENT="$(cd "$(dirname "${OUTPUT}")" && pwd)"
OUTPUT="${OUTPUT_PARENT}/$(basename "${OUTPUT}")"
BOOT="${FIRMWARE_ROOT}/boot"
SOURCE_MODULES="${FIRMWARE_ROOT}/modules/${PUNAR_RPI_KERNEL_RELEASE}"

[ ! -e "${OUTPUT}" ] || die "refusing to overwrite existing output: ${OUTPUT}"
[ -f "${INITRAMFS}" ] && [ ! -L "${INITRAMFS}" ] \
    || die "initramfs must be a regular non-symlink file"
[ -d "${BOOT}" ] || die "firmware boot directory is missing"
[ -d "${SOURCE_MODULES}" ] || die "pinned firmware modules are missing"
[ -d "${ROOT_MODULES}" ] || die "staged root modules are missing"
[ -z "$(find "${SOURCE_MODULES}" -type l -print -quit)" ] \
    || die "pinned firmware modules may not contain symbolic links"
[ -z "$(find "${ROOT_MODULES}" -type l -print -quit)" ] \
    || die "staged root modules may not contain symbolic links"
[ -z "$(find "${BOOT}/overlays" -type l -print -quit)" ] \
    || die "pinned Raspberry Pi overlays may not contain symbolic links"

critical_files=(
    "${BOOT}/kernel8.img"
    "${BOOT}/start4.elf"
    "${BOOT}/fixup4.dat"
    "${BOOT}/LICENCE.broadcom"
    "${BOOT}/COPYING.linux"
    "${BOOT}/bcm2711-rpi-4-b.dtb"
    "${BOOT}/bcm2712-rpi-5-b.dtb"
    "${BOOT}/overlays/overlay_map.dtb"
    "${BOOT}/overlays/vc4-kms-v3d-pi4.dtbo"
    "${BOOT}/overlays/vc4-kms-v3d-pi5.dtbo"
)
for file in "${critical_files[@]}"; do
    [ -f "${file}" ] && [ ! -L "${file}" ] \
        || die "required pinned firmware file is missing or unsafe: ${file}"
done

verify_digest() {
    local file="$1"
    local expected="$2"
    local description="$3"
    local actual
    actual="$(sha256sum "${file}" | awk '{print $1}')"
    [ "${actual}" = "${expected}" ] \
        || die "${description} does not match the pinned digest"
}

tree_digest() {
    local root="$1"
    shift
    (
        cd "${root}"
        find "$@" -type f -print0 \
            | sort -z \
            | while IFS= read -r -d '' file; do
                printf '%s\0' "${file}"
                sha256sum "${file}" | awk '{print $1}'
            done \
            | sha256sum \
            | awk '{print $1}'
    )
}

module_payload_digest() {
    local root="$1"
    (
        cd "${root}"
        find . -type f \
            \( -name '*.ko' -o -name '*.ko.gz' -o -name '*.ko.xz' \
                -o -name '*.ko.zst' \) -print0 \
            | sort -z \
            | while IFS= read -r -d '' file; do
                printf '%s\0' "${file}"
                sha256sum "${file}" | awk '{print $1}'
            done \
            | sha256sum \
            | awk '{print $1}'
    )
}

verify_digest "${BOOT}/kernel8.img" "${PUNAR_RPI_KERNEL_SHA256}" "kernel8.img"
verify_digest "${BOOT}/start4.elf" "${PUNAR_RPI_START4_SHA256}" "start4.elf"
verify_digest "${BOOT}/fixup4.dat" "${PUNAR_RPI_FIXUP4_SHA256}" "fixup4.dat"
verify_digest "${BOOT}/LICENCE.broadcom" "${PUNAR_RPI_LICENCE_SHA256}" \
    "Broadcom firmware licence"

source_modules_digest="$(tree_digest "${SOURCE_MODULES}" .)"
[ "${source_modules_digest}" = "${PUNAR_RPI_MODULES_TREE_SHA256}" ] \
    || die "firmware kernel modules do not match the pinned tree digest"
source_payload_digest="$(module_payload_digest "${SOURCE_MODULES}")"
root_payload_digest="$(module_payload_digest "${ROOT_MODULES}")"
[ "${root_payload_digest}" = "${source_payload_digest}" ] \
    || die "root payload does not contain the exact pinned loadable modules"
[ -n "$(find "${ROOT_MODULES}" -type f \
    \( -name '*.ko' -o -name '*.ko.gz' -o -name '*.ko.xz' \
        -o -name '*.ko.zst' \) -print -quit)" ] \
    || die "root payload contains no loadable modules"
for module_index in modules.dep modules.dep.bin modules.alias modules.alias.bin; do
    [ -s "${ROOT_MODULES}/${module_index}" ] \
        || die "root payload is missing generated ${module_index}"
done

board_assets_digest="$({
    find "${BOOT}" -maxdepth 1 -type f \
        \( -name 'bcm2711*.dtb' -o -name 'bcm2712*.dtb' \) -print0
    find "${BOOT}/overlays" -maxdepth 1 -type f -print0
} | sort -z | while IFS= read -r -d '' file; do
    relative="${file#"${FIRMWARE_ROOT}/"}"
    printf '%s\0' "${relative}"
    sha256sum "${file}" | awk '{print $1}'
done | sha256sum | awk '{print $1}')"
[ "${board_assets_digest}" = "${PUNAR_RPI_BOARD_ASSETS_TREE_SHA256}" ] \
    || die "Raspberry Pi DTBs/overlays do not match the pinned tree digest"

kernel_bytes="$(stat -c %s "${BOOT}/kernel8.img")"
initramfs_bytes="$(stat -c %s "${INITRAMFS}")"
[ "${kernel_bytes}" -gt 0 ] && [ "${kernel_bytes}" -le "${MAX_KERNEL_BYTES}" ] \
    || die "kernel8.img is empty or exceeds the 64 MiB limit"
[ "${initramfs_bytes}" -gt 0 ] && [ "${initramfs_bytes}" -le "${MAX_INITRAMFS_BYTES}" ] \
    || die "initramfs is empty or exceeds the 128 MiB limit"

TEMP_DIR="$(mktemp -d /tmp/punar-rpi-bootfs.XXXXXX)"
success=false
cleanup() {
    rm -rf "${TEMP_DIR}"
    if [ "${success}" != true ] && [ -f "${OUTPUT}" ]; then
        rm -f "${OUTPUT}"
    fi
}
trap cleanup EXIT

cat > "${TEMP_DIR}/cmdline-a.txt" <<EOF
root=PARTUUID=${ROOT_A_PARTUUID} rootfstype=ext4 ro rootwait quiet splash fsck.repair=yes
EOF
cat > "${TEMP_DIR}/cmdline-b.txt" <<EOF
root=PARTUUID=${ROOT_B_PARTUUID} rootfstype=ext4 ro rootwait quiet splash fsck.repair=yes
EOF
cat > "${TEMP_DIR}/config.txt" <<'EOF'
[all]
arm_64bit=1
kernel=kernel8.img
initramfs initramfs8 followkernel
disable_overscan=1

[boot_partition=2]
cmdline=cmdline-a.txt

[boot_partition=4]
cmdline=cmdline-b.txt

[pi4]
dtoverlay=vc4-kms-v3d-pi4

[pi5]
dtoverlay=vc4-kms-v3d-pi5
EOF

truncate --size "${BOOTFS_BYTES}" "${OUTPUT}"
# The exact same signed image can occupy boot A or boot B. The GPT partition
# label carries slot identity; the FAT label intentionally remains neutral.
mkfs.vfat -F 32 -n PUNARBOOT -i 79115027 "${OUTPUT}" >/dev/null
mmd -i "${OUTPUT}" ::/overlays

for file in cmdline-a.txt cmdline-b.txt config.txt; do
    mcopy -i "${OUTPUT}" "${TEMP_DIR}/${file}" "::/${file}"
done
for file in kernel8.img start4.elf fixup4.dat LICENCE.broadcom COPYING.linux; do
    mcopy -i "${OUTPUT}" "${BOOT}/${file}" "::/${file}"
done
mcopy -i "${OUTPUT}" "${INITRAMFS}" ::/initramfs8

while IFS= read -r -d '' file; do
    mcopy -i "${OUTPUT}" "${file}" "::/$(basename "${file}")"
done < <(find "${BOOT}" -maxdepth 1 -type f \
    \( -name 'bcm2711*.dtb' -o -name 'bcm2712*.dtb' \) -print0 | sort -z)
while IFS= read -r -d '' file; do
    mcopy -i "${OUTPUT}" "${file}" "::/overlays/$(basename "${file}")"
done < <(find "${BOOT}/overlays" -maxdepth 1 -type f -print0 | sort -z)

for file in cmdline-a.txt cmdline-b.txt config.txt; do
    mtype -i "${OUTPUT}" "::/${file}" > "${TEMP_DIR}/installed-${file}"
    cmp "${TEMP_DIR}/${file}" "${TEMP_DIR}/installed-${file}"
done
for file in kernel8.img initramfs8 start4.elf fixup4.dat \
    bcm2711-rpi-4-b.dtb bcm2712-rpi-5-b.dtb; do
    mdir -i "${OUTPUT}" "::/${file}" >/dev/null \
        || die "assembled boot filesystem is missing ${file}"
done
mdir -i "${OUTPUT}" ::/overlays/vc4-kms-v3d-pi4.dtbo >/dev/null
mdir -i "${OUTPUT}" ::/overlays/vc4-kms-v3d-pi5.dtbo >/dev/null
fsck.vfat -vn "${OUTPUT}" >/dev/null

actual_size="$(stat -c %s "${OUTPUT}")"
[ "${actual_size}" = "${BOOTFS_BYTES}" ] \
    || die "assembled boot filesystem size changed unexpectedly"
bootfs_digest="$(sha256sum "${OUTPUT}" | awk '{print $1}')"
chmod 0644 "${OUTPUT}"
success=true
echo "PUNAR_RPI_BOOTFS_OK bytes=${actual_size} sha256=${bootfs_digest} firmware_commit=${PUNAR_RPI_FIRMWARE_COMMIT} kernel=${PUNAR_RPI_KERNEL_RELEASE}"
