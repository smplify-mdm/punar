#!/usr/bin/env bash
# Fast contract test for the raw Raspberry Pi boot-filesystem builder. The
# fixture is intentionally tiny and synthetic; real vendor inputs remain
# pinned by os/images/raspberry-pi/firmware.env.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d /tmp/punar-rpi-bootfs-test.XXXXXX)"
cleanup() {
    rm -rf "${WORK}"
}
trap cleanup EXIT

mkdir -p "${WORK}/firmware/boot/overlays" \
    "${WORK}/firmware/modules/fixture-v8+" \
    "${WORK}/root-modules"
printf 'fixture kernel\n' > "${WORK}/firmware/boot/kernel8.img"
printf 'fixture start4\n' > "${WORK}/firmware/boot/start4.elf"
printf 'fixture fixup4\n' > "${WORK}/firmware/boot/fixup4.dat"
printf 'fixture licence\n' > "${WORK}/firmware/boot/LICENCE.broadcom"
printf 'fixture linux copying\n' > "${WORK}/firmware/boot/COPYING.linux"
printf 'fixture pi4 dtb\n' > "${WORK}/firmware/boot/bcm2711-rpi-4-b.dtb"
printf 'fixture pi5 dtb\n' > "${WORK}/firmware/boot/bcm2712-rpi-5-b.dtb"
printf 'fixture overlay map\n' > "${WORK}/firmware/boot/overlays/overlay_map.dtb"
printf 'fixture pi4 kms\n' > "${WORK}/firmware/boot/overlays/vc4-kms-v3d-pi4.dtbo"
printf 'fixture pi5 kms\n' > "${WORK}/firmware/boot/overlays/vc4-kms-v3d-pi5.dtbo"
printf 'fixture dependency\n' > "${WORK}/firmware/modules/fixture-v8+/modules.dep"
printf 'fixture binary dependency\n' \
    > "${WORK}/firmware/modules/fixture-v8+/modules.dep.bin"
printf 'fixture alias\n' > "${WORK}/firmware/modules/fixture-v8+/modules.alias"
printf 'fixture binary alias\n' \
    > "${WORK}/firmware/modules/fixture-v8+/modules.alias.bin"
printf 'fixture module\n' > "${WORK}/firmware/modules/fixture-v8+/fixture.ko"
cp -a "${WORK}/firmware/modules/fixture-v8+/." "${WORK}/root-modules/"
# depmod is expected to regenerate these derived indexes in the install root;
# they need to be present and nonempty, but do not byte-match the vendor copy.
printf 'regenerated root dependency\n' > "${WORK}/root-modules/modules.dep"
printf 'fixture initramfs\n' > "${WORK}/initramfs8"

digest() {
    sha256sum "$1" | awk '{print $1}'
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

modules_digest="$(tree_digest "${WORK}/firmware/modules/fixture-v8+" .)"
board_digest="$({
    find "${WORK}/firmware/boot" -maxdepth 1 -type f \
        \( -name 'bcm2711*.dtb' -o -name 'bcm2712*.dtb' \) -print0
    find "${WORK}/firmware/boot/overlays" -maxdepth 1 -type f -print0
} | sort -z | while IFS= read -r -d '' file; do
    relative="${file#"${WORK}/firmware/"}"
    printf '%s\0' "${relative}"
    sha256sum "${file}" | awk '{print $1}'
done | sha256sum | awk '{print $1}')"

cat > "${WORK}/fixture.env" <<EOF
PUNAR_RPI_FIRMWARE_COMMIT="0000000000000000000000000000000000000000"
PUNAR_RPI_KERNEL_RELEASE="fixture-v8+"
PUNAR_RPI_KERNEL_SHA256="$(digest "${WORK}/firmware/boot/kernel8.img")"
PUNAR_RPI_START4_SHA256="$(digest "${WORK}/firmware/boot/start4.elf")"
PUNAR_RPI_FIXUP4_SHA256="$(digest "${WORK}/firmware/boot/fixup4.dat")"
PUNAR_RPI_LICENCE_SHA256="$(digest "${WORK}/firmware/boot/LICENCE.broadcom")"
PUNAR_RPI_MODULES_TREE_SHA256="${modules_digest}"
PUNAR_RPI_BOARD_ASSETS_TREE_SHA256="${board_digest}"
EOF

PUNAR_RPI_PIN_FILE="${WORK}/fixture.env" \
PUNAR_RPI_BOOTFS_BYTES=$((64 * 1024 * 1024)) \
    "${REPO_ROOT}/tools/build-raspberry-pi-bootfs.sh" \
    "${WORK}/firmware" "${WORK}/initramfs8" "${WORK}/root-modules" \
    "${WORK}/bootfs.img"

[ "$(stat -c %s "${WORK}/bootfs.img")" = "$((64 * 1024 * 1024))" ]
mtype -i "${WORK}/bootfs.img" ::/autoboot.txt \
    | grep -Fxq 'boot_partition=1'
mtype -i "${WORK}/bootfs.img" ::/autoboot.txt \
    | grep -Fxq 'boot_partition=3'
mtype -i "${WORK}/bootfs.img" ::/cmdline.txt \
    | grep -Fq 'root=PARTUUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea'
mtype -i "${WORK}/bootfs.img" ::/cmdline.txt | grep -Fq ' ro rootwait '
mtype -i "${WORK}/bootfs.img" ::/config.txt | grep -Fxq 'kernel=kernel8.img'
mtype -i "${WORK}/bootfs.img" ::/config.txt \
    | grep -Fxq 'initramfs initramfs8 followkernel'
mdir -i "${WORK}/bootfs.img" ::/overlays/vc4-kms-v3d-pi5.dtbo >/dev/null

printf 'tampered kernel\n' >> "${WORK}/firmware/boot/kernel8.img"
if PUNAR_RPI_PIN_FILE="${WORK}/fixture.env" \
    PUNAR_RPI_BOOTFS_BYTES=$((64 * 1024 * 1024)) \
    "${REPO_ROOT}/tools/build-raspberry-pi-bootfs.sh" \
    "${WORK}/firmware" "${WORK}/initramfs8" "${WORK}/root-modules" \
    "${WORK}/tampered.img" >/dev/null 2>&1; then
    echo "error: changed kernel was accepted" >&2
    exit 1
fi
[ ! -e "${WORK}/tampered.img" ]
printf 'fixture kernel\n' > "${WORK}/firmware/boot/kernel8.img"

cp -a "${WORK}/root-modules" "${WORK}/missing-index-modules"
rm "${WORK}/missing-index-modules/modules.alias.bin"
if PUNAR_RPI_PIN_FILE="${WORK}/fixture.env" \
    PUNAR_RPI_BOOTFS_BYTES=$((64 * 1024 * 1024)) \
    "${REPO_ROOT}/tools/build-raspberry-pi-bootfs.sh" \
    "${WORK}/firmware" "${WORK}/initramfs8" \
    "${WORK}/missing-index-modules" \
    "${WORK}/missing-index.img" >/dev/null 2>&1; then
    echo "error: root payload without a module alias index was accepted" >&2
    exit 1
fi
[ ! -e "${WORK}/missing-index.img" ]

printf 'root-only drift\n' >> "${WORK}/root-modules/fixture.ko"
if PUNAR_RPI_PIN_FILE="${WORK}/fixture.env" \
    PUNAR_RPI_BOOTFS_BYTES=$((64 * 1024 * 1024)) \
    "${REPO_ROOT}/tools/build-raspberry-pi-bootfs.sh" \
    "${WORK}/firmware" "${WORK}/initramfs8" "${WORK}/root-modules" \
    "${WORK}/module-drift.img" >/dev/null 2>&1; then
    echo "error: root payload with mismatched modules was accepted" >&2
    exit 1
fi
[ ! -e "${WORK}/module-drift.img" ]

echo "PUNAR_RPI_BOOTFS_TEST_OK"
