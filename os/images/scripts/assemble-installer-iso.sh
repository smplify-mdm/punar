#!/usr/bin/env bash
# Assemble Punar's offline UEFI installer from two pinned mkosi disk outputs.
# The release disk supplies slot A, its ordinary UKI, and the canonical root
# tree. The installer-profile disk supplies a UKI whose cmdline and module
# initrd are live-media capable. xorriso is the sole non-mkosi authoring step.
set -euo pipefail

usage() {
    echo "usage: $0 RELEASE_RAW INSTALLER_RAW VERSION OUTPUT_ISO GIT_SHA BUILT_AT CI_RUN_ID" >&2
    exit 2
}

[ "$#" -eq 7 ] || usage
RELEASE_RAW=$1
INSTALLER_RAW=$2
VERSION=$3
OUTPUT_ISO=$4
GIT_SHA=$5
BUILT_AT=$6
CI_RUN_ID=$7
OPTICAL_ESP_LABEL=PUNAR_BOOT

# FAT volume labels are limited to 11 characters. Keep this explicit so a
# branding change cannot make the native release job fail late in assembly.
[ "${#OPTICAL_ESP_LABEL}" -le 11 ] \
    || { echo "error: optical ESP label exceeds FAT's 11-character limit" >&2; exit 2; }

IMAGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${IMAGES_DIR}/../.." && pwd)"
# shellcheck source=/dev/null
. "${IMAGES_DIR}/snapshot.env"

[[ "${VERSION}" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$ ]] \
    || { echo "error: installer version must be YYYY.MM.DD.N" >&2; exit 2; }
[[ "${GIT_SHA}" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "error: git sha must be 40 lowercase hexadecimal characters" >&2; exit 2; }
[ -f "${RELEASE_RAW}" ] || { echo "error: release raw image is missing: ${RELEASE_RAW}" >&2; exit 2; }
[ -f "${INSTALLER_RAW}" ] || { echo "error: installer raw image is missing: ${INSTALLER_RAW}" >&2; exit 2; }
command -v xorriso >/dev/null || { echo "error: xorriso is not installed in the pinned builder" >&2; exit 2; }

RELEASE_TOOL="${IMAGES_DIR}/cache/cargo-target/release/punar-release-tool"
[ -x "${RELEASE_TOOL}" ] \
    || { echo "error: punar-release-tool was not built for ISO assembly" >&2; exit 2; }

WORK="$(mktemp -d /var/tmp/punar-installer-iso.XXXXXX)"
ROOT_LOOP=''
ESP_LOOP=''
cleanup() {
    mountpoint -q "${WORK}/esp" && umount "${WORK}/esp" || true
    mountpoint -q "${WORK}/root" && umount "${WORK}/root" || true
    if [ -n "${ESP_LOOP}" ]; then losetup --detach "${ESP_LOOP}" 2>/dev/null || true; fi
    if [ -n "${ROOT_LOOP}" ]; then losetup --detach "${ROOT_LOOP}" 2>/dev/null || true; fi
    rm -rf "${WORK}"
}
trap cleanup EXIT

for loop_minor in {0..63}; do
    [ -b "/dev/loop${loop_minor}" ] || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
done
[ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237

partition_bounds() {
    local disk=$1 number=$2
    sfdisk --dump "${disk}" | awk -F '[=,]' -v wanted="${number}" '
        /start=/ {
            count++
            if (count == wanted) {
                gsub(/ /, "", $2)
                gsub(/ /, "", $4)
                print $2, $4
                exit
            }
        }
    '
}

extract_uki() {
    local disk=$1 destination=$2
    local esp_start esp_sectors uki
    read -r esp_start esp_sectors < <(partition_bounds "${disk}" 1)
    [ -n "${esp_start}" ] && [ -n "${esp_sectors}" ] \
        || { echo "error: no ESP partition in ${disk}" >&2; exit 1; }
    ESP_LOOP="$(losetup --find --show --offset "$((esp_start * 512))" \
        --sizelimit "$((esp_sectors * 512))" "${disk}")"
    mkdir -p "${WORK}/esp"
    mount -o ro "${ESP_LOOP}" "${WORK}/esp"
    uki="$(find "${WORK}/esp/EFI/Linux" -maxdepth 1 -type f -name '*.efi' -print -quit)"
    [ -n "${uki}" ] || { echo "error: no UKI in ESP of ${disk}" >&2; exit 1; }
    cp "${uki}" "${destination}"
    umount "${WORK}/esp"
    losetup --detach "${ESP_LOOP}"
    ESP_LOOP=''
}

mkdir -p "${WORK}/root" "${WORK}/iso-root/punar/keys" "${WORK}/erofs-extract"

read -r root_start root_sectors < <(partition_bounds "${RELEASE_RAW}" 2)
[ -n "${root_start}" ] && [ -n "${root_sectors}" ] \
    || { echo "error: no root-A partition in ${RELEASE_RAW}" >&2; exit 1; }
ROOT_BYTES=$((root_sectors * 512))
SLOT_RAW="${WORK}/slot.raw"
dd if="${RELEASE_RAW}" of="${SLOT_RAW}" iflag=skip_bytes,count_bytes \
    skip="$((root_start * 512))" count="${ROOT_BYTES}" conv=sparse status=none
[ "$(blkid -p -s LABEL -o value "${SLOT_RAW}")" = PUNAR-ROOT-A ] \
    || { echo "error: release partition 2 is not PUNAR-ROOT-A" >&2; exit 1; }
e2fsck -fn "${SLOT_RAW}"

ROOT_LOOP="$(losetup --find --show --read-only "${SLOT_RAW}")"
mount -o ro "${ROOT_LOOP}" "${WORK}/root"
python3 "${REPO_ROOT}/tools/tree_manifest.py" \
    "${WORK}/root" "${WORK}/iso-root/punar/tree-manifest.json"
mkfs.erofs -zlz4hc -T1787184000 --all-time -L PUNAR-LIVE \
    "${WORK}/iso-root/punar/live.erofs" "${WORK}/root"
BOOTLOADER="${WORK}/root/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
[ -f "${BOOTLOADER}" ] || { echo "error: systemd-bootx64.efi is absent from release root" >&2; exit 1; }
cp "${BOOTLOADER}" "${WORK}/systemd-bootx64.efi"
umount "${WORK}/root"
losetup --detach "${ROOT_LOOP}"
ROOT_LOOP=''

fsck.erofs --extract="${WORK}/erofs-extract" "${WORK}/iso-root/punar/live.erofs"
python3 "${REPO_ROOT}/tools/tree_manifest.py" \
    "${WORK}/erofs-extract" "${WORK}/tree-manifest-erofs.json"
cmp "${WORK}/iso-root/punar/tree-manifest.json" "${WORK}/tree-manifest-erofs.json"

PAYLOAD_NAME="punar-desktop-x86_64-uefi-${VERSION}.slot.raw.zst"
SLOT_UKI_NAME="punar-desktop-x86_64-uefi-${VERSION}.uki.efi"
INSTALLER_UKI_NAME="punar-installer-${VERSION}-x86_64.efi"
zstd -T0 -10 --force --no-progress "${SLOT_RAW}" \
    -o "${WORK}/iso-root/punar/${PAYLOAD_NAME}"
extract_uki "${RELEASE_RAW}" "${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
extract_uki "${INSTALLER_RAW}" "${WORK}/${INSTALLER_UKI_NAME}"

# The live-root archive must already be inside the UKI built by mkosi/ukify.
# Reconstruct the deterministic member and require its exact bytes in the
# linked .initrd section before spending time on ISO authoring.
"${IMAGES_DIR}/scripts/build-installer-initrd.sh" \
    "${IMAGES_DIR}/installer-initrd" "${WORK}/expected-punar-live.initrd"
objcopy --dump-section ".initrd=${WORK}/installer.initrd" "${WORK}/${INSTALLER_UKI_NAME}"
python3 - "${WORK}/expected-punar-live.initrd" "${WORK}/installer.initrd" <<'PY'
import sys

expected = open(sys.argv[1], "rb").read()
actual = open(sys.argv[2], "rb").read()
occurrences = actual.count(expected)
if occurrences != 1:
    raise SystemExit(
        f"installer UKI contains the exact live-root initrd member {occurrences} times"
    )
PY
objcopy --dump-section ".cmdline=${WORK}/installer.cmdline" "${WORK}/${INSTALLER_UKI_NAME}"
tr -d '\000' < "${WORK}/installer.cmdline" > "${WORK}/installer.cmdline.txt"
grep -Fwq 'punar.live=1' "${WORK}/installer.cmdline.txt"
grep -Fwq 'rd.systemd.gpt_auto=0' "${WORK}/installer.cmdline.txt" \
    || { echo "error: installer UKI does not disable initrd GPT root discovery" >&2; exit 1; }
if grep -Fq 'root=PARTUUID=' "${WORK}/installer.cmdline.txt"; then
    echo "error: installer UKI embeds an installed-slot PARTUUID" >&2
    exit 1
fi
if grep -Eq '(^|[[:space:]])console=(ttyS|ttyAMA)' "${WORK}/installer.cmdline.txt"; then
    echo "error: installer UKI enables a serial kernel console" >&2
    exit 1
fi

PAYLOAD="${WORK}/iso-root/punar/${PAYLOAD_NAME}"
SLOT_UKI="${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
PAYLOAD_DIGEST="$(sha256sum "${PAYLOAD}" | cut -d' ' -f1)"
UNCOMPRESSED_DIGEST="$(sha256sum "${SLOT_RAW}" | cut -d' ' -f1)"
SLOT_UKI_DIGEST="$(sha256sum "${SLOT_UKI}" | cut -d' ' -f1)"
PAYLOAD_SIZE="$(stat -c %s "${PAYLOAD}")"
SLOT_UKI_SIZE="$(stat -c %s "${SLOT_UKI}")"

python3 - "${WORK}/iso-root/punar/release.json" <<PY
import json
import sys

document = {
    "schema_version": 1,
    "release_id": "punar-desktop-stable-x86_64-uefi-${VERSION}",
    "image_id": "punar-desktop",
    "architecture": "x86_64",
    "boot_platform": "uefi",
    "version": "${VERSION}",
    "channel": "stable",
    "snapshot_pin": "${PUNAR_SNAPSHOT_DATE}",
    "overlay_pin": None,
    "payload": {
        "filename": "${PAYLOAD_NAME}",
        "digest_sha256": "${PAYLOAD_DIGEST}",
        "size_bytes": ${PAYLOAD_SIZE},
        "uncompressed_digest_sha256": "${UNCOMPRESSED_DIGEST}",
        "uncompressed_size_bytes": ${ROOT_BYTES},
        "compression": "zstd",
    },
    "boot_artifact": {
        "kind": "uki",
        "filename": "${SLOT_UKI_NAME}",
        "digest_sha256": "${SLOT_UKI_DIGEST}",
        "size_bytes": ${SLOT_UKI_SIZE},
    },
    "min_from": None,
    "security": {"severity": "none", "advisory_ids": []},
    "provenance": {
        "git_commit": "${GIT_SHA}",
        "ci_run_id": "${CI_RUN_ID}",
        "builder_base_digest": "${PUNAR_BUILDER_BASE##*@}",
        "source_date_epoch": 1787184000,
        "built_at": "${BUILT_AT}",
    },
    "sbom": None,
}
with open(sys.argv[1], "w", encoding="utf-8", newline="\n") as stream:
    json.dump(document, stream, sort_keys=True, separators=(",", ":"))
    stream.write("\n")
PY

dd if=/dev/urandom of="${WORK}/release.seed" bs=32 count=1 status=none
chmod 0600 "${WORK}/release.seed"
"${RELEASE_TOOL}" public-key "${WORK}/release.seed" \
    "${WORK}/iso-root/punar/keys/ephemeral-ci.pub"
"${RELEASE_TOOL}" sign "${WORK}/release.seed" \
    "${WORK}/iso-root/punar/release.json" \
    "${WORK}/iso-root/punar/release.json.sig"
"${RELEASE_TOOL}" verify-release "${WORK}/iso-root/punar/keys" \
    "${WORK}/iso-root/punar/release.json" \
    "${WORK}/iso-root/punar/release.json.sig"
"${RELEASE_TOOL}" verify-artifact "${PAYLOAD}" "${PAYLOAD_DIGEST}" "${PAYLOAD_SIZE}"
"${RELEASE_TOOL}" verify-artifact "${SLOT_UKI}" "${SLOT_UKI_DIGEST}" "${SLOT_UKI_SIZE}"

# Put the exact installer UKI in the ISO filesystem. Optical firmware first
# loads a compact GRUB standalone from a standards-sized El Torito FAT image;
# GRUB then chainloads this UKI. Keeping the 100+ MiB UKI outside the El Torito
# image avoids the zero/overflowed 16-bit load-sector count rejected by OVMF.
mkdir -p "${WORK}/iso-root/EFI/Linux" "${WORK}/iso-root/boot"
cp "${WORK}/${INSTALLER_UKI_NAME}" \
    "${WORK}/iso-root/EFI/Linux/${INSTALLER_UKI_NAME}"
cat > "${WORK}/grub.cfg" <<EOF
set timeout=0
set default=0

menuentry "Punar installer" {
    search --no-floppy --file /EFI/Linux/${INSTALLER_UKI_NAME} --set=root
    chainloader /EFI/Linux/${INSTALLER_UKI_NAME}
    boot
}
EOF
grub-mkstandalone \
    --format=x86_64-efi \
    --output="${WORK}/optical-bootx64.efi" \
    --install-modules="part_gpt part_msdos fat iso9660 search search_fs_file chain" \
    --modules="part_gpt part_msdos fat iso9660 search search_fs_file chain" \
    --locales= \
    --fonts= \
    "boot/grub/grub.cfg=${WORK}/grub.cfg"

OPTICAL_ESP_BYTES=$((31 * 1024 * 1024))
OPTICAL_ESP_HEADROOM_BYTES=$((4 * 1024 * 1024))
OPTICAL_LOADER_SIZE="$(stat -c %s "${WORK}/optical-bootx64.efi")"
# El Torito's load-size field is 16-bit and counts 512-byte sectors. A 32 MiB
# image therefore wraps to zero and is rejected by OVMF. Refuse loader growth
# instead of silently crossing that format boundary.
if [ $((OPTICAL_ESP_BYTES % 512)) -ne 0 ] \
    || [ $((OPTICAL_ESP_BYTES / 512)) -gt 65535 ]; then
    echo "error: optical ESP exceeds the El Torito load-sector limit" >&2
    exit 1
fi
if [ $((OPTICAL_LOADER_SIZE + OPTICAL_ESP_HEADROOM_BYTES)) -gt "${OPTICAL_ESP_BYTES}" ]; then
    echo "error: optical UEFI loader no longer fits the bounded El Torito image" >&2
    exit 1
fi
truncate --size "${OPTICAL_ESP_BYTES}" "${WORK}/iso-root/boot/efi.img"
mkfs.vfat -F 32 -n "${OPTICAL_ESP_LABEL}" "${WORK}/iso-root/boot/efi.img"
mmd -i "${WORK}/iso-root/boot/efi.img" ::/EFI ::/EFI/BOOT
mcopy -i "${WORK}/iso-root/boot/efi.img" \
    "${WORK}/optical-bootx64.efi" ::/EFI/BOOT/BOOTX64.EFI

# The appended GPT ESP remains the UEFI removable-media boot partition when
# the same ISO bytes are written to USB or attached as a raw drive.
INSTALLER_UKI_SIZE="$(stat -c %s "${WORK}/${INSTALLER_UKI_NAME}")"
ESP_BYTES=$((INSTALLER_UKI_SIZE + 64 * 1024 * 1024))
if [ "${ESP_BYTES}" -lt $((256 * 1024 * 1024)) ]; then ESP_BYTES=$((256 * 1024 * 1024)); fi
ESP_BYTES=$((((ESP_BYTES + 1024 * 1024 - 1) / (1024 * 1024)) * 1024 * 1024))
truncate --size "${ESP_BYTES}" "${WORK}/esp.img"
mkfs.vfat -F 32 -n PUNAR_ESP "${WORK}/esp.img"
mmd -i "${WORK}/esp.img" ::/EFI ::/EFI/BOOT ::/EFI/Linux
mcopy -i "${WORK}/esp.img" "${WORK}/systemd-bootx64.efi" ::/EFI/BOOT/BOOTX64.EFI
mcopy -i "${WORK}/esp.img" "${WORK}/${INSTALLER_UKI_NAME}" "::/EFI/Linux/${INSTALLER_UKI_NAME}"

TMP_ISO="${OUTPUT_ISO}.tmp"
rm -f "${TMP_ISO}"
xorriso -as mkisofs \
    -iso-level 3 -full-iso9660-filenames -rational-rock \
    -volid PUNAR_INSTALL \
    -appended_part_as_gpt \
    -append_partition 2 C12A7328-F81F-11D2-BA4B-00A0C93EC93B "${WORK}/esp.img" \
    -eltorito-alt-boot \
    -e boot/efi.img \
    -no-emul-boot \
    -o "${TMP_ISO}" "${WORK}/iso-root"
mv -f "${TMP_ISO}" "${OUTPUT_ISO}"

echo "PUNAR_INSTALLER_ISO_OK version=${VERSION} bytes=$(stat -c %s "${OUTPUT_ISO}") sha256=$(sha256sum "${OUTPUT_ISO}" | cut -d' ' -f1)"
