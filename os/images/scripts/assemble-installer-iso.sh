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
ROOT_A_PARTUUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea
ROOT_B_PARTUUID=2b1b91a9-cf2c-4e9c-a723-5ec997971662
# UUIDv5(NAMESPACE_URL, "https://punar.org/filesystem/root-b"). This is the
# same independently bound slot-B filesystem identity used by update bundles.
ROOT_B_FS_UUID=724e1a3b-d966-54b7-9a97-8886985eee18

# FAT volume labels are limited to 11 characters. Keep this explicit so a
# branding change cannot make the native release job fail late in assembly.
[ "${#OPTICAL_ESP_LABEL}" -le 11 ] \
    || { echo "error: optical ESP label exceeds FAT's 11-character limit" >&2; exit 2; }

IMAGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "${IMAGES_DIR}/../.." && pwd)"
# shellcheck source=/dev/null
. "${IMAGES_DIR}/snapshot.env"

# The Arch release lane remains the default caller. Migration lanes may supply
# their own authenticated snapshot, builder image and native release-tool
# location without copying the security-sensitive ISO assembler.
RELEASE_SNAPSHOT_PIN="${PUNAR_RELEASE_SNAPSHOT_PIN:-${PUNAR_SNAPSHOT_DATE}}"
RELEASE_BUILDER_BASE="${PUNAR_RELEASE_BUILDER_BASE:-${PUNAR_BUILDER_BASE}}"
RELEASE_SOURCE_DATE_EPOCH="${PUNAR_RELEASE_SOURCE_DATE_EPOCH:-1787184000}"
RELEASE_TOOL="${PUNAR_RELEASE_TOOL:-${IMAGES_DIR}/cache/cargo-target/release/punar-release-tool}"
RELEASE_BUILDER_DIGEST="${RELEASE_BUILDER_BASE##*@}"

[[ "${VERSION}" =~ ^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.[0-9]+$ ]] \
    || { echo "error: installer version must be YYYY.MM.DD.N" >&2; exit 2; }
[[ "${GIT_SHA}" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "error: git sha must be 40 lowercase hexadecimal characters" >&2; exit 2; }
[ -f "${RELEASE_RAW}" ] || { echo "error: release raw image is missing: ${RELEASE_RAW}" >&2; exit 2; }
[ -f "${INSTALLER_RAW}" ] || { echo "error: installer raw image is missing: ${INSTALLER_RAW}" >&2; exit 2; }
command -v xorriso >/dev/null || { echo "error: xorriso is not installed in the pinned builder" >&2; exit 2; }
[[ "${RELEASE_SNAPSHOT_PIN}" =~ ^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$ ]] \
    || { echo "error: release snapshot pin is invalid" >&2; exit 2; }
[[ "${RELEASE_SOURCE_DATE_EPOCH}" =~ ^[0-9]+$ ]] \
    || { echo "error: release source-date epoch is invalid" >&2; exit 2; }
[[ "${RELEASE_BUILDER_DIGEST}" =~ ^sha256:[0-9a-f]{64}$ ]] \
    || { echo "error: release builder image is not digest-pinned" >&2; exit 2; }
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

# The dual-slot media carries two compressed 8 GiB root payloads, and xorriso
# holds the ISO sources and the finished ISO at once. Refuse to start on a
# filesystem that cannot hold that peak instead of failing after the slot
# copies; the stage lines record the real headroom so this floor can be
# calibrated from a canonical run rather than guessed.
ISO_ASSEMBLY_MIN_FREE_BYTES=$((12 * 1024 * 1024 * 1024))
free_bytes() {
    df --output=avail -B1 "$1" | tail -n 1 | tr -d '[:space:]'
}
report_free_space() {
    echo "installer-iso disk: stage=$1 work_available_bytes=$(free_bytes "${WORK}") output_available_bytes=$(free_bytes "$(dirname "${OUTPUT_ISO}")")"
}
report_free_space start
if [ "$(free_bytes "${WORK}")" -lt "${ISO_ASSEMBLY_MIN_FREE_BYTES}" ]; then
    echo "error: ${WORK} has fewer than ${ISO_ASSEMBLY_MIN_FREE_BYTES} bytes free; dual-slot ISO assembly needs that peak" >&2
    exit 1
fi

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

# objcopy rewrites PE sections without preserving an Authenticode signature.
# The current lane intentionally has simulated Secure Boot, so refuse a signed
# input instead of quietly producing a recovery UKI whose firmware signature
# has been invalidated. Production must derive both sections before signing.
refuse_authenticode_signed_uki() {
    python3 - "$1" <<'PY'
import struct
import sys

path = sys.argv[1]
with open(path, "rb") as stream:
    dos = stream.read(64)
    if len(dos) != 64 or dos[:2] != b"MZ":
        raise SystemExit("release UKI has no bounded DOS header")
    pe = struct.unpack_from("<I", dos, 60)[0]
    stream.seek(pe)
    header = stream.read(24)
    if len(header) != 24 or header[:4] != b"PE\0\0":
        raise SystemExit("release UKI has no bounded PE header")
    optional_size = struct.unpack_from("<H", header, 20)[0]
    optional = stream.read(optional_size)
if len(optional) != optional_size:
    raise SystemExit("release UKI has a truncated PE optional header")
magic = struct.unpack_from("<H", optional, 0)[0]
if magic == 0x10B:
    security = 128
elif magic == 0x20B:
    security = 144
else:
    raise SystemExit("release UKI has an unsupported PE optional-header magic")
if security + 8 > len(optional):
    raise SystemExit("release UKI has no bounded Authenticode directory")
certificate_offset, certificate_size = struct.unpack_from("<II", optional, security)
if certificate_offset or certificate_size:
    raise SystemExit(
        "release UKI is Authenticode-signed; objcopy section mutation would invalidate it"
    )
PY
}

mkdir -p "${WORK}/root" "${WORK}/iso-root/punar/keys" "${WORK}/erofs-extract"

read -r root_start root_sectors < <(partition_bounds "${RELEASE_RAW}" 2)
[ -n "${root_start}" ] && [ -n "${root_sectors}" ] \
    || { echo "error: no root-A partition in ${RELEASE_RAW}" >&2; exit 1; }
ROOT_BYTES=$((root_sectors * 512))
SLOT_RAW="${WORK}/slot.raw"
SLOT_B_RAW="${WORK}/slot-b.raw"
dd if="${RELEASE_RAW}" of="${SLOT_RAW}" iflag=skip_bytes,count_bytes \
    skip="$((root_start * 512))" count="${ROOT_BYTES}" conv=sparse status=none
[ "$(blkid -p -s LABEL -o value "${SLOT_RAW}")" = PUNAR-ROOT-A ] \
    || { echo "error: release partition 2 is not PUNAR-ROOT-A" >&2; exit 1; }
e2fsck -fn "${SLOT_RAW}"

ROOT_LOOP="$(losetup --find --show --read-only "${SLOT_RAW}")"
mount -o ro "${ROOT_LOOP}" "${WORK}/root"
python3 "${REPO_ROOT}/tools/tree_manifest.py" \
    "${WORK}/root" "${WORK}/iso-root/punar/tree-manifest.json"
mkfs.erofs -zlz4hc -T"${RELEASE_SOURCE_DATE_EPOCH}" --all-time -L PUNAR-LIVE \
    "${WORK}/iso-root/punar/live.erofs" "${WORK}/root"
BOOTLOADER="${WORK}/root/usr/lib/systemd/boot/efi/systemd-bootx64.efi"
[ -f "${BOOTLOADER}" ] || { echo "error: systemd-bootx64.efi is absent from release root" >&2; exit 1; }
cp "${BOOTLOADER}" "${WORK}/systemd-bootx64.efi"
umount "${WORK}/root"
losetup --detach "${ROOT_LOOP}"
ROOT_LOOP=''

# A fresh install must have a bootable recovery floor before its first update.
# Derive B at image-assembly time (never on the target device): preserve the
# release tree, replace the root filesystem identity/fstab binding, and verify
# the resulting ext4 image before it enters signed release metadata.
cp --sparse=always "${SLOT_RAW}" "${SLOT_B_RAW}"
ROOT_A_FS_UUID="$(blkid -p -s UUID -o value "${SLOT_RAW}")"
[ -n "${ROOT_A_FS_UUID}" ] \
    || { echo "error: slot A has no ext4 filesystem UUID" >&2; exit 1; }
ROOT_LOOP="$(losetup --find --show "${SLOT_B_RAW}")"
mount "${ROOT_LOOP}" "${WORK}/root"
grep -Fqi "UUID=${ROOT_A_FS_UUID} / ext4" "${WORK}/root/etc/fstab" \
    || { echo "error: slot A fstab does not bind its ext4 filesystem UUID" >&2; exit 1; }
sed -i "s/${ROOT_A_FS_UUID}/${ROOT_B_FS_UUID}/g" "${WORK}/root/etc/fstab"
grep -Fqi "UUID=${ROOT_B_FS_UUID} / ext4" "${WORK}/root/etc/fstab" \
    || { echo "error: could not bind recovery slot B in fstab" >&2; exit 1; }
sync -f "${WORK}/root/etc/fstab"
umount "${WORK}/root"
losetup --detach "${ROOT_LOOP}"
ROOT_LOOP=''
tune2fs -U "${ROOT_B_FS_UUID}" -L PUNAR-ROOT-B "${SLOT_B_RAW}" >/dev/null
[ "$(blkid -p -s UUID -o value "${SLOT_B_RAW}")" = "${ROOT_B_FS_UUID}" ] \
    || { echo "error: recovery slot B has the wrong filesystem UUID" >&2; exit 1; }
[ "$(blkid -p -s LABEL -o value "${SLOT_B_RAW}")" = PUNAR-ROOT-B ] \
    || { echo "error: recovery slot B has the wrong filesystem label" >&2; exit 1; }
e2fsck -fn "${SLOT_B_RAW}"
ROOT_LOOP="$(losetup --find --show --read-only "${SLOT_B_RAW}")"
mount -o ro,noload "${ROOT_LOOP}" "${WORK}/root"
python3 - "${WORK}/root/etc/fstab" "${ROOT_B_FS_UUID}" <<'PY'
import sys

path, uuid = sys.argv[1:]
roots = []
with open(path, "r", encoding="utf-8") as stream:
    for raw in stream:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "/":
            roots.append((fields[0], fields[2]))
if roots != [(f"UUID={uuid}", "ext4")]:
    raise SystemExit(f"recovery fstab has unsafe root binding: {roots!r}")
PY
umount "${WORK}/root"
losetup --detach "${ROOT_LOOP}"
ROOT_LOOP=''

PAYLOAD_NAME="punar-desktop-x86_64-uefi-${VERSION}.slot.raw.zst"
SLOT_UKI_NAME="punar-desktop-x86_64-uefi-${VERSION}.uki.efi"
PAYLOAD_B_NAME="punar-desktop-x86_64-uefi-${VERSION}.slot-b.raw.zst"
SLOT_UKI_B_NAME="punar-desktop-x86_64-uefi-${VERSION}.slot-b.uki.efi"
INSTALLER_UKI_NAME="punar-installer-${VERSION}-x86_64.efi"
PAYLOAD="${WORK}/iso-root/punar/${PAYLOAD_NAME}"
PAYLOAD_B="${WORK}/iso-root/punar/${PAYLOAD_B_NAME}"

# Hash each raw filesystem before compression, verify the durable compressed
# stream expands to those exact bytes, then release the 8 GiB temporary as
# soon as correctness permits. Never carry both raws into EROFS extraction.
UNCOMPRESSED_DIGEST="$(sha256sum "${SLOT_RAW}" | cut -d' ' -f1)"
UNCOMPRESSED_B_DIGEST="$(sha256sum "${SLOT_B_RAW}" | cut -d' ' -f1)"
[ "${UNCOMPRESSED_DIGEST}" != "${UNCOMPRESSED_B_DIGEST}" ] \
    || { echo "error: slot B is an unsafe byte clone of slot A" >&2; exit 1; }
zstd -T0 -10 --force --no-progress "${SLOT_RAW}" \
    -o "${PAYLOAD}"
sync -f "${PAYLOAD}"
zstd --test --no-progress "${PAYLOAD}"
[ "$(zstd --decompress --stdout --no-progress "${PAYLOAD}" | sha256sum | cut -d' ' -f1)" = \
    "${UNCOMPRESSED_DIGEST}" ] \
    || { echo "error: durable slot-A payload does not expand to its source digest" >&2; exit 1; }
PAYLOAD_DIGEST="$(sha256sum "${PAYLOAD}" | cut -d' ' -f1)"
PAYLOAD_SIZE="$(stat -c %s "${PAYLOAD}")"
rm -f "${SLOT_RAW}"

zstd -T0 -10 --force --no-progress "${SLOT_B_RAW}" \
    -o "${PAYLOAD_B}"
sync -f "${PAYLOAD_B}"
zstd --test --no-progress "${PAYLOAD_B}"
[ "$(zstd --decompress --stdout --no-progress "${PAYLOAD_B}" | sha256sum | cut -d' ' -f1)" = \
    "${UNCOMPRESSED_B_DIGEST}" ] \
    || { echo "error: durable slot-B payload does not expand to its source digest" >&2; exit 1; }
PAYLOAD_B_DIGEST="$(sha256sum "${PAYLOAD_B}" | cut -d' ' -f1)"
PAYLOAD_B_SIZE="$(stat -c %s "${PAYLOAD_B}")"
rm -f "${SLOT_B_RAW}"
report_free_space payloads-compressed

fsck.erofs --extract="${WORK}/erofs-extract" "${WORK}/iso-root/punar/live.erofs"
python3 "${REPO_ROOT}/tools/tree_manifest.py" \
    "${WORK}/erofs-extract" "${WORK}/tree-manifest-erofs.json"
cmp "${WORK}/iso-root/punar/tree-manifest.json" "${WORK}/tree-manifest-erofs.json"
rm -rf "${WORK}/erofs-extract"
rm -f "${WORK}/tree-manifest-erofs.json"

extract_uki "${RELEASE_RAW}" "${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
refuse_authenticode_signed_uki "${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
cp "${WORK}/iso-root/punar/${SLOT_UKI_NAME}" \
    "${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}"
# Secure Boot is explicitly SIMULATED for this build. Both UKIs are bound by
# the signed release manifest; when production UKI signing lands, this build-
# time derivation must be followed by that signer rather than moved on-device.
objcopy --dump-section ".cmdline=${WORK}/slot-a.cmdline" \
    "${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
tr -d '\000' < "${WORK}/slot-a.cmdline" > "${WORK}/slot-a.cmdline.txt"
[ "$(tr ' ' '\n' < "${WORK}/slot-a.cmdline.txt" | grep -c '^root=PARTUUID=')" -eq 1 ] \
    || { echo "error: slot-A UKI must contain exactly one root PARTUUID" >&2; exit 1; }
tr ' ' '\n' < "${WORK}/slot-a.cmdline.txt" \
    | grep -Fqx "root=PARTUUID=${ROOT_A_PARTUUID}" \
    || { echo "error: slot-A UKI does not bind the fixed slot-A PARTUUID" >&2; exit 1; }
sed "s/${ROOT_A_PARTUUID}/${ROOT_B_PARTUUID}/g" \
    "${WORK}/slot-a.cmdline.txt" > "${WORK}/slot-b.cmdline"
printf '\0' >> "${WORK}/slot-b.cmdline"
objcopy --update-section ".cmdline=${WORK}/slot-b.cmdline" \
    "${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}"
# Give the permanent fallback a visibly distinct boot-menu identity. This is
# part of the B artifact before its manifest digest is computed. Production
# Secure Boot must likewise derive both mutable UKI sections before signing.
objcopy --dump-section ".osrel=${WORK}/slot-a.osrel" \
    "${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
python3 - "${WORK}/slot-a.osrel" "${WORK}/slot-b.osrel" "${VERSION}" <<'PY'
import sys

source, destination, version = sys.argv[1:]
raw = open(source, "rb").read()
text = raw.rstrip(b"\0").decode("utf-8")
lines = text.splitlines()
matches = [index for index, line in enumerate(lines) if line.startswith("PRETTY_NAME=")]
if len(matches) != 1:
    raise SystemExit("slot-A UKI os-release does not contain exactly one PRETTY_NAME")
lines[matches[0]] = f'PRETTY_NAME="Punar recovery {version}"'
with open(destination, "wb") as stream:
    stream.write(("\n".join(lines) + "\n").encode("utf-8"))
    stream.write(b"\0")
PY
objcopy --update-section ".osrel=${WORK}/slot-b.osrel" \
    "${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}"
# objcopy --update-section grows .osrel/.cmdline in place. The EFI loader
# maps sections by VirtualAddress, so a grown section that crossed into its
# successor's address range would be silently overlaid at boot. Require the
# derived artifact's section table to stay strictly non-overlapping and to
# keep A's section names, since nothing boots the recovery UKI before I17.
check_uki_section_layout() {
    python3 - "$1" "$2" <<'PY'
import struct
import sys


def sections(path):
    with open(path, "rb") as stream:
        dos = stream.read(64)
        pe = struct.unpack_from("<I", dos, 60)[0]
        stream.seek(pe)
        header = stream.read(24)
        if header[:4] != b"PE\0\0":
            raise SystemExit(f"{path}: no PE signature")
        count = struct.unpack_from("<H", header, 6)[0]
        optional_size = struct.unpack_from("<H", header, 20)[0]
        optional = stream.read(optional_size)
        alignment = struct.unpack_from("<I", optional, 32)[0]
        table = []
        for _ in range(count):
            entry = stream.read(40)
            name = entry[:8].split(b"\0", 1)[0].decode("ascii", "replace")
            virtual_size, virtual_address, raw_size = struct.unpack_from("<III", entry, 8)
            table.append((name, virtual_address, virtual_size, raw_size))
    return alignment, table


derived_path, source_path = sys.argv[1:]
alignment, derived = sections(derived_path)
_, source = sections(source_path)
if [name for name, *_ in derived] != [name for name, *_ in source]:
    raise SystemExit("recovery UKI section names differ from the slot-A UKI")
ordered = sorted(derived, key=lambda section: section[1])
for (name, address, virtual_size, raw_size), successor in zip(ordered, ordered[1:]):
    end = address + max(virtual_size, raw_size)
    if alignment:
        end = (end + alignment - 1) // alignment * alignment
    if end > successor[1]:
        raise SystemExit(
            f"recovery UKI section {name} ends at {end:#x}, overlapping {successor[0]} at {successor[1]:#x}"
        )
PY
}
check_uki_section_layout "${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}" \
    "${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
objcopy --dump-section ".cmdline=${WORK}/slot-b-verified.cmdline" \
    "${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}"
tr -d '\000' < "${WORK}/slot-b-verified.cmdline" \
    | tr ' ' '\n' | grep -Fqx "root=PARTUUID=${ROOT_B_PARTUUID}" \
    || { echo "error: recovery UKI does not bind the fixed slot-B PARTUUID" >&2; exit 1; }
objcopy --dump-section ".osrel=${WORK}/slot-b-verified.osrel" \
    "${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}"
tr -d '\000' < "${WORK}/slot-b-verified.osrel" \
    | grep -Fxq "PRETTY_NAME=\"Punar recovery ${VERSION}\"" \
    || { echo "error: recovery UKI does not carry its distinct boot title" >&2; exit 1; }
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

SLOT_UKI="${WORK}/iso-root/punar/${SLOT_UKI_NAME}"
SLOT_UKI_B="${WORK}/iso-root/punar/${SLOT_UKI_B_NAME}"
SLOT_UKI_DIGEST="$(sha256sum "${SLOT_UKI}" | cut -d' ' -f1)"
SLOT_UKI_B_DIGEST="$(sha256sum "${SLOT_UKI_B}" | cut -d' ' -f1)"
SLOT_UKI_SIZE="$(stat -c %s "${SLOT_UKI}")"
SLOT_UKI_B_SIZE="$(stat -c %s "${SLOT_UKI_B}")"
[ "${SLOT_UKI_DIGEST}" != "${SLOT_UKI_B_DIGEST}" ] \
    || { echo "error: recovery UKI is not independently bound to slot B" >&2; exit 1; }

python3 - \
    "${WORK}/iso-root/punar/release.json" \
    "${VERSION}" \
    "${PAYLOAD_NAME}" "${PAYLOAD_DIGEST}" "${PAYLOAD_SIZE}" \
    "${UNCOMPRESSED_DIGEST}" "${ROOT_BYTES}" \
    "${SLOT_UKI_NAME}" "${SLOT_UKI_DIGEST}" "${SLOT_UKI_SIZE}" \
    "${PAYLOAD_B_NAME}" "${PAYLOAD_B_DIGEST}" "${PAYLOAD_B_SIZE}" \
    "${UNCOMPRESSED_B_DIGEST}" \
    "${SLOT_UKI_B_NAME}" "${SLOT_UKI_B_DIGEST}" "${SLOT_UKI_B_SIZE}" \
    "${RELEASE_SNAPSHOT_PIN}" "${GIT_SHA}" "${CI_RUN_ID}" \
    "${RELEASE_BUILDER_DIGEST}" "${RELEASE_SOURCE_DATE_EPOCH}" \
    "${BUILT_AT}" <<'PY'
import json
import sys

(
    output_path,
    version,
    payload_name,
    payload_digest,
    payload_size,
    uncompressed_digest,
    root_bytes,
    slot_uki_name,
    slot_uki_digest,
    slot_uki_size,
    payload_b_name,
    payload_b_digest,
    payload_b_size,
    uncompressed_b_digest,
    slot_uki_b_name,
    slot_uki_b_digest,
    slot_uki_b_size,
    snapshot_pin,
    git_sha,
    ci_run_id,
    builder_digest,
    source_date_epoch,
    built_at,
) = sys.argv[1:]

document = {
    "schema_version": 1,
    "release_id": f"punar-desktop-stable-x86_64-uefi-{version}",
    "image_id": "punar-desktop",
    "architecture": "x86_64",
    "boot_platform": "uefi",
    "version": version,
    "channel": "stable",
    "snapshot_pin": snapshot_pin,
    "overlay_pin": None,
    "payload": {
        "filename": payload_name,
        "digest_sha256": payload_digest,
        "size_bytes": int(payload_size),
        "uncompressed_digest_sha256": uncompressed_digest,
        "uncompressed_size_bytes": int(root_bytes),
        "compression": "zstd",
    },
    "boot_artifact": {
        "kind": "uki",
        "filename": slot_uki_name,
        "digest_sha256": slot_uki_digest,
        "size_bytes": int(slot_uki_size),
    },
    "uefi_slots": {
        "a": {
            "payload": {
                "filename": payload_name,
                "digest_sha256": payload_digest,
                "size_bytes": int(payload_size),
                "uncompressed_digest_sha256": uncompressed_digest,
                "uncompressed_size_bytes": int(root_bytes),
                "compression": "zstd",
            },
            "boot_artifact": {
                "kind": "uki",
                "filename": slot_uki_name,
                "digest_sha256": slot_uki_digest,
                "size_bytes": int(slot_uki_size),
            },
        },
        "b": {
            "payload": {
                "filename": payload_b_name,
                "digest_sha256": payload_b_digest,
                "size_bytes": int(payload_b_size),
                "uncompressed_digest_sha256": uncompressed_b_digest,
                "uncompressed_size_bytes": int(root_bytes),
                "compression": "zstd",
            },
            "boot_artifact": {
                "kind": "uki",
                "filename": slot_uki_b_name,
                "digest_sha256": slot_uki_b_digest,
                "size_bytes": int(slot_uki_b_size),
            },
        },
    },
    "min_from": None,
    "security": {"severity": "none", "advisory_ids": []},
    "provenance": {
        "git_commit": git_sha,
        "ci_run_id": ci_run_id,
        "builder_base_digest": builder_digest,
        "source_date_epoch": int(source_date_epoch),
        "built_at": built_at,
    },
    "sbom": None,
}
with open(output_path, "w", encoding="utf-8", newline="\n") as stream:
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
"${RELEASE_TOOL}" verify-artifact "${PAYLOAD_B}" "${PAYLOAD_B_DIGEST}" "${PAYLOAD_B_SIZE}"
"${RELEASE_TOOL}" verify-artifact "${SLOT_UKI_B}" "${SLOT_UKI_B_DIGEST}" "${SLOT_UKI_B_SIZE}"

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
    --install-modules="part_gpt part_msdos fat iso9660 search search_fs_file chain normal configfile" \
    --modules="part_gpt part_msdos fat iso9660 search search_fs_file chain normal configfile" \
    --locales= \
    --fonts= \
    "/boot/grub/grub.cfg=${WORK}/grub.cfg"

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
# FAT32 requires more clusters than this bounded El Torito image can contain;
# OVMF rejects that undersized filesystem. FAT16 is valid for this removable
# optical boot image and keeps the separately appended disk ESP on FAT32.
mkfs.vfat -F 16 -n "${OPTICAL_ESP_LABEL}" "${WORK}/iso-root/boot/efi.img"
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
report_free_space before-xorriso
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
report_free_space finished

echo "PUNAR_INSTALLER_ISO_OK version=${VERSION} bytes=$(stat -c %s "${OUTPUT_ISO}") sha256=$(sha256sum "${OUTPUT_ISO}" | cut -d' ' -f1)"
