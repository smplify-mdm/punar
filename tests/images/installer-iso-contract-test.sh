#!/usr/bin/env bash
# Verify a completed Punar hybrid installer artifact without trusting assembly
# intermediates. This is the structural I01-I04 gate; bootability is exercised
# separately by installer-boot-test.sh in both optical and raw-drive forms.
set -euo pipefail

usage() {
    echo "usage: $0 INSTALLER_ISO [PUNAR_RELEASE_TOOL]" >&2
    exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage
ISO=$1
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RELEASE_TOOL=${2:-"${REPO_ROOT}/os/images/cache/cargo-target/release/punar-release-tool"}

fail() {
    echo "installer-iso-contract-test: FAIL: $*" >&2
    exit 1
}

[ -f "${ISO}" ] || fail "installer ISO is missing: ${ISO}"
[ -x "${RELEASE_TOOL}" ] || fail "release verifier is missing: ${RELEASE_TOOL}"
for command in xorriso sfdisk mcopy objcopy fsck.erofs zstd blkid e2fsck debugfs; do
    command -v "${command}" >/dev/null || fail "required command is missing: ${command}"
done

WORK="$(mktemp -d)"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

xorriso -indev "${ISO}" -pvd_info > "${WORK}/pvd.txt" 2>&1
PVD_VOLUME_ID="$(awk -F ':' '
    /^Volume Id[[:space:]]*:/ {
        value = $2
        sub(/^[[:space:]]*/, "", value)
        sub(/[[:space:]]*$/, "", value)
        print value
        exit
    }
' "${WORK}/pvd.txt")"
[ "${PVD_VOLUME_ID}" = PUNAR_INSTALL ] \
    || fail "ISO9660 volume label is not PUNAR_INSTALL (observed: ${PVD_VOLUME_ID:-missing})"
xorriso -indev "${ISO}" -report_el_torito plain > "${WORK}/eltorito.txt" 2>&1
grep -Eq 'UEFI|EFI' "${WORK}/eltorito.txt" \
    || fail 'no UEFI El Torito boot image was reported'
grep -Eq 'El Torito boot img :[[:space:]]+1[[:space:]]+UEFI[[:space:]]+y[[:space:]]+none[[:space:]]+0x[0-9A-Fa-f]+[[:space:]]+0x[0-9A-Fa-f]+[[:space:]]+[1-9][0-9]*[[:space:]]+[0-9]+' \
    "${WORK}/eltorito.txt" \
    || fail 'UEFI El Torito image has a zero/invalid load-sector count'
grep -Fq 'El Torito img path :   1  /boot/efi.img' "${WORK}/eltorito.txt" \
    || fail 'UEFI El Torito image is not the compact optical ESP'

mkdir -p "${WORK}/iso" "${WORK}/erofs-root"
xorriso -osirrox on -indev "${ISO}" -extract /punar "${WORK}/iso/punar" \
    > "${WORK}/extract.txt" 2>&1
for file in release.json release.json.sig tree-manifest.json live.erofs; do
    [ -f "${WORK}/iso/punar/${file}" ] || fail "ISO is missing /punar/${file}"
done
[ -d "${WORK}/iso/punar/keys" ] || fail 'ISO is missing /punar/keys'

mapfile -t ARTIFACT_FIELDS < <(
    python3 - "${WORK}/iso/punar/release.json" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    doc = json.load(stream)

required = {
    "schema_version": 1,
    "image_id": "punar-desktop",
    "architecture": "x86_64",
    "boot_platform": "uefi",
    "channel": "stable",
}
for key, expected in required.items():
    if doc.get(key) != expected:
        raise SystemExit(f"release metadata {key!r} is not {expected!r}")
if not re.fullmatch(r"\d{4}\.\d{2}\.\d{2}\.\d+", doc.get("version", "")):
    raise SystemExit("release metadata has an invalid version")

slots = doc.get("uefi_slots")
if not isinstance(slots, dict) or set(slots) != {"a", "b"}:
    raise SystemExit("UEFI installer release does not carry exactly two slot pairs")
slot_a = slots["a"]
slot_b = slots["b"]
if doc["payload"] != slot_a["payload"] or doc["boot_artifact"] != slot_a["boot_artifact"]:
    raise SystemExit("top-level install artifacts are not the signed slot-A pair")
payload = slot_a["payload"]
boot = slot_a["boot_artifact"]
payload_b = slot_b["payload"]
boot_b = slot_b["boot_artifact"]
values = [
    doc["version"], payload["filename"], payload["digest_sha256"],
    str(payload["size_bytes"]), payload["uncompressed_digest_sha256"],
    str(payload["uncompressed_size_bytes"]), boot["filename"],
    boot["digest_sha256"], str(boot["size_bytes"]), payload_b["filename"],
    payload_b["digest_sha256"], str(payload_b["size_bytes"]),
    payload_b["uncompressed_digest_sha256"],
    str(payload_b["uncompressed_size_bytes"]), boot_b["filename"],
    boot_b["digest_sha256"], str(boot_b["size_bytes"]),
]
if any(any(char.isspace() for char in value) for value in values):
    raise SystemExit("release metadata artifact fields contain whitespace")
print("\n".join(values))
PY
)
[ "${#ARTIFACT_FIELDS[@]}" -eq 17 ] \
    || fail "release metadata returned ${#ARTIFACT_FIELDS[@]} artifact fields, expected 17"
VERSION=${ARTIFACT_FIELDS[0]}
PAYLOAD=${ARTIFACT_FIELDS[1]}
PAYLOAD_SHA=${ARTIFACT_FIELDS[2]}
PAYLOAD_SIZE=${ARTIFACT_FIELDS[3]}
RAW_SHA=${ARTIFACT_FIELDS[4]}
RAW_SIZE=${ARTIFACT_FIELDS[5]}
SLOT_UKI=${ARTIFACT_FIELDS[6]}
SLOT_UKI_SHA=${ARTIFACT_FIELDS[7]}
SLOT_UKI_SIZE=${ARTIFACT_FIELDS[8]}
PAYLOAD_B=${ARTIFACT_FIELDS[9]}
PAYLOAD_B_SHA=${ARTIFACT_FIELDS[10]}
PAYLOAD_B_SIZE=${ARTIFACT_FIELDS[11]}
RAW_B_SHA=${ARTIFACT_FIELDS[12]}
RAW_B_SIZE=${ARTIFACT_FIELDS[13]}
SLOT_UKI_B=${ARTIFACT_FIELDS[14]}
SLOT_UKI_B_SHA=${ARTIFACT_FIELDS[15]}
SLOT_UKI_B_SIZE=${ARTIFACT_FIELDS[16]}

PAYLOAD_PATH="${WORK}/iso/punar/${PAYLOAD}"
SLOT_UKI_PATH="${WORK}/iso/punar/${SLOT_UKI}"
PAYLOAD_B_PATH="${WORK}/iso/punar/${PAYLOAD_B}"
SLOT_UKI_B_PATH="${WORK}/iso/punar/${SLOT_UKI_B}"
[ -f "${PAYLOAD_PATH}" ] || fail "declared payload is absent: ${PAYLOAD}"
[ -f "${SLOT_UKI_PATH}" ] || fail "declared slot UKI is absent: ${SLOT_UKI}"
[ -f "${PAYLOAD_B_PATH}" ] || fail "declared recovery payload is absent: ${PAYLOAD_B}"
[ -f "${SLOT_UKI_B_PATH}" ] || fail "declared recovery UKI is absent: ${SLOT_UKI_B}"

"${RELEASE_TOOL}" verify-release "${WORK}/iso/punar/keys" \
    "${WORK}/iso/punar/release.json" "${WORK}/iso/punar/release.json.sig"
"${RELEASE_TOOL}" verify-artifact "${PAYLOAD_PATH}" "${PAYLOAD_SHA}" "${PAYLOAD_SIZE}"
"${RELEASE_TOOL}" verify-artifact "${SLOT_UKI_PATH}" "${SLOT_UKI_SHA}" "${SLOT_UKI_SIZE}"
"${RELEASE_TOOL}" verify-artifact "${PAYLOAD_B_PATH}" "${PAYLOAD_B_SHA}" "${PAYLOAD_B_SIZE}"
"${RELEASE_TOOL}" verify-artifact "${SLOT_UKI_B_PATH}" "${SLOT_UKI_B_SHA}" "${SLOT_UKI_B_SIZE}"

[ "${RAW_SIZE}" = "${RAW_B_SIZE}" ] \
    || fail 'slot A and recovery slot B do not have equal root sizes'
[ "${RAW_SHA}" != "${RAW_B_SHA}" ] \
    || fail 'recovery slot B is an unsafe byte clone of slot A'

# Keep peak scratch use bounded to one decompressed root at a time. Finish all
# source-A checks and release it before materializing B; release B before the
# independent EROFS extraction below.
zstd --decompress --force --no-progress "${PAYLOAD_PATH}" -o "${WORK}/slot.raw"
[ "$(stat -c %s "${WORK}/slot.raw")" = "${RAW_SIZE}" ] \
    || fail 'uncompressed payload size does not match release metadata'
[ "$(sha256sum "${WORK}/slot.raw" | cut -d' ' -f1)" = "${RAW_SHA}" ] \
    || fail 'uncompressed payload digest does not match release metadata'
[ "$(blkid -p -s LABEL -o value "${WORK}/slot.raw")" = 'PUNAR-ROOT-A' ] \
    || fail 'uncompressed payload is not the PUNAR-ROOT-A filesystem'
e2fsck -fn "${WORK}/slot.raw" >/dev/null
rm -f "${WORK}/slot.raw"

zstd --decompress --force --no-progress "${PAYLOAD_B_PATH}" -o "${WORK}/slot-b.raw"
[ "$(stat -c %s "${WORK}/slot-b.raw")" = "${RAW_B_SIZE}" ] \
    || fail 'uncompressed recovery payload size does not match release metadata'
[ "$(sha256sum "${WORK}/slot-b.raw" | cut -d' ' -f1)" = "${RAW_B_SHA}" ] \
    || fail 'uncompressed recovery payload digest does not match release metadata'
[ "$(blkid -p -s LABEL -o value "${WORK}/slot-b.raw")" = 'PUNAR-ROOT-B' ] \
    || fail 'uncompressed recovery payload is not the PUNAR-ROOT-B filesystem'
[ "$(blkid -p -s UUID -o value "${WORK}/slot-b.raw")" = \
    '724e1a3b-d966-54b7-9a97-8886985eee18' ] \
    || fail 'uncompressed recovery payload has the wrong slot-B filesystem UUID'
e2fsck -fn "${WORK}/slot-b.raw" >/dev/null
debugfs -R 'cat /etc/fstab' "${WORK}/slot-b.raw" \
    > "${WORK}/slot-b.fstab" 2>/dev/null \
    || fail 'could not read recovery fstab from the signed source image'
python3 - "${WORK}/slot-b.fstab" <<'PY'
import sys

roots = []
with open(sys.argv[1], "r", encoding="utf-8") as stream:
    for raw in stream:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "/":
            roots.append((fields[0], fields[2]))
expected = [("UUID=724e1a3b-d966-54b7-9a97-8886985eee18", "ext4")]
if roots != expected:
    raise SystemExit(f"recovery fstab has unsafe root binding: {roots!r}")
PY
rm -f "${WORK}/slot-b.raw" "${WORK}/slot-b.fstab"

ESP_BYTES=$((1024 * 1024 * 1024))
BOOTLOADER_RESERVE=$((2 * 16 * 1024 * 1024))
FAT_RESERVE=$((64 * 1024 * 1024))
UPDATE_HEADROOM=$((192 * 1024 * 1024))
[ "${SLOT_UKI_SIZE}" -le "${UPDATE_HEADROOM}" ] \
    && [ "${SLOT_UKI_B_SIZE}" -le "${UPDATE_HEADROOM}" ] \
    || fail 'a signed UKI exceeds the fixed future-update headroom'
[ $((SLOT_UKI_SIZE + SLOT_UKI_B_SIZE + BOOTLOADER_RESERVE + FAT_RESERVE + UPDATE_HEADROOM)) -le "${ESP_BYTES}" ] \
    || fail 'initial UKIs do not leave the explicit ESP update reserve'

objcopy --dump-section ".cmdline=${WORK}/slot-a.cmdline" "${SLOT_UKI_PATH}"
objcopy --dump-section ".cmdline=${WORK}/slot-b.cmdline" "${SLOT_UKI_B_PATH}"
objcopy --dump-section ".osrel=${WORK}/slot-a.osrel" "${SLOT_UKI_PATH}"
objcopy --dump-section ".osrel=${WORK}/slot-b.osrel" "${SLOT_UKI_B_PATH}"
tr -d '\000' < "${WORK}/slot-a.cmdline" > "${WORK}/slot-a.cmdline.txt"
tr -d '\000' < "${WORK}/slot-b.cmdline" > "${WORK}/slot-b.cmdline.txt"
[ "$(tr ' ' '\n' < "${WORK}/slot-a.cmdline.txt" | grep -c '^root=PARTUUID=')" -eq 1 ] \
    || fail 'slot-A UKI does not carry exactly one root selector'
[ "$(tr ' ' '\n' < "${WORK}/slot-b.cmdline.txt" | grep -c '^root=PARTUUID=')" -eq 1 ] \
    || fail 'recovery UKI does not carry exactly one root selector'
tr ' ' '\n' < "${WORK}/slot-a.cmdline.txt" \
    | grep -Fqx 'root=PARTUUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea' \
    || fail 'slot-A UKI does not bind the fixed slot-A PARTUUID'
tr ' ' '\n' < "${WORK}/slot-b.cmdline.txt" \
    | grep -Fqx 'root=PARTUUID=2b1b91a9-cf2c-4e9c-a723-5ec997971662' \
    || fail 'recovery UKI does not bind the fixed slot-B PARTUUID'
cmp -s "${WORK}/slot-a.osrel" "${WORK}/slot-b.osrel" \
    && fail 'recovery UKI has no distinct boot-menu identity'
tr -d '\000' < "${WORK}/slot-b.osrel" \
    | grep -Fxq "PRETTY_NAME=\"Punar recovery ${VERSION}\"" \
    || fail 'recovery UKI does not carry its distinct recovery title'

fsck.erofs --extract="${WORK}/erofs-root" "${WORK}/iso/punar/live.erofs" >/dev/null
python3 "${REPO_ROOT}/tools/tree_manifest.py" \
    "${WORK}/erofs-root" "${WORK}/erofs-tree-manifest.json"
cmp "${WORK}/iso/punar/tree-manifest.json" "${WORK}/erofs-tree-manifest.json" \
    || fail 'live.erofs tree differs from the signed release-tree manifest'
rm -rf "${WORK}/erofs-root"
rm -f "${WORK}/erofs-tree-manifest.json"

# Locate the appended ESP from the final artifact, then inspect it in place.
sfdisk --json "${ISO}" > "${WORK}/partitions.json"
ESP_START="$(python3 - "${WORK}/partitions.json" <<'PY'
import json
import sys

ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
with open(sys.argv[1], encoding="utf-8") as stream:
    table = json.load(stream)["partitiontable"]
for part in table.get("partitions", []):
    if str(part.get("type", "")).lower() == ESP:
        print(part["start"])
        break
else:
    raise SystemExit("no appended EFI System Partition")
PY
)" || fail 'final ISO has no readable appended GPT ESP'
[[ "${ESP_START}" =~ ^[0-9]+$ ]] || fail 'appended ESP start is invalid'
ESP_OFFSET=$((ESP_START * 512))

mcopy -i "${ISO}@@${ESP_OFFSET}" ::/EFI/BOOT/BOOTX64.EFI "${WORK}/BOOTX64.EFI"
INSTALLER_UKI="punar-installer-${VERSION}-x86_64.efi"
mcopy -i "${ISO}@@${ESP_OFFSET}" "::/EFI/Linux/${INSTALLER_UKI}" "${WORK}/${INSTALLER_UKI}"
[ -s "${WORK}/BOOTX64.EFI" ] || fail 'removable-media UEFI bootloader is empty'
[ -s "${WORK}/${INSTALLER_UKI}" ] || fail 'installer UKI is empty'

# The optical path must be small enough for a non-zero El Torito load count
# and must chainload the byte-identical UKI verified above from ISO9660.
xorriso -osirrox on -indev "${ISO}" \
    -extract /boot/efi.img "${WORK}/optical-esp.img" \
    -extract "/EFI/Linux/${INSTALLER_UKI}" "${WORK}/optical-${INSTALLER_UKI}" \
    > "${WORK}/extract-optical.txt" 2>&1
mcopy -i "${WORK}/optical-esp.img" ::/EFI/BOOT/BOOTX64.EFI \
    "${WORK}/optical-BOOTX64.EFI"
[ -s "${WORK}/optical-BOOTX64.EFI" ] \
    || fail 'optical UEFI handoff loader is empty'
cmp "${WORK}/optical-${INSTALLER_UKI}" "${WORK}/${INSTALLER_UKI}" \
    || fail 'optical and raw-drive installer UKIs differ'

objcopy --dump-section ".cmdline=${WORK}/installer.cmdline" "${WORK}/${INSTALLER_UKI}"
tr -d '\000' < "${WORK}/installer.cmdline" > "${WORK}/installer.cmdline.txt"
grep -Fwq 'punar.live=1' "${WORK}/installer.cmdline.txt" \
    || fail 'installer UKI lacks exact punar.live=1 token'
grep -Fwq 'rd.systemd.gpt_auto=0' "${WORK}/installer.cmdline.txt" \
    || fail 'installer UKI does not disable initrd GPT root discovery'
if grep -Fq 'root=PARTUUID=' "${WORK}/installer.cmdline.txt"; then
    fail 'installer UKI embeds an installed-slot PARTUUID'
fi
if grep -Eq '(^|[[:space:]])console=(ttyS|ttyAMA)' "${WORK}/installer.cmdline.txt"; then
    fail 'installer UKI enables a serial kernel console'
fi

# Reconstruct the deterministic live-root member from source and prove the
# final artifact contains those exact bytes. A source-only unit test cannot
# catch a PE section that was linked at the old size and silently truncated.
"${REPO_ROOT}/os/images/scripts/build-installer-initrd.sh" \
    "${REPO_ROOT}/os/images/installer-initrd" "${WORK}/expected-punar-live.initrd"
objcopy --dump-section ".initrd=${WORK}/installer.initrd" "${WORK}/${INSTALLER_UKI}"
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

echo "installer-iso-contract-test: PASS version=${VERSION} bytes=$(stat -c %s "${ISO}")"
