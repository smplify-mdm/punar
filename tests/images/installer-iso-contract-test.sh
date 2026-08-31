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
for command in xorriso sfdisk mcopy objcopy fsck.erofs zstd blkid e2fsck; do
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

mkdir -p "${WORK}/iso" "${WORK}/erofs-root"
xorriso -osirrox on -indev "${ISO}" -extract /punar "${WORK}/iso/punar" \
    > "${WORK}/extract.txt" 2>&1
for file in release.json release.json.sig tree-manifest.json live.erofs; do
    [ -f "${WORK}/iso/punar/${file}" ] || fail "ISO is missing /punar/${file}"
done
[ -d "${WORK}/iso/punar/keys" ] || fail 'ISO is missing /punar/keys'

read -r VERSION PAYLOAD PAYLOAD_SHA PAYLOAD_SIZE RAW_SHA RAW_SIZE \
    SLOT_UKI SLOT_UKI_SHA SLOT_UKI_SIZE < <(
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

payload = doc["payload"]
boot = doc["boot_artifact"]
values = [
    doc["version"], payload["filename"], payload["digest_sha256"],
    str(payload["size_bytes"]), payload["uncompressed_digest_sha256"],
    str(payload["uncompressed_size_bytes"]), boot["filename"],
    boot["digest_sha256"], str(boot["size_bytes"]),
]
if any(any(char.isspace() for char in value) for value in values):
    raise SystemExit("release metadata artifact fields contain whitespace")
print(" ".join(values))
PY
)

PAYLOAD_PATH="${WORK}/iso/punar/${PAYLOAD}"
SLOT_UKI_PATH="${WORK}/iso/punar/${SLOT_UKI}"
[ -f "${PAYLOAD_PATH}" ] || fail "declared payload is absent: ${PAYLOAD}"
[ -f "${SLOT_UKI_PATH}" ] || fail "declared slot UKI is absent: ${SLOT_UKI}"

"${RELEASE_TOOL}" verify-release "${WORK}/iso/punar/keys" \
    "${WORK}/iso/punar/release.json" "${WORK}/iso/punar/release.json.sig"
"${RELEASE_TOOL}" verify-artifact "${PAYLOAD_PATH}" "${PAYLOAD_SHA}" "${PAYLOAD_SIZE}"
"${RELEASE_TOOL}" verify-artifact "${SLOT_UKI_PATH}" "${SLOT_UKI_SHA}" "${SLOT_UKI_SIZE}"

zstd --decompress --force --no-progress "${PAYLOAD_PATH}" -o "${WORK}/slot.raw"
[ "$(stat -c %s "${WORK}/slot.raw")" = "${RAW_SIZE}" ] \
    || fail 'uncompressed payload size does not match release metadata'
[ "$(sha256sum "${WORK}/slot.raw" | cut -d' ' -f1)" = "${RAW_SHA}" ] \
    || fail 'uncompressed payload digest does not match release metadata'
[ "$(blkid -p -s LABEL -o value "${WORK}/slot.raw")" = 'PUNAR-ROOT-A' ] \
    || fail 'uncompressed payload is not the PUNAR-ROOT-A filesystem'
e2fsck -fn "${WORK}/slot.raw" >/dev/null

fsck.erofs --extract="${WORK}/erofs-root" "${WORK}/iso/punar/live.erofs" >/dev/null
python3 "${REPO_ROOT}/tools/tree_manifest.py" \
    "${WORK}/erofs-root" "${WORK}/erofs-tree-manifest.json"
cmp "${WORK}/iso/punar/tree-manifest.json" "${WORK}/erofs-tree-manifest.json" \
    || fail 'live.erofs tree differs from the signed release-tree manifest'

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

echo "installer-iso-contract-test: PASS version=${VERSION} bytes=$(stat -c %s "${ISO}")"
