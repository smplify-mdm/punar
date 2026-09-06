#!/usr/bin/env bash
# Prove that a Raspberry Pi install bundle was assembled from the official
# pinned firmware rather than from the tiny fixtures
# tests/images/raspberry-pi-bootfs-test.sh uses. That test proves the
# assembler's logic; this one proves the artifact a device would actually be
# written with (ADR-006, BUILD-QUEUE section 5).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE_ROOT="${1:-}"
PIN_FILE="${PUNAR_RPI_PIN_FILE:-${REPO_ROOT}/os/images/raspberry-pi/firmware.env}"

# The A/B root identities are punard's product contract
# (crates/punard/src/install.rs ROOT_A_PARTUUID / ROOT_B_PARTUUID); the other
# image tests pin the same two literals.
ROOT_A_PARTUUID="1beabfe0-9cb8-4b49-91ef-d372b845e7ea"
ROOT_B_PARTUUID="2b1b91a9-cf2c-4e9c-a723-5ec997971662"

# A fixture kernel/initramfs is a one-line printf. Real vendor inputs are
# megabytes, so a floor is the direct anti-fixture guard even though the
# digests below are the exact assertion.
MIN_KERNEL_BYTES=$((4 * 1024 * 1024))
MIN_INITRAMFS_BYTES=$((4 * 1024 * 1024))

die() {
    echo "error: $*" >&2
    exit 1
}

[ -n "${BUNDLE_ROOT}" ] || die "usage: $0 BUNDLE_ROOT"
for command in jq sha256sum zstd mdir mtype stat awk; do
    command -v "${command}" >/dev/null 2>&1 \
        || die "required command is missing: ${command}"
done
[ -f "${PIN_FILE}" ] || die "firmware pin file is missing: ${PIN_FILE}"
# shellcheck source=/dev/null
. "${PIN_FILE}"

RELEASE_DIR="${BUNDLE_ROOT}/release"
MANIFEST="${RELEASE_DIR}/release.json"
[ -f "${MANIFEST}" ] || die "bundle has no release manifest: ${MANIFEST}"
[ -s "${RELEASE_DIR}/release.json.sig" ] \
    || die 'the bundle manifest carries no signature'

jq -e '.schema_version == 1
       and .architecture == "aarch64"
       and .boot_platform == "raspberry_pi"
       and .boot_artifact.kind == "raspberry_pi_bootfs"
       and .payload.compression == "zstd"' "${MANIFEST}" >/dev/null \
    || die 'the manifest does not describe an aarch64 Raspberry Pi install bundle'

# The firmware commit is part of the release identity, so a bundle can never
# silently carry a different vendor tree than the one this tree pins.
manifest_pin="$(jq -r '.snapshot_pin' "${MANIFEST}")"
case "${manifest_pin}" in
    *"+rpi-${PUNAR_RPI_FIRMWARE_COMMIT}") ;;
    *) die "manifest snapshot_pin ${manifest_pin} does not name the pinned firmware commit ${PUNAR_RPI_FIRMWARE_COMMIT}" ;;
esac

check_artifact() {
    local selector="$1" label="$2"
    local filename digest size path actual_digest actual_size
    filename="$(jq -r "${selector}.filename" "${MANIFEST}")"
    digest="$(jq -r "${selector}.digest_sha256" "${MANIFEST}")"
    size="$(jq -r "${selector}.size_bytes" "${MANIFEST}")"
    path="${RELEASE_DIR}/${filename}"
    [ -f "${path}" ] || die "the manifest names a missing ${label}: ${filename}"
    actual_digest="$(sha256sum "${path}" | awk '{print $1}')"
    actual_size="$(stat -c '%s' "${path}")"
    [ "${actual_digest}" = "${digest}" ] \
        || die "the ${label} does not match its manifest digest"
    [ "${actual_size}" = "${size}" ] \
        || die "the ${label} is ${actual_size} bytes, not the ${size} the manifest claims"
    printf '%s\n' "${path}"
}

PAYLOAD="$(check_artifact '.payload' 'root payload')"
BOOTFS="$(check_artifact '.boot_artifact' 'boot artifact')"

# A compressed digest only proves the archive is intact. Decompress it to
# prove the uncompressed root a device would be written with is the one the
# manifest signed.
expected_root_digest="$(jq -r '.payload.uncompressed_digest_sha256' "${MANIFEST}")"
expected_root_size="$(jq -r '.payload.uncompressed_size_bytes' "${MANIFEST}")"
# Two passes rather than tee into a process substitution: bash does not wait
# for a process substitution, so the byte count could be read before it lands.
# zstd decompresses this payload in seconds, so the second pass is cheap.
actual_root_digest="$(zstd -dc "${PAYLOAD}" | sha256sum | awk '{print $1}')"
actual_root_size="$(zstd -dc "${PAYLOAD}" | wc -c | tr -d ' ')"
[ "${actual_root_digest}" = "${expected_root_digest}" ] \
    || die 'the decompressed root payload does not match its signed uncompressed digest'
[ "${actual_root_size}" = "${expected_root_size}" ] \
    || die "the decompressed root payload is ${actual_root_size} bytes, not the ${expected_root_size} the manifest claims"

# --- the boot filesystem a Pi actually reads -------------------------------
listing="$(mdir -/ -b -i "${BOOTFS}" ::/ )"
for entry in ::/config.txt ::/cmdline-a.txt ::/cmdline-b.txt ::/kernel8.img \
        ::/start4.elf ::/fixup4.dat ::/LICENCE.broadcom ::/COPYING.linux \
        ::/initramfs8 ::/overlays/; do
    printf '%s\n' "${listing}" | grep -Fqx "${entry}" \
        || die "the boot filesystem has no ${entry}"
done

fat_digest() {
    mtype -i "${BOOTFS}" "::/$1" | sha256sum | awk '{print $1}'
}
fat_size() {
    mtype -i "${BOOTFS}" "::/$1" | wc -c | tr -d ' '
}

# THE assertion: the vendor binaries on the artifact are byte-for-byte the
# ones os/images/raspberry-pi/firmware.env pins.
while IFS='|' read -r fat_name pinned_digest; do
    actual="$(fat_digest "${fat_name}")"
    [ "${actual}" = "${pinned_digest}" ] \
        || die "boot filesystem ${fat_name} is ${actual}, not the pinned ${pinned_digest}"
done <<PINS
kernel8.img|${PUNAR_RPI_KERNEL_SHA256}
start4.elf|${PUNAR_RPI_START4_SHA256}
fixup4.dat|${PUNAR_RPI_FIXUP4_SHA256}
LICENCE.broadcom|${PUNAR_RPI_LICENCE_SHA256}
PINS

kernel_bytes="$(fat_size kernel8.img)"
[ "${kernel_bytes}" -ge "${MIN_KERNEL_BYTES}" ] \
    || die "the boot filesystem kernel is ${kernel_bytes} bytes; a fixture, not a vendor kernel"
initramfs_bytes="$(fat_size initramfs8)"
[ "${initramfs_bytes}" -ge "${MIN_INITRAMFS_BYTES}" ] \
    || die "the boot filesystem initramfs is ${initramfs_bytes} bytes; a fixture, not a generated initramfs"

# ADR-006: the firmware itself selects the cmdline from the active boot
# partition, so the two files must exist, differ, and name the two roots.
config_txt="$(mtype -i "${BOOTFS}" ::/config.txt)"
printf '%s\n' "${config_txt}" | grep -Fqx '[boot_partition=2]' \
    || die 'config.txt does not select a cmdline for boot partition 2'
printf '%s\n' "${config_txt}" | grep -Fqx '[boot_partition=4]' \
    || die 'config.txt does not select a cmdline for boot partition 4'
printf '%s\n' "${config_txt}" | grep -Fqx 'cmdline=cmdline-a.txt' \
    || die 'config.txt does not point boot partition 2 at cmdline-a.txt'
printf '%s\n' "${config_txt}" | grep -Fqx 'cmdline=cmdline-b.txt' \
    || die 'config.txt does not point boot partition 4 at cmdline-b.txt'

cmdline_a="$(mtype -i "${BOOTFS}" ::/cmdline-a.txt)"
cmdline_b="$(mtype -i "${BOOTFS}" ::/cmdline-b.txt)"
printf '%s\n' "${cmdline_a}" | tr ' ' '\n' \
    | grep -Fqx "root=PARTUUID=${ROOT_A_PARTUUID}" \
    || die 'cmdline-a.txt does not select root slot A by PARTUUID'
printf '%s\n' "${cmdline_b}" | tr ' ' '\n' \
    | grep -Fqx "root=PARTUUID=${ROOT_B_PARTUUID}" \
    || die 'cmdline-b.txt does not select root slot B by PARTUUID'
[ "${cmdline_a}" != "${cmdline_b}" ] \
    || die 'both boot slots would mount the same root'

# The bootfs is slot-neutral on purpose: the selector is written at install
# time. A committed autoboot.txt would freeze one slot into the artifact.
if printf '%s\n' "${listing}" | grep -Fqx '::/autoboot.txt'; then
    die 'the slot-neutral boot artifact carries an autoboot.txt selector'
fi

echo "raspberry-pi-bundle-check: PASS (pinned firmware ${PUNAR_RPI_FIRMWARE_COMMIT}, kernel ${PUNAR_RPI_KERNEL_RELEASE}, root payload ${expected_root_size} bytes)"
