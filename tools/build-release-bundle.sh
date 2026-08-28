#!/usr/bin/env bash
# Turn one verified A/B qcow2 into a signed slot-B update fixture.
#
# The release signature uses a per-run ephemeral Ed25519 key. This proves the
# device verification path; it is not a production signing/custody solution.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-release-arm64.qcow2}"
VERSION="${2:-2026.08.27.1}"
OUT_ROOT="${3:-${REPO_ROOT}/os/images/out/repository}"
CHANNEL="${PUNAR_RELEASE_CHANNEL:-stable}"
ROLLOUT_BPS="${PUNAR_RELEASE_ROLLOUT_BPS:-10000}"
IMAGE_ID="punar-desktop"
ARCH="aarch64"
BOOT_PLATFORM="uefi"
SLOT_A_UUID="1beabfe0-9cb8-4b49-91ef-d372b845e7ea"
SLOT_B_UUID="2b1b91a9-cf2c-4e9c-a723-5ec997971662"
# UUIDv5(NAMESPACE_URL, "https://punar.org/filesystem/root-b"). Root slots
# must not share an ext4 UUID: the UKI selects by GPT PARTUUID, while fstab
# and recovery tooling still observe filesystem UUIDs.
SLOT_B_FS_UUID="724e1a3b-d966-54b7-9a97-8886985eee18"
RELEASE_DIR="${OUT_ROOT}/releases/${VERSION}"
KEY_DIR="${OUT_ROOT}/keys"
PAYLOAD_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.slot.raw.zst"
UKI_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.uki.efi"

# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/arm64/snapshot.env"
BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"
BUILDER_DIGEST="${PUNAR_DEBIAN_BUILDER_BASE##*@}"
BUILD_INFO="${REPO_ROOT}/os/images/out/arm64-build-info.txt"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

case "${CHANNEL}" in stable|dev|edge) ;; *) echo "error: invalid channel: ${CHANNEL}" >&2; exit 2 ;; esac
case "${ROLLOUT_BPS}" in ''|*[!0-9]*) echo "error: rollout basis points must be an integer" >&2; exit 2 ;; esac
if [ "${ROLLOUT_BPS}" -gt 10000 ]; then
    echo "error: rollout basis points must be between 0 and 10000" >&2
    exit 2
fi
if ! [[ "${VERSION}" =~ ^[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.[0-9]+$ ]]; then
    echo "error: version must be YYYY.MM.DD.N" >&2
    exit 2
fi
[ -f "${IMAGE}" ] || { echo "error: image not found: ${IMAGE}" >&2; exit 2; }
[ -f "${BUILD_INFO}" ] || { echo "error: build info not found: ${BUILD_INFO}" >&2; exit 2; }
docker image inspect "${BUILDER_TAG}" >/dev/null 2>&1 \
    || { echo "error: builder image is missing; run tools/build-arm64-image.sh first" >&2; exit 2; }

TEMP_DIR="$(mktemp -d "${REPO_ROOT}/os/images/out/.release-work.XXXXXX")"
cleanup() {
    rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

mkdir -p "${RELEASE_DIR}" "${KEY_DIR}"

echo "==> Extracting and rebinding the ARM64 root payload to inactive slot B"
docker run --rm --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env "PUNAR_IMAGE=${IMAGE#"${REPO_ROOT}"/}" \
    --env "PUNAR_TEMP=${TEMP_DIR#"${REPO_ROOT}"/}" \
    --env "PUNAR_RELEASE_DIR=${RELEASE_DIR#"${REPO_ROOT}"/}" \
    --env "PUNAR_PAYLOAD_NAME=${PAYLOAD_NAME}" \
    --env "PUNAR_UKI_NAME=${UKI_NAME}" \
    --env "PUNAR_SLOT_A_UUID=${SLOT_A_UUID}" \
    --env "PUNAR_SLOT_B_UUID=${SLOT_B_UUID}" \
    --env "PUNAR_SLOT_B_FS_UUID=${SLOT_B_FS_UUID}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" \
    bash -ceu '
        qemu-img convert -p -O raw -S 4k "/work/${PUNAR_IMAGE}" "/work/${PUNAR_TEMP}/disk.raw"
        /work/tests/images/check-repart-layout.sh "/work/${PUNAR_TEMP}/disk.raw" arm64

        read -r esp_start esp_size < <(sfdisk --dump "/work/${PUNAR_TEMP}/disk.raw" | awk -F "[=,]" "/start=/ {n++; if (n == 1) {gsub(/ /, \"\", \$2); gsub(/ /, \"\", \$4); print \$2, \$4}}")
        read -r root_start root_size < <(sfdisk --dump "/work/${PUNAR_TEMP}/disk.raw" | awk -F "[=,]" "/start=/ {n++; if (n == 2) {gsub(/ /, \"\", \$2); gsub(/ /, \"\", \$4); print \$2, \$4}}")
        printf "%s\n" "$((root_size * 512))" > "/work/${PUNAR_TEMP}/uncompressed-size"
        dd if="/work/${PUNAR_TEMP}/disk.raw" of="/work/${PUNAR_TEMP}/slot-b.raw" \
            iflag=skip_bytes,count_bytes skip="$((root_start * 512))" count="$((root_size * 512))" \
            conv=sparse status=none

        for loop_minor in {0..31}; do
            [ -b "/dev/loop${loop_minor}" ] || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
        done
        [ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237
        root_loop="$(losetup --find --show "/work/${PUNAR_TEMP}/slot-b.raw")"
        mkdir -p "/work/${PUNAR_TEMP}/root" "/work/${PUNAR_TEMP}/esp"
        mount "${root_loop}" "/work/${PUNAR_TEMP}/root"
        root_a_fs_uuid="$(findmnt -n -o UUID --target "/work/${PUNAR_TEMP}/root")"
        [ -n "${root_a_fs_uuid}" ]
        sed -i "s/${root_a_fs_uuid}/${PUNAR_SLOT_B_FS_UUID}/g" "/work/${PUNAR_TEMP}/root/etc/fstab"
        grep -Fqi "UUID=${PUNAR_SLOT_B_FS_UUID} / ext4" "/work/${PUNAR_TEMP}/root/etc/fstab"
        sync -f "/work/${PUNAR_TEMP}/root/etc/fstab"
        umount "/work/${PUNAR_TEMP}/root"
        losetup --detach "${root_loop}"
        tune2fs -U "${PUNAR_SLOT_B_FS_UUID}" -L PUNAR-ROOT-B "/work/${PUNAR_TEMP}/slot-b.raw"
        [ "$(blkid -p -s UUID -o value "/work/${PUNAR_TEMP}/slot-b.raw")" = "${PUNAR_SLOT_B_FS_UUID}" ]
        [ "$(blkid -p -s LABEL -o value "/work/${PUNAR_TEMP}/slot-b.raw")" = PUNAR-ROOT-B ]
        e2fsck -fn "/work/${PUNAR_TEMP}/slot-b.raw"

        esp_loop="$(losetup --find --show --offset "$((esp_start * 512))" --sizelimit "$((esp_size * 512))" "/work/${PUNAR_TEMP}/disk.raw")"
        mount -o ro "${esp_loop}" "/work/${PUNAR_TEMP}/esp"
        uki="$(find "/work/${PUNAR_TEMP}/esp/EFI/Linux" -maxdepth 1 -type f -name "*.efi" -print -quit)"
        [ -n "${uki}" ]
        cp "${uki}" "/work/${PUNAR_TEMP}/slot-b.efi"
        umount "/work/${PUNAR_TEMP}/esp"
        losetup --detach "${esp_loop}"

        objcopy --only-section=.cmdline --output-target=binary "/work/${PUNAR_TEMP}/slot-b.efi" "/work/${PUNAR_TEMP}/cmdline"
        tr -d "\000" < "/work/${PUNAR_TEMP}/cmdline" > "/work/${PUNAR_TEMP}/cmdline.txt"
        grep -Fqi "root=PARTUUID=${PUNAR_SLOT_A_UUID}" "/work/${PUNAR_TEMP}/cmdline.txt"
        sed "s/${PUNAR_SLOT_A_UUID}/${PUNAR_SLOT_B_UUID}/g" "/work/${PUNAR_TEMP}/cmdline.txt" > "/work/${PUNAR_TEMP}/cmdline-b.txt"
        printf "\0" >> "/work/${PUNAR_TEMP}/cmdline-b.txt"
        objcopy --update-section ".cmdline=/work/${PUNAR_TEMP}/cmdline-b.txt" "/work/${PUNAR_TEMP}/slot-b.efi"
        objcopy --only-section=.cmdline --output-target=binary "/work/${PUNAR_TEMP}/slot-b.efi" "/work/${PUNAR_TEMP}/cmdline-verified"
        tr -d "\000" < "/work/${PUNAR_TEMP}/cmdline-verified" | grep -Fqi "root=PARTUUID=${PUNAR_SLOT_B_UUID}"

        zstd -T0 -10 --force --no-progress "/work/${PUNAR_TEMP}/slot-b.raw" -o "/work/${PUNAR_RELEASE_DIR}/${PUNAR_PAYLOAD_NAME}"
        cp "/work/${PUNAR_TEMP}/slot-b.efi" "/work/${PUNAR_RELEASE_DIR}/${PUNAR_UKI_NAME}"
        chown -R "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" "/work/${PUNAR_RELEASE_DIR}"
    '

PAYLOAD="${RELEASE_DIR}/${PAYLOAD_NAME}"
UKI="${RELEASE_DIR}/${UKI_NAME}"
PAYLOAD_DIGEST="$(shasum -a 256 "${PAYLOAD}" | awk '{print $1}')"
UKI_DIGEST="$(shasum -a 256 "${UKI}" | awk '{print $1}')"
PAYLOAD_SIZE="$(wc -c < "${PAYLOAD}" | tr -d ' ')"
UKI_SIZE="$(wc -c < "${UKI}" | tr -d ' ')"
UNCOMPRESSED_SIZE="$(< "${TEMP_DIR}/uncompressed-size")"
GIT_SHA="$(awk -F ': ' '$1 == "git-sha" {print $2}' "${BUILD_INFO}")"
BUILT_AT="$(awk -F ': ' '$1 == "built-at" {print $2}' "${BUILD_INFO}")"
CI_RUN_ID="local-$(date -u +%Y%m%dT%H%M%SZ)"
RELEASE_ID="${IMAGE_ID}-${CHANNEL}-${ARCH}-${BOOT_PLATFORM}-${VERSION}"

jq -n \
    --arg release_id "${RELEASE_ID}" \
    --arg image_id "${IMAGE_ID}" \
    --arg version "${VERSION}" \
    --arg channel "${CHANNEL}" \
    --arg snapshot_pin "${PUNAR_DEBIAN_SNAPSHOT}" \
    --arg payload_filename "${PAYLOAD_NAME}" \
    --arg payload_digest "${PAYLOAD_DIGEST}" \
    --argjson payload_size "${PAYLOAD_SIZE}" \
    --argjson uncompressed_size "${UNCOMPRESSED_SIZE}" \
    --arg uki_filename "${UKI_NAME}" \
    --arg uki_digest "${UKI_DIGEST}" \
    --argjson uki_size "${UKI_SIZE}" \
    --arg git_commit "${GIT_SHA}" \
    --arg ci_run_id "${CI_RUN_ID}" \
    --arg builder_digest "${BUILDER_DIGEST}" \
    --argjson source_date_epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
    --arg built_at "${BUILT_AT}" \
    '{schema_version: 1, release_id: $release_id, image_id: $image_id,
      architecture: "aarch64", boot_platform: "uefi", version: $version,
      channel: $channel, snapshot_pin: $snapshot_pin, overlay_pin: null,
      payload: {filename: $payload_filename, digest_sha256: $payload_digest,
        size_bytes: $payload_size, uncompressed_size_bytes: $uncompressed_size,
        compression: "zstd"},
      boot_artifact: {kind: "uki", filename: $uki_filename,
        digest_sha256: $uki_digest, size_bytes: $uki_size},
      min_from: null, security: {severity: "none", advisory_ids: []},
      provenance: {git_commit: $git_commit, ci_run_id: $ci_run_id,
        builder_base_digest: $builder_digest, source_date_epoch: $source_date_epoch,
        built_at: $built_at}, sbom: null}' > "${RELEASE_DIR}/release.json"

PUBLISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
    --arg image_id "${IMAGE_ID}" \
    --arg channel "${CHANNEL}" \
    --arg current "${VERSION}" \
    --arg release_manifest "releases/${VERSION}/release.json" \
    --argjson rollout_bps "${ROLLOUT_BPS}" \
    --arg published_at "${PUBLISHED_AT}" \
    '{schema_version: 1, image_id: $image_id, architecture: "aarch64",
      boot_platform: "uefi", channel: $channel, current: $current,
      release_manifest: $release_manifest, rollout_bps: $rollout_bps,
      halted: false, published_at: $published_at,
      min_supported_version: $current}' > "${OUT_ROOT}/channel.json"

echo "==> Signing exact metadata bytes with an ephemeral CI key"
SEED="${TEMP_DIR}/ephemeral-release.seed"
dd if=/dev/urandom of="${SEED}" bs=32 count=1 status=none
chmod 0600 "${SEED}"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    public-key "/work/${SEED#"${REPO_ROOT}"/}" "/work/${KEY_DIR#"${REPO_ROOT}"/}/ephemeral-ci.pub"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    sign "/work/${SEED#"${REPO_ROOT}"/}" "/work/${RELEASE_DIR#"${REPO_ROOT}"/}/release.json" "/work/${RELEASE_DIR#"${REPO_ROOT}"/}/release.json.sig"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    sign "/work/${SEED#"${REPO_ROOT}"/}" "/work/${OUT_ROOT#"${REPO_ROOT}"/}/channel.json" "/work/${OUT_ROOT#"${REPO_ROOT}"/}/channel.json.sig"

echo "==> Verifying signatures, schemas, and exact artifact digests"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-release "/work/${KEY_DIR#"${REPO_ROOT}"/}" "/work/${RELEASE_DIR#"${REPO_ROOT}"/}/release.json" "/work/${RELEASE_DIR#"${REPO_ROOT}"/}/release.json.sig"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-channel "/work/${KEY_DIR#"${REPO_ROOT}"/}" "/work/${OUT_ROOT#"${REPO_ROOT}"/}/channel.json" "/work/${OUT_ROOT#"${REPO_ROOT}"/}/channel.json.sig"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-artifact "/work/${PAYLOAD#"${REPO_ROOT}"/}" "${PAYLOAD_DIGEST}" "${PAYLOAD_SIZE}"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-artifact "/work/${UKI#"${REPO_ROOT}"/}" "${UKI_DIGEST}" "${UKI_SIZE}"

chmod 0644 "${KEY_DIR}/ephemeral-ci.pub" "${RELEASE_DIR}/release.json" \
    "${RELEASE_DIR}/release.json.sig" "${OUT_ROOT}/channel.json" "${OUT_ROOT}/channel.json.sig"

echo "PUNAR_RELEASE_BUNDLE_OK version=${VERSION} architecture=${ARCH} signing=SIMULATED_EPHEMERAL"
du -sh "${OUT_ROOT}"
