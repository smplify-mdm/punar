#!/usr/bin/env bash
# Turn one verified A/B qcow2 into a signed, independently root-bound A/B
# update fixture.
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
PAYLOAD_A_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.slot-a.raw.zst"
PAYLOAD_B_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.slot-b.raw.zst"
UKI_A_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.slot-a.uki.efi"
UKI_B_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.slot-b.uki.efi"

# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/arm64/snapshot.env"
BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"
BUILDER_DIGEST="${PUNAR_DEBIAN_BUILDER_BASE##*@}"
BUILD_INFO="${REPO_ROOT}/os/images/out/arm64-build-info.txt"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
MIN_SUPPORTED_VERSION="${PUNAR_RELEASE_MIN_SUPPORTED_VERSION:-${PUNAR_BASE_IMAGE_VERSION}}"

for command in docker jq shasum; do
    command -v "${command}" >/dev/null 2>&1 \
        || { echo "error: required command is missing: ${command}" >&2; exit 2; }
done
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
if ! [[ "${MIN_SUPPORTED_VERSION}" =~ ^[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.[0-9]+$ ]]; then
    echo "error: minimum supported version must be YYYY.MM.DD.N" >&2
    exit 2
fi
IMAGE="$(cd "$(dirname "${IMAGE}")" && pwd)/$(basename "${IMAGE}")"
OUT_ROOT_PARENT="$(cd "$(dirname "${OUT_ROOT}")" && pwd)"
OUT_ROOT="${OUT_ROOT_PARENT}/$(basename "${OUT_ROOT}")"
RELEASE_DIR="${OUT_ROOT}/releases/${VERSION}"
KEY_DIR="${OUT_ROOT}/keys"
case "${IMAGE}" in "${REPO_ROOT}"/*) ;; *) echo "error: source image must be inside the repository" >&2; exit 2 ;; esac
case "${OUT_ROOT}" in "${REPO_ROOT}"/*) ;; *) echo "error: output root must be inside the repository" >&2; exit 2 ;; esac
[ -f "${IMAGE}" ] || { echo "error: image not found: ${IMAGE}" >&2; exit 2; }
[ -f "${BUILD_INFO}" ] || { echo "error: build info not found: ${BUILD_INFO}" >&2; exit 2; }
[ ! -e "${OUT_ROOT}" ] \
    || { echo "error: refusing to mix an ephemeral signing set into existing output: ${OUT_ROOT}" >&2; exit 2; }
docker image inspect "${BUILDER_TAG}" >/dev/null 2>&1 \
    || { echo "error: builder image is missing; run tools/build-arm64-image.sh first" >&2; exit 2; }
grep -Eq '^images: .*punar-release-arm64([[:space:]]|$)' "${BUILD_INFO}" \
    || { echo "error: build info does not identify the source as a Punar ARM64 release image" >&2; exit 2; }
[ "$(awk -F ': ' '$1 == "snapshot" {print $2}' "${BUILD_INFO}")" = "${PUNAR_DEBIAN_SNAPSHOT}" ] \
    || { echo "error: source image build info does not match the pinned Debian snapshot" >&2; exit 2; }
[ "$(awk -F ': ' '$1 == "architecture" {print $2}' "${BUILD_INFO}")" = arm64 ] \
    || { echo "error: source image build info does not identify ARM64" >&2; exit 2; }
GIT_SHA="$(awk -F ': ' '$1 == "git-sha" {print $2}' "${BUILD_INFO}")"
[[ "${GIT_SHA}" =~ ^[0-9a-f]{40}$ ]] \
    || { echo "error: source image build info does not contain a valid Git commit" >&2; exit 2; }

TEMP_DIR="$(mktemp -d "${REPO_ROOT}/os/images/out/.release-work.XXXXXX")"
success=false
cleanup() {
    rm -rf "${TEMP_DIR}"
    if [ "${success}" != true ] && [ -d "${OUT_ROOT}" ]; then
        find "${OUT_ROOT}" -type f -exec truncate --size 0 {} + 2>/dev/null || true
        rm -rf "${OUT_ROOT}"
    fi
}
trap cleanup EXIT

mkdir -p "${RELEASE_DIR}" "${KEY_DIR}"

echo "==> Extracting slot A and deriving the independently bound slot B pair"
docker run --rm --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env "PUNAR_IMAGE=${IMAGE#"${REPO_ROOT}"/}" \
    --env "PUNAR_RELEASE_DIR=${RELEASE_DIR#"${REPO_ROOT}"/}" \
    --env "PUNAR_PAYLOAD_A_NAME=${PAYLOAD_A_NAME}" \
    --env "PUNAR_PAYLOAD_B_NAME=${PAYLOAD_B_NAME}" \
    --env "PUNAR_UKI_A_NAME=${UKI_A_NAME}" \
    --env "PUNAR_UKI_B_NAME=${UKI_B_NAME}" \
    --env "PUNAR_SLOT_A_UUID=${SLOT_A_UUID}" \
    --env "PUNAR_SLOT_B_UUID=${SLOT_B_UUID}" \
    --env "PUNAR_SLOT_B_FS_UUID=${SLOT_B_FS_UUID}" \
    --env "PUNAR_VERSION=${VERSION}" \
    --env "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" \
    bash -ceu '
        work="$(mktemp -d /var/tmp/punar-release-bundle.XXXXXX)"
        root_loop=""
        esp_loop=""
        cleanup_inner() {
            mountpoint -q "${work}/root" && umount "${work}/root" || true
            mountpoint -q "${work}/esp" && umount "${work}/esp" || true
            [ -z "${root_loop}" ] || losetup --detach "${root_loop}" || true
            [ -z "${esp_loop}" ] || losetup --detach "${esp_loop}" || true
            for raw in "${work}/disk.raw" "${work}/slot-a.raw" "${work}/slot-b.raw"; do
                [ ! -f "${raw}" ] || truncate --size 0 "${raw}" || true
            done
            rm -rf "${work}"
        }
        trap cleanup_inner EXIT
        mkdir -p "${work}/root" "${work}/esp"

        qemu-img convert -p -O raw -S 4k "/work/${PUNAR_IMAGE}" "${work}/disk.raw"
        /work/tests/images/check-repart-layout.sh "${work}/disk.raw" arm64

        read -r esp_start esp_size < <(sfdisk --dump "${work}/disk.raw" | awk -F "[=,]" "/start=/ {n++; if (n == 1) {gsub(/ /, \"\", \$2); gsub(/ /, \"\", \$4); print \$2, \$4}}")
        read -r root_start root_size < <(sfdisk --dump "${work}/disk.raw" | awk -F "[=,]" "/start=/ {n++; if (n == 2) {gsub(/ /, \"\", \$2); gsub(/ /, \"\", \$4); print \$2, \$4}}")
        uncompressed_size="$((root_size * 512))"
        dd if="${work}/disk.raw" of="${work}/slot-a.raw" \
            iflag=skip_bytes,count_bytes skip="$((root_start * 512))" count="$((root_size * 512))" \
            conv=sparse status=none

        for loop_minor in {0..31}; do
            [ -b "/dev/loop${loop_minor}" ] || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
        done
        [ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237
        # The signed manifest version and the identity observed after boot
        # must be the same fact. Stamp slot A before deriving B so both roots
        # carry the canonical target identity while retaining substrate
        # ID/VERSION_ID for inventory.
        root_loop="$(losetup --find --show "${work}/slot-a.raw")"
        mount "${root_loop}" "${work}/root"
        stamp_release_identity() {
            local os_release="$1"
            [ -f "${os_release}" ]
            awk "!/^(IMAGE_ID|IMAGE_VERSION|PUNAR_SNAPSHOT_PIN)=/" \
                "${os_release}" > "${os_release}.punar"
            {
                printf "IMAGE_ID=punar-desktop\n"
                printf "IMAGE_VERSION=%s\n" "${PUNAR_VERSION}"
                printf "PUNAR_SNAPSHOT_PIN=%s\n" "${PUNAR_SNAPSHOT_PIN}"
            } >> "${os_release}.punar"
            chmod 0644 "${os_release}.punar"
            mv "${os_release}.punar" "${os_release}"
        }
        os_release="${work}/root/usr/lib/os-release"
        stamp_release_identity "${os_release}"
        if [ ! -L "${work}/root/etc/os-release" ]; then
            stamp_release_identity "${work}/root/etc/os-release"
        fi
        grep -Fxq "IMAGE_ID=punar-desktop" "${work}/root/etc/os-release"
        grep -Fxq "IMAGE_VERSION=${PUNAR_VERSION}" "${work}/root/etc/os-release"
        grep -Fxq "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" "${work}/root/etc/os-release"
        root_a_fs_uuid="$(findmnt -n -o UUID --target "${work}/root")"
        [ -n "${root_a_fs_uuid}" ]
        sync -f "${os_release}"
        umount "${work}/root"
        losetup --detach "${root_loop}"
        root_loop=""

        cp --sparse=always "${work}/slot-a.raw" "${work}/slot-b.raw"
        root_loop="$(losetup --find --show "${work}/slot-b.raw")"
        mount "${root_loop}" "${work}/root"
        sed -i "s/${root_a_fs_uuid}/${PUNAR_SLOT_B_FS_UUID}/g" "${work}/root/etc/fstab"
        grep -Fqi "UUID=${PUNAR_SLOT_B_FS_UUID} / ext4" "${work}/root/etc/fstab"
        grep -Fxq "IMAGE_VERSION=${PUNAR_VERSION}" "${work}/root/etc/os-release"
        grep -Fxq "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" "${work}/root/etc/os-release"
        sync -f "${work}/root/etc/fstab"
        umount "${work}/root"
        losetup --detach "${root_loop}"
        root_loop=""
        tune2fs -U "${PUNAR_SLOT_B_FS_UUID}" -L PUNAR-ROOT-B "${work}/slot-b.raw"
        [ "$(blkid -p -s UUID -o value "${work}/slot-b.raw")" = "${PUNAR_SLOT_B_FS_UUID}" ]
        [ "$(blkid -p -s LABEL -o value "${work}/slot-b.raw")" = PUNAR-ROOT-B ]
        e2fsck -fn "${work}/slot-b.raw"

        esp_loop="$(losetup --find --show --offset "$((esp_start * 512))" --sizelimit "$((esp_size * 512))" "${work}/disk.raw")"
        mount -o ro "${esp_loop}" "${work}/esp"
        uki="$(find "${work}/esp/EFI/Linux" -maxdepth 1 -type f -name "*.efi" -print -quit)"
        [ -n "${uki}" ]
        cp "${uki}" "${work}/slot-a.efi"
        cp "${uki}" "${work}/slot-b.efi"
        umount "${work}/esp"
        losetup --detach "${esp_loop}"
        esp_loop=""

        objcopy --only-section=.cmdline --output-target=binary "${work}/slot-b.efi" "${work}/cmdline"
        tr -d "\000" < "${work}/cmdline" > "${work}/cmdline.txt"
        grep -Fqi "root=PARTUUID=${PUNAR_SLOT_A_UUID}" "${work}/cmdline.txt"
        sed "s/${PUNAR_SLOT_A_UUID}/${PUNAR_SLOT_B_UUID}/g" "${work}/cmdline.txt" > "${work}/cmdline-b.txt"
        printf "\0" >> "${work}/cmdline-b.txt"
        objcopy --update-section ".cmdline=${work}/cmdline-b.txt" "${work}/slot-b.efi"
        objcopy --only-section=.cmdline --output-target=binary "${work}/slot-b.efi" "${work}/cmdline-verified"
        tr -d "\000" < "${work}/cmdline-verified" > "${work}/cmdline-b-verified.txt"
        [ "$(tr " " "\n" < "${work}/cmdline.txt" | grep -c "^root=PARTUUID=")" -eq 1 ]
        [ "$(tr " " "\n" < "${work}/cmdline-b-verified.txt" | grep -c "^root=PARTUUID=")" -eq 1 ]
        tr " " "\n" < "${work}/cmdline.txt" | grep -Fqx "root=PARTUUID=${PUNAR_SLOT_A_UUID}"
        tr " " "\n" < "${work}/cmdline-b-verified.txt" | grep -Fqx "root=PARTUUID=${PUNAR_SLOT_B_UUID}"

        slot_a_digest="$(sha256sum "${work}/slot-a.raw" | awk "{print \$1}")"
        slot_b_digest="$(sha256sum "${work}/slot-b.raw" | awk "{print \$1}")"
        printf "%s\n" "${slot_a_digest}" > "/work/${PUNAR_RELEASE_DIR}/slot-a.sha256"
        printf "%s\n" "${slot_b_digest}" > "/work/${PUNAR_RELEASE_DIR}/slot-b.sha256"
        printf "%s\n" "${uncompressed_size}" > "/work/${PUNAR_RELEASE_DIR}/uncompressed-size"
        zstd -T0 -10 --force --no-progress "${work}/slot-a.raw" -o "/work/${PUNAR_RELEASE_DIR}/${PUNAR_PAYLOAD_A_NAME}"
        zstd -T0 -10 --force --no-progress "${work}/slot-b.raw" -o "/work/${PUNAR_RELEASE_DIR}/${PUNAR_PAYLOAD_B_NAME}"
        [ "$(zstd -dc "/work/${PUNAR_RELEASE_DIR}/${PUNAR_PAYLOAD_A_NAME}" | sha256sum | awk "{print \$1}")" = "${slot_a_digest}" ]
        [ "$(zstd -dc "/work/${PUNAR_RELEASE_DIR}/${PUNAR_PAYLOAD_B_NAME}" | sha256sum | awk "{print \$1}")" = "${slot_b_digest}" ]
        cp "${work}/slot-a.efi" "/work/${PUNAR_RELEASE_DIR}/${PUNAR_UKI_A_NAME}"
        cp "${work}/slot-b.efi" "/work/${PUNAR_RELEASE_DIR}/${PUNAR_UKI_B_NAME}"
        chown -R "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" "/work/${PUNAR_RELEASE_DIR}"
    '

PAYLOAD_A="${RELEASE_DIR}/${PAYLOAD_A_NAME}"
PAYLOAD_B="${RELEASE_DIR}/${PAYLOAD_B_NAME}"
UKI_A="${RELEASE_DIR}/${UKI_A_NAME}"
UKI_B="${RELEASE_DIR}/${UKI_B_NAME}"
PAYLOAD_A_DIGEST="$(shasum -a 256 "${PAYLOAD_A}" | awk '{print $1}')"
PAYLOAD_B_DIGEST="$(shasum -a 256 "${PAYLOAD_B}" | awk '{print $1}')"
UNCOMPRESSED_A_DIGEST="$(< "${RELEASE_DIR}/slot-a.sha256")"
UNCOMPRESSED_B_DIGEST="$(< "${RELEASE_DIR}/slot-b.sha256")"
UKI_A_DIGEST="$(shasum -a 256 "${UKI_A}" | awk '{print $1}')"
UKI_B_DIGEST="$(shasum -a 256 "${UKI_B}" | awk '{print $1}')"
PAYLOAD_A_SIZE="$(wc -c < "${PAYLOAD_A}" | tr -d ' ')"
PAYLOAD_B_SIZE="$(wc -c < "${PAYLOAD_B}" | tr -d ' ')"
UKI_A_SIZE="$(wc -c < "${UKI_A}" | tr -d ' ')"
UKI_B_SIZE="$(wc -c < "${UKI_B}" | tr -d ' ')"
UNCOMPRESSED_SIZE="$(< "${RELEASE_DIR}/uncompressed-size")"
BUILT_AT="$(awk -F ': ' '$1 == "built-at" {print $2}' "${BUILD_INFO}")"
CI_RUN_ID="local-$(date -u +%Y%m%dT%H%M%SZ)"
RELEASE_ID="${IMAGE_ID}-${CHANNEL}-${ARCH}-${BOOT_PLATFORM}-${VERSION}"

jq -n \
    --arg release_id "${RELEASE_ID}" \
    --arg image_id "${IMAGE_ID}" \
    --arg version "${VERSION}" \
    --arg channel "${CHANNEL}" \
    --arg snapshot_pin "${PUNAR_DEBIAN_SNAPSHOT}" \
    --arg payload_a_filename "${PAYLOAD_A_NAME}" \
    --arg payload_a_digest "${PAYLOAD_A_DIGEST}" \
    --argjson payload_a_size "${PAYLOAD_A_SIZE}" \
    --arg uncompressed_a_digest "${UNCOMPRESSED_A_DIGEST}" \
    --arg payload_b_filename "${PAYLOAD_B_NAME}" \
    --arg payload_b_digest "${PAYLOAD_B_DIGEST}" \
    --argjson payload_b_size "${PAYLOAD_B_SIZE}" \
    --arg uncompressed_b_digest "${UNCOMPRESSED_B_DIGEST}" \
    --argjson uncompressed_size "${UNCOMPRESSED_SIZE}" \
    --arg uki_a_filename "${UKI_A_NAME}" \
    --arg uki_a_digest "${UKI_A_DIGEST}" \
    --argjson uki_a_size "${UKI_A_SIZE}" \
    --arg uki_b_filename "${UKI_B_NAME}" \
    --arg uki_b_digest "${UKI_B_DIGEST}" \
    --argjson uki_b_size "${UKI_B_SIZE}" \
    --arg git_commit "${GIT_SHA}" \
    --arg ci_run_id "${CI_RUN_ID}" \
    --arg builder_digest "${BUILDER_DIGEST}" \
    --argjson source_date_epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
    --arg built_at "${BUILT_AT}" \
    '{schema_version: 1, release_id: $release_id, image_id: $image_id,
      architecture: "aarch64", boot_platform: "uefi", version: $version,
      channel: $channel, snapshot_pin: $snapshot_pin, overlay_pin: null,
      payload: {filename: $payload_a_filename, digest_sha256: $payload_a_digest,
        size_bytes: $payload_a_size, uncompressed_digest_sha256: $uncompressed_a_digest,
        uncompressed_size_bytes: $uncompressed_size,
        compression: "zstd"},
      boot_artifact: {kind: "uki", filename: $uki_a_filename,
        digest_sha256: $uki_a_digest, size_bytes: $uki_a_size},
      uefi_slots: {
        a: {
          payload: {filename: $payload_a_filename, digest_sha256: $payload_a_digest,
            size_bytes: $payload_a_size, uncompressed_digest_sha256: $uncompressed_a_digest,
            uncompressed_size_bytes: $uncompressed_size, compression: "zstd"},
          boot_artifact: {kind: "uki", filename: $uki_a_filename,
            digest_sha256: $uki_a_digest, size_bytes: $uki_a_size}},
        b: {
          payload: {filename: $payload_b_filename, digest_sha256: $payload_b_digest,
            size_bytes: $payload_b_size, uncompressed_digest_sha256: $uncompressed_b_digest,
            uncompressed_size_bytes: $uncompressed_size, compression: "zstd"},
          boot_artifact: {kind: "uki", filename: $uki_b_filename,
            digest_sha256: $uki_b_digest, size_bytes: $uki_b_size}}
      },
      min_from: null, security: {severity: "none", advisory_ids: []},
      provenance: {git_commit: $git_commit, ci_run_id: $ci_run_id,
        builder_base_digest: $builder_digest, source_date_epoch: $source_date_epoch,
        built_at: $built_at}, sbom: null}' > "${RELEASE_DIR}/release.json"
rm -f "${RELEASE_DIR}/slot-a.sha256" "${RELEASE_DIR}/slot-b.sha256" \
    "${RELEASE_DIR}/uncompressed-size"

PUBLISHED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
    --arg image_id "${IMAGE_ID}" \
    --arg channel "${CHANNEL}" \
    --arg current "${VERSION}" \
    --arg min_supported_version "${MIN_SUPPORTED_VERSION}" \
    --arg release_manifest "releases/${VERSION}/release.json" \
    --argjson rollout_bps "${ROLLOUT_BPS}" \
    --arg published_at "${PUBLISHED_AT}" \
    '{schema_version: 1, image_id: $image_id, architecture: "aarch64",
      boot_platform: "uefi", channel: $channel, current: $current,
      release_manifest: $release_manifest, rollout_bps: $rollout_bps,
      halted: false, published_at: $published_at,
      min_supported_version: $min_supported_version}' > "${OUT_ROOT}/channel.json"

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
    verify-artifact "/work/${PAYLOAD_A#"${REPO_ROOT}"/}" "${PAYLOAD_A_DIGEST}" "${PAYLOAD_A_SIZE}"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-artifact "/work/${PAYLOAD_B#"${REPO_ROOT}"/}" "${PAYLOAD_B_DIGEST}" "${PAYLOAD_B_SIZE}"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-artifact "/work/${UKI_A#"${REPO_ROOT}"/}" "${UKI_A_DIGEST}" "${UKI_A_SIZE}"
docker run --rm --platform linux/arm64 \
    --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
    cargo run --quiet --locked -p punar-common --bin punar-release-tool -- \
    verify-artifact "/work/${UKI_B#"${REPO_ROOT}"/}" "${UKI_B_DIGEST}" "${UKI_B_SIZE}"

chmod 0644 "${KEY_DIR}/ephemeral-ci.pub" "${RELEASE_DIR}/release.json" \
    "${RELEASE_DIR}/release.json.sig" "${OUT_ROOT}/channel.json" "${OUT_ROOT}/channel.json.sig"

echo "PUNAR_RELEASE_BUNDLE_OK version=${VERSION} architecture=${ARCH} signing=SIMULATED_EPHEMERAL"
du -sh "${OUT_ROOT}"
success=true
