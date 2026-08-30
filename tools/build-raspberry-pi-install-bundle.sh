#!/usr/bin/env bash
# Convert one verified generic ARM64 release image into a signed Raspberry Pi
# *installation* bundle for root slot A plus a slot-neutral Pi boot artifact.
# This is intentionally separate
# from build-release-bundle.sh, whose payload and UKI are rebound to inactive
# slot B for update/rollback proof. Mixing those roles would create duplicate
# filesystem identities after the first update.
#
# Signatures use an ephemeral per-run Ed25519 key until production key custody
# is supplied. The bundle is therefore software-path evidence, not a release.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${1:-${REPO_ROOT}/os/images/out/punar-release-arm64.qcow2}"
VERSION="${2:-2026.08.30.1}"
OUT_ROOT="${3:-${REPO_ROOT}/os/images/out/raspberry-pi-installer}"
CHANNEL="${PUNAR_RELEASE_CHANNEL:-stable}"
IMAGE_ID="punar-desktop"
ARCH="aarch64"
BOOT_PLATFORM="raspberry_pi"
ROOT_A_BYTES=$((8 * 1024 * 1024 * 1024))
RELEASE_DIR="${OUT_ROOT}/release"
KEY_DIR="${OUT_ROOT}/keys"
PAYLOAD_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.root-a.raw.zst"
BOOTFS_NAME="${IMAGE_ID}-${ARCH}-${BOOT_PLATFORM}-${VERSION}.boot.img"

# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/arm64/snapshot.env"
# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/raspberry-pi/firmware.env"
BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"
BUILDER_DIGEST="${PUNAR_DEBIAN_BUILDER_BASE##*@}"
BUILD_INFO="${REPO_ROOT}/os/images/out/arm64-build-info.txt"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"

die() {
    echo "error: $*" >&2
    exit 1
}

for command in docker jq qemu-img shasum dd; do
    command -v "${command}" >/dev/null 2>&1 \
        || die "required command is missing: ${command}"
done
case "${CHANNEL}" in stable|dev|edge) ;; *) die "invalid channel: ${CHANNEL}" ;; esac
[[ "${VERSION}" =~ ^[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.[0-9]+$ ]] \
    || die "version must be YYYY.MM.DD.N"

IMAGE="$(cd "$(dirname "${IMAGE}")" && pwd)/$(basename "${IMAGE}")"
OUT_ROOT_PARENT="$(cd "$(dirname "${OUT_ROOT}")" && pwd)"
OUT_ROOT="${OUT_ROOT_PARENT}/$(basename "${OUT_ROOT}")"
RELEASE_DIR="${OUT_ROOT}/release"
KEY_DIR="${OUT_ROOT}/keys"
case "${IMAGE}" in "${REPO_ROOT}"/*) ;; *) die "source image must be inside the repository" ;; esac
case "${OUT_ROOT}" in "${REPO_ROOT}"/*) ;; *) die "output root must be inside the repository" ;; esac
[ -f "${IMAGE}" ] || die "source release image not found: ${IMAGE}"
[ -f "${BUILD_INFO}" ] || die "ARM64 build info not found: ${BUILD_INFO}"
[ ! -e "${OUT_ROOT}" ] || die "refusing to overwrite installer bundle: ${OUT_ROOT}"
qemu-img info "${IMAGE}" >/dev/null || die "source image is not readable by qemu-img"
docker image inspect "${BUILDER_TAG}" >/dev/null 2>&1 \
    || die "ARM64 builder is missing; run tools/build-arm64-image.sh first"
grep -Eq '^images: .*punar-release-arm64([[:space:]]|$)' "${BUILD_INFO}" \
    || die "build info does not identify the source as a Punar ARM64 release image"
[ "$(awk -F ': ' '$1 == "snapshot" {print $2}' "${BUILD_INFO}")" \
    = "${PUNAR_DEBIAN_SNAPSHOT}" ] \
    || die "source image build info does not match the pinned Debian snapshot"
[ "$(awk -F ': ' '$1 == "architecture" {print $2}' "${BUILD_INFO}")" = arm64 ] \
    || die "source image build info does not identify ARM64"
BUILD_GIT_SHA="$(awk -F ': ' '$1 == "git-sha" {print $2}' "${BUILD_INFO}")"
[[ "${BUILD_GIT_SHA}" =~ ^[0-9a-f]{40}$ ]] \
    || die "source image build info does not contain a valid Git commit"

TEMP_DIR="$(mktemp -d "${REPO_ROOT}/os/images/out/.rpi-install-sign.XXXXXX")"
success=false
cleanup() {
    rm -rf "${TEMP_DIR}"
    if [ "${success}" != true ] && [ -d "${OUT_ROOT}" ]; then
        rm -rf "${OUT_ROOT}"
    fi
}
trap cleanup EXIT
mkdir -p "${RELEASE_DIR}" "${KEY_DIR}"

container_path() {
    printf '/work/%s' "${1#"${REPO_ROOT}"/}"
}

echo "==> Building root A plus the slot-neutral Raspberry Pi boot artifact"
docker run --rm --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env "PUNAR_SOURCE_IMAGE=$(container_path "${IMAGE}")" \
    --env "PUNAR_RELEASE_DIR=$(container_path "${RELEASE_DIR}")" \
    --env "PUNAR_PAYLOAD_NAME=${PAYLOAD_NAME}" \
    --env "PUNAR_BOOTFS_NAME=${BOOTFS_NAME}" \
    --env "PUNAR_ROOT_A_BYTES=${ROOT_A_BYTES}" \
    --env "PUNAR_RPI_KERNEL_RELEASE=${PUNAR_RPI_KERNEL_RELEASE}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" bash -ceu '
        for command in qemu-img sfdisk dd losetup mount umount mountpoint \
            blkid e2fsck zstd sha256sum sync mknod truncate; do
            command -v "${command}" >/dev/null 2>&1 \
                || { echo "error: required builder command is missing: ${command}" >&2; exit 1; }
        done
        work="$(mktemp -d /var/tmp/punar-rpi-install.XXXXXX)"
        root_loop=""
        unmount_chroot() {
            for virtual_fs in run dev sys proc; do
                if mountpoint -q "${work}/root/${virtual_fs}"; then
                    umount --recursive "${work}/root/${virtual_fs}" || true
                fi
            done
        }
        cleanup_inner() {
            unmount_chroot
            mountpoint -q "${work}/root" && umount "${work}/root" || true
            [ -z "${root_loop}" ] || losetup --detach "${root_loop}" || true
            [ ! -f "${work}/disk.raw" ] || truncate --size 0 "${work}/disk.raw" || true
            [ ! -f "${work}/root-a.raw" ] || truncate --size 0 "${work}/root-a.raw" || true
            rm -rf "${work}"
        }
        trap cleanup_inner EXIT
        mkdir -p "${work}/root"
        for loop_minor in {0..31}; do
            [ -b "/dev/loop${loop_minor}" ] \
                || mknod --mode=0660 "/dev/loop${loop_minor}" b 7 "${loop_minor}"
        done
        [ -c /dev/loop-control ] || mknod --mode=0660 /dev/loop-control c 10 237

        /work/tools/fetch-raspberry-pi-firmware.sh "${work}/firmware"
        qemu-img convert -p -O raw -S 4k "${PUNAR_SOURCE_IMAGE}" "${work}/disk.raw"
        /work/tests/images/check-repart-layout.sh "${work}/disk.raw" arm64
        read -r root_start root_size < <(
            sfdisk --dump "${work}/disk.raw" \
                | awk -F "[=,]" "/start=/ {n++; if (n == 2) {gsub(/ /, \"\", \$2); gsub(/ /, \"\", \$4); print \$2, \$4}}"
        )
        root_bytes="$((root_size * 512))"
        [ "${root_bytes}" = "${PUNAR_ROOT_A_BYTES}" ] \
            || { echo "error: source root A has an unexpected size" >&2; exit 1; }
        dd if="${work}/disk.raw" of="${work}/root-a.raw" \
            iflag=skip_bytes,count_bytes skip="$((root_start * 512))" \
            count="${root_bytes}" conv=sparse status=none
        root_uuid="$(blkid -p -s UUID -o value "${work}/root-a.raw")"
        [[ "${root_uuid}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
            || { echo "error: source root A filesystem UUID is invalid" >&2; exit 1; }
        [ "$(blkid -p -s LABEL -o value "${work}/root-a.raw")" = PUNAR-ROOT-A ] \
            || { echo "error: source root A filesystem label is not canonical" >&2; exit 1; }

        root_loop="$(losetup --find --show "${work}/root-a.raw")"
        mount "${root_loop}" "${work}/root"
        grep -Fqi "UUID=${root_uuid} / ext4" "${work}/root/etc/fstab" \
            || { echo "error: source root A fstab does not bind its filesystem UUID" >&2; exit 1; }
        mkdir -p "${work}/root/proc" "${work}/root/sys" \
            "${work}/root/dev" "${work}/root/run"
        mount -t proc proc "${work}/root/proc"
        mount --rbind /sys "${work}/root/sys"
        mount --make-rslave "${work}/root/sys"
        mount --rbind /dev "${work}/root/dev"
        mount --make-rslave "${work}/root/dev"
        mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "${work}/root/run"
        /work/tools/stage-raspberry-pi-root.sh \
            "${work}/firmware" "${work}/root" "${work}/initramfs8"
        /work/tools/build-raspberry-pi-bootfs.sh \
            "${work}/firmware" "${work}/initramfs8" \
            "${work}/root/usr/lib/modules/${PUNAR_RPI_KERNEL_RELEASE}" \
            "${PUNAR_RELEASE_DIR}/${PUNAR_BOOTFS_NAME}"
        unmount_chroot
        sync -f "${work}/root"
        umount "${work}/root"
        losetup --detach "${root_loop}"
        root_loop=""
        e2fsck -fn "${work}/root-a.raw"

        sha256sum "${work}/root-a.raw" | awk "{print \$1}" \
            > "${PUNAR_RELEASE_DIR}/root-a.sha256"
        printf "%s\n" "${root_bytes}" > "${PUNAR_RELEASE_DIR}/root-a.bytes"
        zstd -T0 -10 --force --no-progress "${work}/root-a.raw" \
            -o "${PUNAR_RELEASE_DIR}/${PUNAR_PAYLOAD_NAME}"
        chown -R "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" "${PUNAR_RELEASE_DIR}"
    '

PAYLOAD="${RELEASE_DIR}/${PAYLOAD_NAME}"
BOOTFS="${RELEASE_DIR}/${BOOTFS_NAME}"
[ -f "${PAYLOAD}" ] && [ -f "${BOOTFS}" ] \
    || die "builder did not produce both install artifacts"
PAYLOAD_DIGEST="$(shasum -a 256 "${PAYLOAD}" | awk '{print $1}')"
PAYLOAD_SIZE="$(wc -c < "${PAYLOAD}" | tr -d ' ')"
UNCOMPRESSED_DIGEST="$(< "${RELEASE_DIR}/root-a.sha256")"
UNCOMPRESSED_SIZE="$(< "${RELEASE_DIR}/root-a.bytes")"
BOOTFS_DIGEST="$(shasum -a 256 "${BOOTFS}" | awk '{print $1}')"
BOOTFS_SIZE="$(wc -c < "${BOOTFS}" | tr -d ' ')"
GIT_SHA="${BUILD_GIT_SHA}"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
CI_RUN_ID="${GITHUB_RUN_ID:-local-$(date -u +%Y%m%dT%H%M%SZ)}"
RELEASE_ID="${IMAGE_ID}-${CHANNEL}-${ARCH}-${BOOT_PLATFORM}-${VERSION}"
SNAPSHOT_PIN="${PUNAR_DEBIAN_SNAPSHOT}+rpi-${PUNAR_RPI_FIRMWARE_COMMIT}"

jq -n \
    --arg release_id "${RELEASE_ID}" \
    --arg image_id "${IMAGE_ID}" \
    --arg version "${VERSION}" \
    --arg channel "${CHANNEL}" \
    --arg snapshot_pin "${SNAPSHOT_PIN}" \
    --arg payload_filename "${PAYLOAD_NAME}" \
    --arg payload_digest "${PAYLOAD_DIGEST}" \
    --argjson payload_size "${PAYLOAD_SIZE}" \
    --arg uncompressed_digest "${UNCOMPRESSED_DIGEST}" \
    --argjson uncompressed_size "${UNCOMPRESSED_SIZE}" \
    --arg bootfs_filename "${BOOTFS_NAME}" \
    --arg bootfs_digest "${BOOTFS_DIGEST}" \
    --argjson bootfs_size "${BOOTFS_SIZE}" \
    --arg git_commit "${GIT_SHA}" \
    --arg ci_run_id "${CI_RUN_ID}" \
    --arg builder_digest "${BUILDER_DIGEST}" \
    --argjson source_date_epoch "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
    --arg built_at "${BUILT_AT}" \
    '{schema_version: 1, release_id: $release_id, image_id: $image_id,
      architecture: "aarch64", boot_platform: "raspberry_pi", version: $version,
      channel: $channel, snapshot_pin: $snapshot_pin, overlay_pin: null,
      payload: {filename: $payload_filename, digest_sha256: $payload_digest,
        size_bytes: $payload_size, uncompressed_digest_sha256: $uncompressed_digest,
        uncompressed_size_bytes: $uncompressed_size, compression: "zstd"},
      boot_artifact: {kind: "raspberry_pi_bootfs", filename: $bootfs_filename,
        digest_sha256: $bootfs_digest, size_bytes: $bootfs_size},
      min_from: null, security: {severity: "none", advisory_ids: []},
      provenance: {git_commit: $git_commit, ci_run_id: $ci_run_id,
        builder_base_digest: $builder_digest, source_date_epoch: $source_date_epoch,
        built_at: $built_at}, sbom: null}' > "${RELEASE_DIR}/release.json"

echo "==> Signing and independently verifying the Pi install manifest/artifacts"
SEED="${TEMP_DIR}/ephemeral-install.seed"
dd if=/dev/urandom of="${SEED}" bs=32 count=1 status=none
chmod 0600 "${SEED}"
run_release_tool() {
    docker run --rm --platform linux/arm64 \
        --env PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
        --volume "${REPO_ROOT}:/work" --workdir /work rust:1.95.0-slim \
        cargo run --quiet --locked -p punar-common --bin punar-release-tool -- "$@"
}
run_release_tool public-key "$(container_path "${SEED}")" \
    "$(container_path "${KEY_DIR}/ephemeral-ci.pub")"
run_release_tool sign "$(container_path "${SEED}")" \
    "$(container_path "${RELEASE_DIR}/release.json")" \
    "$(container_path "${RELEASE_DIR}/release.json.sig")"
run_release_tool verify-release "$(container_path "${KEY_DIR}")" \
    "$(container_path "${RELEASE_DIR}/release.json")" \
    "$(container_path "${RELEASE_DIR}/release.json.sig")"
run_release_tool verify-artifact "$(container_path "${PAYLOAD}")" \
    "${PAYLOAD_DIGEST}" "${PAYLOAD_SIZE}"
run_release_tool verify-artifact "$(container_path "${BOOTFS}")" \
    "${BOOTFS_DIGEST}" "${BOOTFS_SIZE}"

rm -f "${RELEASE_DIR}/root-a.sha256" "${RELEASE_DIR}/root-a.bytes"
chmod 0644 "${KEY_DIR}/ephemeral-ci.pub" "${RELEASE_DIR}/release.json" \
    "${RELEASE_DIR}/release.json.sig" "${PAYLOAD}" "${BOOTFS}"
success=true
echo "PUNAR_RPI_INSTALL_BUNDLE_OK version=${VERSION} signing=SIMULATED_EPHEMERAL firmware=${PUNAR_RPI_FIRMWARE_TAG}"
du -sh "${OUT_ROOT}"
