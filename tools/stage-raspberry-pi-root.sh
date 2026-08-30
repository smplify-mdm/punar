#!/usr/bin/env bash
# Add the pinned Raspberry Pi kernel's matching modules to a disposable root-A
# filesystem and generate its initramfs from inside that root. The caller must
# subsequently run build-raspberry-pi-bootfs.sh, which independently compares
# every staged loadable module with the pinned source before accepting it.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PIN_FILE="${PUNAR_RPI_PIN_FILE:-${REPO_ROOT}/os/images/raspberry-pi/firmware.env}"
FIRMWARE_ROOT="${1:-}"
ROOT="${2:-}"
OUTPUT_INITRAMFS="${3:-}"

die() {
    echo "error: $*" >&2
    exit 1
}

[ -n "${FIRMWARE_ROOT}" ] && [ -n "${ROOT}" ] \
    && [ -n "${OUTPUT_INITRAMFS}" ] \
    || die "usage: $0 FIRMWARE_ROOT MOUNTED_ROOT_A OUTPUT_INITRAMFS"
[ "$(id -u)" -eq 0 ] || die "root staging must run as root in the image builder"
for command in chroot cp find install sha256sum awk grep mountpoint sync stat; do
    command -v "${command}" >/dev/null 2>&1 \
        || die "required command is missing: ${command}"
done
[ -f "${PIN_FILE}" ] || die "firmware pin file is missing: ${PIN_FILE}"
# shellcheck source=/dev/null
. "${PIN_FILE}"
for variable in PUNAR_RPI_FIRMWARE_TAG PUNAR_RPI_FIRMWARE_COMMIT \
    PUNAR_RPI_KERNEL_RELEASE PUNAR_RPI_KERNEL_SHA256 \
    PUNAR_RPI_MODULES_TREE_SHA256; do
    [ -n "${!variable:-}" ] || die "firmware pin is missing ${variable}"
done

FIRMWARE_ROOT="$(cd "${FIRMWARE_ROOT}" && pwd)"
ROOT="$(cd "${ROOT}" && pwd)"
OUTPUT_PARENT="$(cd "$(dirname "${OUTPUT_INITRAMFS}")" && pwd)"
OUTPUT_INITRAMFS="${OUTPUT_PARENT}/$(basename "${OUTPUT_INITRAMFS}")"
SOURCE_MODULES="${FIRMWARE_ROOT}/modules/${PUNAR_RPI_KERNEL_RELEASE}"
TARGET_MODULES="${ROOT}/usr/lib/modules/${PUNAR_RPI_KERNEL_RELEASE}"
ROOT_INITRAMFS="${ROOT}/boot/initramfs-${PUNAR_RPI_KERNEL_RELEASE}.img"

[ ! -e "${OUTPUT_INITRAMFS}" ] \
    || die "refusing to overwrite initramfs output: ${OUTPUT_INITRAMFS}"
[ -d "${SOURCE_MODULES}" ] || die "pinned Raspberry Pi module tree is missing"
[ -z "$(find "${SOURCE_MODULES}" -type l -print -quit)" ] \
    || die "pinned Raspberry Pi module tree may not contain symbolic links"
[ -f "${ROOT}/etc/os-release" ] \
    || die "target does not look like a Linux root filesystem"
[ -f "${ROOT}/usr/lib/systemd/system/punard.service" ] \
    || die "target is not a Punar release root"
[ -x "${ROOT}/usr/bin/dracut" ] \
    || die "Punar release root is missing its pinned dracut generator"
[ -x "${ROOT}/usr/bin/lsinitrd" ] \
    || die "Punar release root is missing lsinitrd"
[ -x "${ROOT}/usr/sbin/depmod" ] || [ -x "${ROOT}/sbin/depmod" ] \
    || die "Punar release root is missing depmod"
for virtual_fs in proc sys dev run; do
    mountpoint -q "${ROOT}/${virtual_fs}" \
        || die "target ${virtual_fs} must be mounted for initramfs generation"
done
[ ! -e "${TARGET_MODULES}" ] \
    || die "target root already contains the Raspberry Pi kernel release"
[ ! -e "${ROOT_INITRAMFS}" ] \
    || die "target root already contains the Raspberry Pi initramfs"

install -d -m 0755 "${ROOT}/usr/lib/modules"
cp -a --no-preserve=ownership "${SOURCE_MODULES}" "${TARGET_MODULES}"
chown -R 0:0 "${TARGET_MODULES}"

install -d -m 0755 "${ROOT}/usr/share/punar"
cat > "${ROOT}/usr/share/punar/raspberry-pi-kernel.json" <<EOF
{"schema_version":1,"firmware_tag":"${PUNAR_RPI_FIRMWARE_TAG}","firmware_commit":"${PUNAR_RPI_FIRMWARE_COMMIT}","kernel_release":"${PUNAR_RPI_KERNEL_RELEASE}","kernel_sha256":"${PUNAR_RPI_KERNEL_SHA256}","modules_tree_sha256":"${PUNAR_RPI_MODULES_TREE_SHA256}","initramfs_generator":"dracut"}
EOF
chmod 0644 "${ROOT}/usr/share/punar/raspberry-pi-kernel.json"

chroot "${ROOT}" /usr/sbin/depmod "${PUNAR_RPI_KERNEL_RELEASE}"
for module_index in modules.dep modules.dep.bin modules.alias modules.alias.bin; do
    [ -s "${TARGET_MODULES}/${module_index}" ] \
        || die "depmod did not produce ${module_index} for the paired kernel"
done
# Root A intentionally carries no mutable /var/tmp: it is mounted from the
# encrypted shared-state partition at runtime. Keep image assembly inside the
# immutable root's existing /tmp instead of weakening that separation.
chroot "${ROOT}" /usr/bin/env TMPDIR=/tmp \
    /usr/bin/dracut --force --no-hostonly --reproducible --gzip \
    "/boot/initramfs-${PUNAR_RPI_KERNEL_RELEASE}.img" \
    "${PUNAR_RPI_KERNEL_RELEASE}"
[ -s "${ROOT_INITRAMFS}" ] || die "dracut did not produce an initramfs"

listing="$(chroot "${ROOT}" /usr/bin/lsinitrd \
    "/boot/initramfs-${PUNAR_RPI_KERNEL_RELEASE}.img")"
module_root="usr/lib/modules/${PUNAR_RPI_KERNEL_RELEASE}"
if ! awk -v dependency_index="${module_root}/modules.dep" \
    '$NF == dependency_index || $NF == dependency_index ".bin" { found = 1 }
     END { exit !found }' <<< "${listing}"; then
    grep -E "modules\.(dep|alias)" <<< "${listing}" >&2 || true
    grep -F "lib/modules/${PUNAR_RPI_KERNEL_RELEASE}/" <<< "${listing}" \
        | head -n 50 >&2 || true
    die "generated initramfs does not contain the paired module dependency index"
fi
if ! awk -v module_prefix="${module_root}/kernel/" \
    'index($NF, module_prefix) == 1 && $NF ~ /\.ko(\.(gz|xz|zst))?$/ { found = 1 }
     END { exit !found }' <<< "${listing}"; then
    grep -F "lib/modules/${PUNAR_RPI_KERNEL_RELEASE}/" <<< "${listing}" \
        | head -n 50 >&2 || true
    die "generated initramfs does not contain a module for the paired kernel"
fi

install -m 0644 "${ROOT_INITRAMFS}" "${OUTPUT_INITRAMFS}"
sync -f "${ROOT}/usr/share/punar/raspberry-pi-kernel.json"
sync -f "${ROOT_INITRAMFS}"
sync -f "${OUTPUT_INITRAMFS}"

initramfs_bytes="$(stat -c %s "${OUTPUT_INITRAMFS}")"
initramfs_digest="$(sha256sum "${OUTPUT_INITRAMFS}" | awk '{print $1}')"
echo "PUNAR_RPI_ROOT_OK kernel=${PUNAR_RPI_KERNEL_RELEASE} initramfs_bytes=${initramfs_bytes} initramfs_sha256=${initramfs_digest}"
