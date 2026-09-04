#!/usr/bin/env bash
# A physical-machine firmware floor belongs in the installed root; it must not
# silently turn the UKI into a second copy of every kernel module and firmware
# dependency. This contract keeps early boot bounded on every generic image
# while preserving the full post-root hardware payload.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ARCH_BASE="${REPO_ROOT}/os/images/mkosi.conf"
DEBIAN_AMD64_BASE="${REPO_ROOT}/os/images/amd64-debian/mkosi.conf"
DEBIAN_ARM64_BASE="${REPO_ROOT}/os/images/arm64/mkosi.conf"
ARCH_DESKTOP="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.conf"
DEBIAN_HARDWARE="${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/hardware-x86/mkosi.conf"
ARCH_INSTALLER="${REPO_ROOT}/os/images/mkosi.profiles/installer/mkosi.conf"
DEBIAN_INSTALLER="${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/installer/mkosi.conf"

fail() {
    echo "initrd-module-policy-test: FAIL: $*" >&2
    exit 1
}

for config in "${ARCH_BASE}" "${DEBIAN_AMD64_BASE}" "${DEBIAN_ARM64_BASE}"; do
    count="$(grep -Ec '^KernelInitrdModules=default$' "${config}")"
    [ "${count}" -eq 1 ] \
        || fail "${config#"${REPO_ROOT}/"} does not select mkosi's bounded boot module set exactly once"
done

# Firmware filtering at the main-image level would also delete it from the
# root filesystem in mkosi 26. Guard against solving UKI size by breaking the
# bare-hardware payload.
if rg -n '^(FirmwareFiles|KernelModules)=' \
    "${ARCH_BASE}" "${DEBIAN_AMD64_BASE}" "${DEBIAN_ARM64_BASE}"; then
    fail "a base image filters the installed kernel module or firmware tree"
fi
for package in linux-firmware sof-firmware intel-ucode amd-ucode; do
    grep -Eq "^(Packages=|[[:space:]]+)${package}$" "${ARCH_DESKTOP}" \
        || fail "Arch hardware floor no longer carries ${package}"
done
for package in firmware-linux firmware-iwlwifi firmware-realtek \
    firmware-sof-signed intel-microcode amd64-microcode; do
    grep -Eq "^(Packages=|[[:space:]]+)${package}$" "${DEBIAN_HARDWARE}" \
        || fail "Debian hardware floor no longer carries ${package}"
done

# Live media needs a few modules in addition to the ordinary default boot set.
for installer in "${ARCH_INSTALLER}" "${DEBIAN_INSTALLER}"; do
    for module in loop overlay erofs isofs sr_mod virtio_blk virtio_pci ahci nvme; do
        grep -Eq "^(KernelInitrdModules=|[[:space:]]+)${module}$" "${installer}" \
            || fail "${installer#"${REPO_ROOT}/"} lacks live-root module ${module}"
    done
done

echo 'PUNAR_INITRD_MODULE_POLICY_OK'
