#!/usr/bin/env bash
# Static contract test for the declarative live-root initrd overlay.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_ROOT="${REPO_ROOT}/os/images/installer-initrd/usr/lib/systemd/system"
INSTALLER_CONF="${REPO_ROOT}/os/images/mkosi.profiles/installer/mkosi.conf"

fail() {
    echo "installer-initrd-test: FAIL: $*" >&2
    exit 1
}

assert_line() {
    local file=$1 expected=$2
    grep -Fqx -- "${expected}" "${file}" \
        || fail "${file#"${REPO_ROOT}/"} is missing: ${expected}"
}

MEDIUM="${UNIT_ROOT}/run-punar-medium.mount"
LOWER="${UNIT_ROOT}/run-punar-lower.mount"
OVERLAY="${UNIT_ROOT}/run-punar-overlay.mount"
PREP="${UNIT_ROOT}/run-punar-overlay-prep.service"
SYSROOT="${UNIT_ROOT}/sysroot.mount"
READY="${UNIT_ROOT}/punar-installer-ready.service"
TARGET="${UNIT_ROOT}/initrd-root-fs.target.d/50-punar-live.conf"
SWITCH_ROOT_PROOF="${UNIT_ROOT}/initrd-switch-root.service.d/50-punar-serial-proof.conf"
FINALIZER="${REPO_ROOT}/os/images/mkosi.finalize"
INITRD_BUILDER="${REPO_ROOT}/os/images/scripts/build-installer-initrd.sh"
ASSEMBLER="${REPO_ROOT}/os/images/scripts/assemble-installer-iso.sh"

for file in "${MEDIUM}" "${LOWER}" "${OVERLAY}" "${PREP}" \
    "${SYSROOT}" "${READY}" "${TARGET}" "${SWITCH_ROOT_PROOF}"; do
    [ -f "${file}" ] || fail "missing ${file#"${REPO_ROOT}/"}"
done
[ -x "${INITRD_BUILDER}" ] || fail 'installer initrd builder is not executable'
grep -Fq -- '--owner=0:0' "${INITRD_BUILDER}" \
    || fail 'installer initrd builder does not normalize archive ownership'

# All installer inputs are fixed below the read-only, non-executable medium.
assert_line "${MEDIUM}" 'What=/dev/disk/by-label/PUNAR_INSTALL'
assert_line "${MEDIUM}" 'Where=/run/punar/medium'
assert_line "${MEDIUM}" 'Type=iso9660'
assert_line "${MEDIUM}" 'Options=ro,nosuid,nodev,noexec'
assert_line "${LOWER}" 'What=/run/punar/medium/punar/live.erofs'
assert_line "${LOWER}" 'Type=erofs'
assert_line "${LOWER}" 'Options=loop,ro,nosuid,nodev'

# The only writable layer is volatile tmpfs. The real root is the bounded
# overlay assembled from that tmpfs and the verified read-only erofs.
assert_line "${OVERLAY}" 'What=tmpfs'
assert_line "${OVERLAY}" 'Where=/run/punar/overlay'
assert_line "${OVERLAY}" 'Options=mode=0755,nosuid,nodev'
assert_line "${PREP}" 'ExecStart=/usr/bin/mkdir -p /run/punar/overlay/upper /run/punar/overlay/work'
assert_line "${SYSROOT}" 'What=overlay'
assert_line "${SYSROOT}" 'Where=/sysroot'
assert_line "${SYSROOT}" 'Options=lowerdir=/run/punar/lower,upperdir=/run/punar/overlay/upper,workdir=/run/punar/overlay/work'

# Reaching initrd-root-fs.target must require the overlay and emit the exact
# serial marker used by both optical-drive and raw-hybrid boot gates.
assert_line "${TARGET}" 'Requires=sysroot.mount'
assert_line "${TARGET}" 'Wants=punar-installer-ready.service'
assert_line "${READY}" 'Requires=sysroot.mount'
assert_line "${READY}" 'ExecStart=/usr/bin/echo PUNAR_INSTALLER_OK'
assert_line "${READY}" 'TTYPath=/dev/ttyS0'

# A failed handoff must be diagnosable without turning the proof UART into a
# kernel console or enabling an emergency login.
assert_line "${SWITCH_ROOT_PROOF}" 'StandardOutput=tty'
assert_line "${SWITCH_ROOT_PROOF}" 'StandardError=tty'
assert_line "${SWITCH_ROOT_PROOF}" 'TTYPath=/dev/ttyS0'

# The proof marker may use QEMU's serial device directly, but the live kernel
# must not designate a serial console. That would widen the pre-install attack
# surface on physical hardware and violates the same A8 rule as the product.
assert_line "${INSTALLER_CONF}" \
    'KernelCommandLine=console=tty0 rd.systemd.gpt_auto=0 systemd.getty_auto=no punar.live=1'
if grep -Eq 'KernelCommandLine=.*console=(ttyS|ttyAMA)' "${INSTALLER_CONF}"; then
    fail 'installer kernel command line enables a serial console'
fi

# No unit may introduce a shell, caller-supplied environment expansion, a
# network dependency, or a writable boot-medium mount.
if rg -n '(sh -c|bash -c|EnvironmentFile=|curl|wget|network-online|Options=.*(^|,)rw(,|$))' \
    "${UNIT_ROOT}"; then
    fail 'live-root units contain an unbounded execution/network/write path'
fi

# The archive is injected before ukify links the UKI. Post-link objcopy growth
# is specifically forbidden because a successful command does not prove that
# the PE/COFF section allocation grew with the payload.
grep -Fq 'ARTIFACTDIR}/io.mkosi.initrd/90-punar-live.initrd' "${FINALIZER}" \
    || fail 'mkosi finalization does not publish the installer initrd artifact'
if grep -Fq 'objcopy --update-section ".initrd=' "${ASSEMBLER}"; then
    fail 'installer assembly still mutates the linked UKI initrd section'
fi
assert_line "${ASSEMBLER}" 'OPTICAL_ESP_LABEL=PUNAR_BOOT'
grep -Fq "\"\${#OPTICAL_ESP_LABEL}\" -le 11" "${ASSEMBLER}" \
    || fail 'installer assembly does not enforce the FAT label length limit'
grep -Fq "mkfs.vfat -F 16 -n \"\${OPTICAL_ESP_LABEL}\"" "${ASSEMBLER}" \
    || fail 'optical ESP does not use the validated FAT label'
assert_line "${ASSEMBLER}" "OPTICAL_ESP_BYTES=\$((31 * 1024 * 1024))"
grep -Fq 'OPTICAL_ESP_BYTES / 512)) -gt 65535' "${ASSEMBLER}" \
    || fail 'installer assembly does not enforce the El Torito load-sector limit'

echo 'installer-initrd-test: PASS'
