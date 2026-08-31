#!/usr/bin/env bash
# Static contract test for the declarative live-root initrd overlay.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
UNIT_ROOT="${REPO_ROOT}/os/images/installer-initrd/usr/lib/systemd/system"

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

for file in "${MEDIUM}" "${LOWER}" "${OVERLAY}" "${PREP}" \
    "${SYSROOT}" "${READY}" "${TARGET}"; do
    [ -f "${file}" ] || fail "missing ${file#"${REPO_ROOT}/"}"
done

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
assert_line "${READY}" 'TTYPath=/dev/console'

# No unit may introduce a shell, caller-supplied environment expansion, a
# network dependency, or a writable boot-medium mount.
if rg -n '(sh -c|bash -c|EnvironmentFile=|curl|wget|network-online|Options=.*(^|,)rw(,|$))' \
    "${UNIT_ROOT}"; then
    fail 'live-root units contain an unbounded execution/network/write path'
fi

echo 'installer-initrd-test: PASS'
