#!/usr/bin/env bash
# Cheap wiring guard for stabilized-window memory attribution. The runtime
# desktop gate proves the contents; this catches a renamed or dropped file
# before an expensive image boot silently loses the diagnostic evidence.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IDLE_RAM="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/idle-ram.sh"
BOOT_TEST="${REPO_ROOT}/tools/boot-test.sh"
WORKFLOW="${REPO_ROOT}/.github/workflows/ci.yml"

fail() {
    echo "memory-attribution-contract-test: FAIL: $*" >&2
    exit 1
}

require_literal() {
    local file=$1 literal=$2 reason=$3
    grep -Fq -- "${literal}" "${file}" || fail "${reason}"
}

require_literal "${IDLE_RAM}" \
    "cp /proc/meminfo \"\${RUN_DIR}/ram-meminfo-start.txt\"" \
    'the stabilized window has no start meminfo snapshot'
require_literal "${IDLE_RAM}" \
    "cp /proc/meminfo \"\${RUN_DIR}/ram-meminfo-end.txt\"" \
    'the stabilized window has no end meminfo snapshot'
for field in Pss: Locked: Pss_Anon: Pss_File: Pss_Shmem:; do
    require_literal "${IDLE_RAM}" "/^${field}/" \
        "the process attribution omits ${field}"
done
for artifact in ram-process-memory.txt ram-meminfo-start.txt ram-meminfo-end.txt; do
    occurrences="$(grep -Fc -- "${artifact}" "${BOOT_TEST}")"
    [ "${occurrences}" -ge 2 ] \
        || fail "boot-test does not both clean and export ${artifact}"
    require_literal "${WORKFLOW}" \
        "os/images/out/desktop-proof/${artifact}" \
        "CI does not retain ${artifact}"
done

# The whole guest's idle writes: the journal as its own counter, every
# top-level cgroup summed, and the kernel/filesystem remainder as the device
# total MINUS that sum. A remainder of root plus children counts every
# charged byte twice (the root's io.stat is the whole disk's own counter).
require_literal "${IDLE_RAM}" \
    '/sys/fs/cgroup/system.slice/systemd-journald.service/io.stat' \
    'the journal is not counted on its own'
require_literal "${IDLE_RAM}" "\"\$(io_write_bytes /sys/fs/cgroup/io.stat)\"" \
    'the device total is not read from the root cgroup'
require_literal "${IDLE_RAM}" 'for cgroup in /sys/fs/cgroup/*/; do' \
    'the top-level cgroups are not summed'
require_literal "${IDLE_RAM}" \
    "kernel_fs_write_bytes=\$((device_write_bytes - cgroups_write_bytes))" \
    'the kernel/filesystem remainder is not the device total minus the cgroups'
if grep -Eq 'device_write_bytes *\+ *cgroups_write_bytes|cgroups_write_bytes *\+ *device_write_bytes' \
        "${IDLE_RAM}"; then
    fail 'the device total is added to the cgroups: every charged byte counted twice'
fi
# The first-party services' write counter covers the same disks as every
# whole-guest figure: summing every device in their io.stat (zram swap-out,
# loop devices) made the breakdown mix a filtered and an unfiltered counter.
require_literal "${IDLE_RAM}" "write_bytes=\"\$(io_write_bytes \"\${cgroup}/io.stat\")\"" \
    'the first-party write counter is not filtered to the same disks'
for fact in DEVICE_BYTES DEVICE_SOURCE JOURNALD_BYTES CGROUPS_BYTES KERNEL_FS_BYTES; do
    require_literal "${IDLE_RAM}" "emit_fact \"PUNAR_IDLE_WRITE_${fact}=" \
        "the sampler does not report PUNAR_IDLE_WRITE_${fact}"
done
require_literal "${BOOT_TEST}" "'^PUNAR_(IDLE_|" \
    'boot-test does not carry the PUNAR_IDLE_ facts into ram-report.txt'

echo 'PUNAR_MEMORY_ATTRIBUTION_CONTRACT_OK'
