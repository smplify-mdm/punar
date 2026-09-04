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

echo 'PUNAR_MEMORY_ATTRIBUTION_CONTRACT_OK'
