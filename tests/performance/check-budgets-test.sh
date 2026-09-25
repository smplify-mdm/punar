#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="${REPO_ROOT}/tests/performance/check-budgets.sh"
PASS_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-pass.txt"
TCG_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-tcg.txt"
HVF_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-hvf.txt"
MISSING_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-missing.txt"
OFFLINE_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-offline.txt"
NO_ZRAM_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-no-zram.txt"
SHORT_WINDOW_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-short-window.txt"
INITRAMFS_KEPT_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-initramfs-kept.txt"
INITRAMFS_NOTHING_FREED_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-initramfs-nothing-freed.txt"
INITRAMFS_NO_DROP_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-initramfs-no-drop.txt"
INITRAMFS_LATE_WARNING_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-initramfs-late-warning.txt"
INITRAMFS_NOT_NEEDED_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-initramfs-not-needed.txt"
UNIT_DIR="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system"

# cpu.stat/io.stat are not portable assumptions unless accounting is explicit
# on each measured service. One architecture exposed the controllers through a
# parent while another did not; pin the unit contract so that cannot regress.
for service in punard.service punar-agentd.service punar-secrets.service punar-netd.service; do
    grep -qx 'CPUAccounting=yes' "${UNIT_DIR}/${service}" \
        || { echo "FAIL: ${service} does not enable CPUAccounting" >&2; exit 1; }
    grep -qx 'IOAccounting=yes' "${UNIT_DIR}/${service}" \
        || { echo "FAIL: ${service} does not enable IOAccounting" >&2; exit 1; }
done

"${CHECKER}" "${PASS_REPORT}" >/dev/null 2>&1

if PUNAR_IDLE_CPU_HARD_BPS=10 "${CHECKER}" "${PASS_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a native KVM report above the per-service CPU ceiling passed" >&2
    exit 1
fi

if PUNAR_IDLE_CPU_HARD_BPS=10 "${CHECKER}" "${HVF_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a native Apple-HVF report above the per-service CPU ceiling passed" >&2
    exit 1
fi

if PUNAR_IDLE_CPU_HARD_BPS=10 "${CHECKER}" "${TCG_REPORT}" >/dev/null 2>&1; then
    :
else
    echo "FAIL: a numeric TCG CPU breach should be warn-only" >&2
    exit 1
fi

if PUNAR_IDLE_WRITE_HARD_BYTES=4096 "${CHECKER}" "${PASS_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a native KVM report above the first-party write ceiling passed" >&2
    exit 1
fi

if PUNAR_IDLE_WRITE_HARD_BYTES=4096 "${CHECKER}" "${HVF_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a native Apple-HVF report above the first-party write ceiling passed" >&2
    exit 1
fi

if PUNAR_IDLE_WRITE_HARD_BYTES=4096 "${CHECKER}" "${TCG_REPORT}" >/dev/null 2>&1; then
    :
else
    echo "FAIL: a numeric TCG write breach should be warn-only" >&2
    exit 1
fi

if "${CHECKER}" "${MISSING_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a report with no runtime facts passed" >&2
    exit 1
fi

if "${CHECKER}" "${OFFLINE_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: an otherwise complete native report with no network passed" >&2
    exit 1
fi

if "${CHECKER}" "${NO_ZRAM_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: an otherwise complete native report with no active zram passed" >&2
    exit 1
fi

if "${CHECKER}" "${SHORT_WINDOW_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a native report measured over less than five minutes passed" >&2
    exit 1
fi

if "${CHECKER}" "${INITRAMFS_KEPT_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a report whose initrd never freed the unpacked initramfs passed" >&2
    exit 1
fi

if "${CHECKER}" "${INITRAMFS_NOTHING_FREED_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a clean initramfs release line that freed nothing passed" >&2
    exit 1
fi

if "${CHECKER}" "${INITRAMFS_NO_DROP_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: an initramfs release whose memory figures did not fall passed" >&2
    exit 1
fi

if "${CHECKER}" "${INITRAMFS_LATE_WARNING_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: warnings between the initramfs release and the switch-root passed" >&2
    exit 1
fi

"${CHECKER}" "${INITRAMFS_NOT_NEEDED_REPORT}" >/dev/null 2>&1 || {
    echo "FAIL: a kernel that releases the initramfs by itself was not accepted" >&2
    exit 1
}

echo "PASS: stabilized-idle checker gates KVM/HVF CPU+writes + connected five-minute idle + zram + a freed initramfs (the kernel's figures, not the helper's word), rejects missing facts, and TCG-downgrades numeric evidence"
