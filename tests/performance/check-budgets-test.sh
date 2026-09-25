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
SMPLIFYD_RESIDENT_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-smplifyd-resident.txt"
DOUBLE_COUNT_REPORT="${REPO_ROOT}/tests/performance/fixtures/stabilized-idle-double-count.txt"
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

# The Smplify agent is dormant until enrolled: a resident agent, a missing
# count and a socket that is not listening each fail, even under TCG.
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
if "${CHECKER}" "${SMPLIFYD_RESIDENT_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a report with a Smplify agent running on an unenrolled image passed" >&2
    exit 1
fi
sed 's/^PUNAR_SMPLIFYD_PROCS=0$/PUNAR_SMPLIFYD_PROCS=2/' "${TCG_REPORT}" > "${WORK}/tcg-resident.txt"
if "${CHECKER}" "${WORK}/tcg-resident.txt" >/dev/null 2>&1; then
    echo "FAIL: a resident Smplify agent was downgraded under TCG" >&2
    exit 1
fi
grep -v '^PUNAR_SMPLIFYD_PROCS=' "${PASS_REPORT}" > "${WORK}/no-count.txt"
if "${CHECKER}" "${WORK}/no-count.txt" >/dev/null 2>&1; then
    echo "FAIL: a report without the Smplify agent's process count passed" >&2
    exit 1
fi
sed 's/^PUNAR_SMPLIFYD_SOCKET=active$/PUNAR_SMPLIFYD_SOCKET=failed/' "${PASS_REPORT}" > "${WORK}/no-socket.txt"
if "${CHECKER}" "${WORK}/no-socket.txt" >/dev/null 2>&1; then
    echo "FAIL: a report whose Smplify agent socket is not listening passed" >&2
    exit 1
fi

# The whole guest's writes are attributed without a double count: the
# kernel/filesystem remainder is the device total minus the cgroups, never
# plus them, and every attribution fact must be there. Even under TCG: this
# is the sampler's arithmetic, not a measurement.
if "${CHECKER}" "${DOUBLE_COUNT_REPORT}" >/dev/null 2>&1; then
    echo "FAIL: a remainder computed as the device plus the cgroups passed" >&2
    exit 1
fi
sed 's/^PUNAR_IDLE_WRITE_KERNEL_FS_BYTES=.*/PUNAR_IDLE_WRITE_KERNEL_FS_BYTES=5619712/' \
    "${TCG_REPORT}" > "${WORK}/tcg-double-count.txt"
if "${CHECKER}" "${WORK}/tcg-double-count.txt" >/dev/null 2>&1; then
    echo "FAIL: a double-counted attribution was downgraded under TCG" >&2
    exit 1
fi
for fact in DEVICE JOURNALD CGROUPS KERNEL_FS; do
    grep -v "^PUNAR_IDLE_WRITE_${fact}_BYTES=" "${PASS_REPORT}" > "${WORK}/no-${fact}.txt"
    if "${CHECKER}" "${WORK}/no-${fact}.txt" >/dev/null 2>&1; then
        echo "FAIL: a report without PUNAR_IDLE_WRITE_${fact}_BYTES passed" >&2
        exit 1
    fi
done
sed 's/^PUNAR_IDLE_WRITE_DEVICE_SOURCE=.*/PUNAR_IDLE_WRITE_DEVICE_SOURCE=guessed/' \
    "${PASS_REPORT}" > "${WORK}/bad-source.txt"
if "${CHECKER}" "${WORK}/bad-source.txt" >/dev/null 2>&1; then
    echo "FAIL: a device total from an unnamed source passed" >&2
    exit 1
fi
# Counters flushed at different moments can put the cgroups a few pages
# ahead of the disk: the remainder is then zero, which is consistent.
sed -e 's/^PUNAR_IDLE_WRITE_CGROUPS_BYTES=.*/PUNAR_IDLE_WRITE_CGROUPS_BYTES=4415488/' \
    -e 's/^PUNAR_IDLE_WRITE_KERNEL_FS_BYTES=.*/PUNAR_IDLE_WRITE_KERNEL_FS_BYTES=0/' \
    "${PASS_REPORT}" > "${WORK}/cgroups-ahead.txt"
if ! "${CHECKER}" "${WORK}/cgroups-ahead.txt" >/dev/null 2>&1; then
    echo "FAIL: cgroup counters a page ahead of the disk were rejected" >&2
    exit 1
fi

echo "PASS: stabilized-idle checker gates KVM/HVF CPU+writes + connected five-minute idle + zram + the dormant Smplify agent + write attribution without a double count, rejects missing facts, and TCG-downgrades numeric evidence"
