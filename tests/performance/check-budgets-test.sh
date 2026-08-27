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

echo "PASS: stabilized-idle checker gates KVM/HVF CPU+writes + connected five-minute idle + zram, rejects missing facts, and TCG-downgrades numeric evidence"
