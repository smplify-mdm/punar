#!/usr/bin/env bash
# Stabilized-idle performance budget gate (PERFORMANCE_BUDGETS.md §1/§5.1).
#
# Reads the ram-report.txt produced by `tools/boot-test.sh --mode desktop`
# and applies the whole-system idle-RAM budgets:
#
#   mean > 1536 MB (1.5 GB hard ceiling)  ::error::   -> exit 1 (release blocker)
#   mean > 1024 MB (1.0 GB target)        ::warning:: -> exit 0
#   max  > 1536 MB                        ::warning:: (informational until a
#                                         baseline lands in PERFORMANCE_BUDGETS.md §4;
#                                         the gate is on the MEAN — survey
#                                         decision, milestone-1.md §8)
#
# Since M3 it also gates the Punar services RAM (PERFORMANCE_BUDGETS.md
# §1.2/§2.3; milestone-3.md §9) from the same report. The number is the
# COMBINED services total, never per-daemon: spec 6.2 budgets the services
# together, so as sibling daemons ship they are summed into the same value
# and the thresholds do NOT move (punard since M3, punar-agentd since M7,
# punar-secrets since M9 — milestone-7.md §11, milestone-9.md §11). Adding a
# daemon and leaving it out of the sum, or raising a threshold to make room
# for one, would both make this gate say something untrue:
#
#   PUNAR_SERVICES_RSS_MB > 150 (MVP ceiling)  ::error::   -> exit 1
#   PUNAR_SERVICES_RSS_MB > 100 (target)       ::warning:: -> exit 0
#   absent / missing / non-numeric             ::error::   -> exit 1
#                                              (EVERY Punar service must be
#                                              alive at idle — EVEN under
#                                              TCG: a dead daemon is not an
#                                              emulation artifact, and one
#                                              live sibling must not be able
#                                              to mask another's absence)
#
# The variable name says RSS (fixed consumer contract); the value is the
# summed PSS of the pids in every Punar service cgroup (§2.3 canonical
# metric — cgroup attribution, never process-name matching).
#
# The same five-minute window carries enforceable idle-CPU and first-party
# write contracts (PERFORMANCE_BUDGETS.md §1.3–1.4/§2.4–2.5):
#
#   max first-party cgroup >= 0.50% of one CPU    ::error:: -> exit 1
#   combined Punar service writes > 65,536 bytes  ::error:: -> exit 1
#   short/missing runtime, network or zram facts  ::error:: -> exit 1
#
# CPU is stored in hundredths of a percentage point (`bps`): 50 is 0.50%.
# The write ceiling is the engineering interpretation recorded after two
# native Apple-HVF windows each wrote exactly 8,192 first-party bytes. The
# 64 KiB ceiling leaves 8x headroom for legitimate batches while rejecting a
# sustained writer. Whole-guest block writes remain context only because they
# include the journal, package-independent services and filesystem metadata.
#
# TCG-emulated runs (`PUNAR_RAM_ACCEL=tcg`) NEVER fail the build on a
# NUMERIC breach: the numbers are labeled "(VM, emulated)" and indicative
# only (PERFORMANCE_BUDGETS.md §2.2/§5.2) — ceiling breaches are downgraded
# to warning annotations. The absent/missing services value is the one
# exception (above).
#
# Usage: tests/performance/check-budgets.sh [ram-report.txt]
#        (default: os/images/out/desktop-proof/ram-report.txt)
# Environment (testing/iteration only — overriding budgets is NON-CANONICAL;
# the real numbers are spec-owned, see PERFORMANCE_BUDGETS.md §6):
#   PUNAR_RAM_HARD_MB         hard ceiling in MB (default 1536)
#   PUNAR_RAM_TARGET_MB       target in MB (default 1024)
#   PUNAR_SERVICES_HARD_MB    services ceiling in MB (default 150)
#   PUNAR_SERVICES_TARGET_MB  services target in MB (default 100)
#   PUNAR_IDLE_CPU_HARD_BPS   per-service CPU ceiling, hundredths of one
#                             percentage point (default 50 = 0.50%)
#   PUNAR_IDLE_WRITE_HARD_BYTES combined first-party write ceiling per
#                               five-minute window (default 65536 = 64 KiB)
#
# GitHub annotations (::error:: / ::warning::) are emitted only when
# GITHUB_ACTIONS=true; locally the same text goes to stderr.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT="${1:-${REPO_ROOT}/os/images/out/desktop-proof/ram-report.txt}"

# Budget numbers mirror PERFORMANCE_BUDGETS.md §1.1 (which mirrors spec §6)
# and must not drift from it: 1.5 GB hard ceiling, 1.0 GB target.
HARD_MB="${PUNAR_RAM_HARD_MB:-1536}"
TARGET_MB="${PUNAR_RAM_TARGET_MB:-1024}"
# Punar services (combined) — PERFORMANCE_BUDGETS.md §1.2: < 100 MB target,
# < 150 MB MVP ceiling, judged against summed PSS (§2.3).
SERVICES_HARD_MB="${PUNAR_SERVICES_HARD_MB:-150}"
SERVICES_TARGET_MB="${PUNAR_SERVICES_TARGET_MB:-100}"
IDLE_CPU_HARD_BPS="${PUNAR_IDLE_CPU_HARD_BPS:-50}"
IDLE_WRITE_HARD_BYTES="${PUNAR_IDLE_WRITE_HARD_BYTES:-65536}"

fail=0

annotate() {
    # annotate <error|warning|notice> <message>
    local level="$1"
    shift
    echo "${level}: $*" >&2
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::${level}::$*"
    fi
}

die() {
    annotate error "$*"
    exit 1
}

get_field() {
    awk -F= -v key="$1" '$1 == key { print $2; exit }' "${REPORT}"
}

require_number() {
    # require_number <name> <value>
    case "$2" in
        ''|*[!0-9]*)
            die "check-budgets: field $1 missing or non-numeric in ${REPORT} (got: '${2}')"
            ;;
    esac
}

format_bps() {
    printf '%d.%02d%%' "$((10#$1 / 100))" "$((10#$1 % 100))"
}

[ -f "${REPORT}" ] \
    || die "check-budgets: report not found: ${REPORT} (run tools/boot-test.sh --mode desktop first)"
require_number PUNAR_IDLE_CPU_HARD_BPS "${IDLE_CPU_HARD_BPS}"
require_number PUNAR_IDLE_WRITE_HARD_BYTES "${IDLE_WRITE_HARD_BYTES}"

MEAN_MB="$(get_field PUNAR_RAM_MEAN_MB)"
MAX_MB="$(get_field PUNAR_RAM_MAX_MB)"
ACCEL="$(get_field PUNAR_RAM_ACCEL)"
IMAGE="$(get_field PUNAR_RAM_IMAGE)"
SERVICES_MB="$(get_field PUNAR_SERVICES_RSS_MB)"
RUNTIME_PRESENT="$(get_field PUNAR_IDLE_RUNTIME_PRESENT)"
IDLE_WINDOW_MS="$(get_field PUNAR_IDLE_WINDOW_MS)"
IDLE_CPU_MAX_BPS="$(get_field PUNAR_IDLE_CPU_MAX_BPS)"
IDLE_SERVICE_WRITE_BYTES="$(get_field PUNAR_IDLE_SERVICE_WRITE_BYTES)"
IDLE_SYSTEM_CPU_BPS="$(get_field PUNAR_IDLE_SYSTEM_CPU_BPS)"
IDLE_BLOCK_WRITE_BYTES="$(get_field PUNAR_IDLE_BLOCK_WRITE_BYTES)"
NETWORK_ONLINE="$(get_field PUNAR_NETWORK_ONLINE)"
ZRAM_PRESENT="$(get_field PUNAR_ZRAM_PRESENT)"
ZRAM_DISKSIZE_MB="$(get_field PUNAR_ZRAM_DISKSIZE_MB)"
ZRAM_ALGORITHM="$(get_field PUNAR_ZRAM_ALGORITHM)"
ZRAM_SWAP_ACTIVE="$(get_field PUNAR_ZRAM_SWAP_ACTIVE)"
require_number PUNAR_RAM_MEAN_MB "${MEAN_MB}"
require_number PUNAR_RAM_MAX_MB "${MAX_MB}"

# Environment label per PERFORMANCE_BUDGETS.md §2.2: native KVM and native
# Apple-HVF runs gate; only TCG software emulation downgrades numeric breaches.
if [ "${ACCEL}" = "kvm" ] || [ "${ACCEL}" = "hvf" ]; then
    LABEL="(VM)"
    EMULATED=0
else
    LABEL="(VM, emulated)"
    EMULATED=1
fi

echo "==> Idle-RAM budget check ${LABEL}"
echo "    report:  ${REPORT}"
echo "    image:   ${IMAGE:-unknown}"
echo "    mean:    ${MEAN_MB} MB"
echo "    max:     ${MAX_MB} MB"
echo "    target:  ${TARGET_MB} MB   hard ceiling: ${HARD_MB} MB (PERFORMANCE_BUDGETS.md §1.1)"
echo "    services: ${SERVICES_MB:-missing} MB (summed PSS, punard + punar-agentd + punar-secrets cgroups — §1.2/§2.3:"
echo "              target ${SERVICES_TARGET_MB} MB, MVP ceiling ${SERVICES_HARD_MB} MB)"

if [ "${MEAN_MB}" -gt "${HARD_MB}" ]; then
    if [ "${EMULATED}" -eq 1 ]; then
        annotate warning "idle RAM mean ${MEAN_MB} MB ${LABEL} exceeds the ${HARD_MB} MB hard ceiling, but this is a TCG-emulated run — indicative only, not gated (PERFORMANCE_BUDGETS.md §5.2)"
    else
        annotate error "idle RAM mean ${MEAN_MB} MB ${LABEL} exceeds the ${HARD_MB} MB (1.5 GB) hard ceiling — release blocker (PERFORMANCE_BUDGETS.md §1.1)"
        fail=1
    fi
elif [ "${MEAN_MB}" -gt "${TARGET_MB}" ]; then
    annotate warning "idle RAM mean ${MEAN_MB} MB ${LABEL} is over the ${TARGET_MB} MB (1.0 GB) target (hard ceiling ${HARD_MB} MB not exceeded)"
else
    echo "==> OK: idle RAM mean ${MEAN_MB} MB ${LABEL} is within the ${TARGET_MB} MB target"
fi

if [ "${MAX_MB}" -gt "${HARD_MB}" ]; then
    annotate warning "idle RAM max ${MAX_MB} MB ${LABEL} exceeds the ${HARD_MB} MB hard ceiling (informational: the gate is on the mean until a baseline is recorded — milestone-1.md §8)"
fi

# --- Punar services RAM gate (M3; PERFORMANCE_BUDGETS.md §1.2/§2.3,
# milestone-3.md §9). absent/missing/non-numeric fails EVEN under TCG: it
# means a Punar daemon was not alive at stabilized idle (or the report
# predates M3),
# which no emulation slowness explains. Numeric breaches follow the same
# TCG-downgrade rule as the whole-system gate above.
case "${SERVICES_MB:-missing}" in
    ''|missing|absent)
        annotate error "Punar services RSS is '${SERVICES_MB:-missing}' — a Punar service (punard.service, punar-agentd.service or punar-secrets.service) was not running at stabilized idle, or the guest never emitted PUNAR_SERVICES_RSS_MB; a dead daemon is a gate failure even on emulated runs (milestone-3.md §9, milestone-7.md §11, milestone-9.md §11)"
        fail=1
        ;;
    *[!0-9]*)
        annotate error "check-budgets: field PUNAR_SERVICES_RSS_MB is non-numeric in ${REPORT} (got: '${SERVICES_MB}')"
        fail=1
        ;;
    *)
        if [ "${SERVICES_MB}" -gt "${SERVICES_HARD_MB}" ]; then
            if [ "${EMULATED}" -eq 1 ]; then
                annotate warning "Punar services RSS ${SERVICES_MB} MB ${LABEL} exceeds the ${SERVICES_HARD_MB} MB MVP ceiling, but this is a TCG-emulated run — indicative only, not gated (PERFORMANCE_BUDGETS.md §5.2)"
            else
                annotate error "Punar services RSS ${SERVICES_MB} MB ${LABEL} exceeds the ${SERVICES_HARD_MB} MB MVP ceiling (summed PSS — PERFORMANCE_BUDGETS.md §1.2)"
                fail=1
            fi
        elif [ "${SERVICES_MB}" -gt "${SERVICES_TARGET_MB}" ]; then
            annotate warning "Punar services RSS ${SERVICES_MB} MB ${LABEL} is over the ${SERVICES_TARGET_MB} MB target (MVP ceiling ${SERVICES_HARD_MB} MB not exceeded)"
        else
            echo "==> OK: Punar services RSS ${SERVICES_MB} MB ${LABEL} is within the ${SERVICES_TARGET_MB} MB target"
        fi
        ;;
esac

# --- Stabilized idle CPU + writes. Absence fails on every accelerator: it
# means the shipped sampler did not produce the evidence, not that emulation
# was slow. Numeric CPU/write breaches follow RAM's TCG downgrade rule.
if [ "${RUNTIME_PRESENT}" != "yes" ]; then
    annotate error "idle runtime facts are incomplete or missing (PUNAR_IDLE_RUNTIME_PRESENT='${RUNTIME_PRESENT:-missing}') — every Punar service cgroup must expose CPU and I/O counters"
    fail=1
fi
if [ "${NETWORK_ONLINE}" != "yes" ]; then
    annotate error "stabilized idle was not DHCP-connected (PUNAR_NETWORK_ONLINE='${NETWORK_ONLINE:-missing}') — the canonical method requires a live non-loopback link and default route"
    fail=1
fi

for field_and_value in \
    "PUNAR_IDLE_WINDOW_MS:${IDLE_WINDOW_MS}" \
    "PUNAR_IDLE_CPU_MAX_BPS:${IDLE_CPU_MAX_BPS}" \
    "PUNAR_IDLE_SERVICE_WRITE_BYTES:${IDLE_SERVICE_WRITE_BYTES}" \
    "PUNAR_IDLE_SYSTEM_CPU_BPS:${IDLE_SYSTEM_CPU_BPS}" \
    "PUNAR_IDLE_BLOCK_WRITE_BYTES:${IDLE_BLOCK_WRITE_BYTES}" \
    "PUNAR_ZRAM_DISKSIZE_MB:${ZRAM_DISKSIZE_MB}"; do
    field="${field_and_value%%:*}"
    value="${field_and_value#*:}"
    case "${value}" in
        ''|*[!0-9]*)
            annotate error "check-budgets: field ${field} missing or non-numeric in ${REPORT} (got: '${value}')"
            fail=1
            ;;
    esac
done

if [ -n "${IDLE_WINDOW_MS}" ] && case "${IDLE_WINDOW_MS}" in *[!0-9]*) false ;; *) true ;; esac \
    && [ "${IDLE_WINDOW_MS}" -lt 300000 ]; then
    annotate error "stabilized-idle window was ${IDLE_WINDOW_MS} ms, shorter than the canonical 300000 ms"
    fail=1
fi

if [ "${ZRAM_PRESENT}" != yes ]; then
    annotate error "live zram device is absent (PUNAR_ZRAM_PRESENT='${ZRAM_PRESENT:-missing}')"
    fail=1
fi
if [ "${ZRAM_SWAP_ACTIVE}" != yes ]; then
    annotate error "zram is not an active swap device (PUNAR_ZRAM_SWAP_ACTIVE='${ZRAM_SWAP_ACTIVE:-missing}')"
    fail=1
fi
case "${ZRAM_ALGORITHM}" in
    ''|unknown)
        annotate error "active zram compression algorithm is not observable (PUNAR_ZRAM_ALGORITHM='${ZRAM_ALGORITHM:-missing}')"
        fail=1
        ;;
esac
if [ -n "${ZRAM_DISKSIZE_MB}" ] && case "${ZRAM_DISKSIZE_MB}" in *[!0-9]*) false ;; *) true ;; esac \
    && [ "${ZRAM_DISKSIZE_MB}" -eq 0 ]; then
    annotate error "zram device has zero capacity"
    fail=1
fi

if [ -n "${IDLE_CPU_MAX_BPS}" ] && case "${IDLE_CPU_MAX_BPS}" in *[!0-9]*) false ;; *) true ;; esac; then
    echo "    idle CPU: max first-party cgroup $(format_bps "${IDLE_CPU_MAX_BPS}") of one CPU; ceiling $(format_bps "${IDLE_CPU_HARD_BPS}")"
    if [ -n "${IDLE_SYSTEM_CPU_BPS}" ] && case "${IDLE_SYSTEM_CPU_BPS}" in *[!0-9]*) false ;; *) true ;; esac; then
        echo "              whole guest $(format_bps "${IDLE_SYSTEM_CPU_BPS}") across available CPUs (context only)"
    fi
    if [ "${IDLE_CPU_MAX_BPS}" -ge "${IDLE_CPU_HARD_BPS}" ]; then
        if [ "${EMULATED}" -eq 1 ]; then
            annotate warning "max first-party cgroup idle CPU $(format_bps "${IDLE_CPU_MAX_BPS}") ${LABEL} meets or exceeds the $(format_bps "${IDLE_CPU_HARD_BPS}") ceiling, but this is a TCG-emulated run — indicative only"
        else
            annotate error "max first-party cgroup idle CPU $(format_bps "${IDLE_CPU_MAX_BPS}") ${LABEL} meets or exceeds the $(format_bps "${IDLE_CPU_HARD_BPS}") ceiling (PERFORMANCE_BUDGETS.md §2.4)"
            fail=1
        fi
    else
        echo "==> OK: every first-party cgroup remained within the idle-CPU ceiling"
    fi
fi

if [ -n "${IDLE_SERVICE_WRITE_BYTES}" ] && case "${IDLE_SERVICE_WRITE_BYTES}" in *[!0-9]*) false ;; *) true ;; esac; then
    echo "    idle writes: ${IDLE_SERVICE_WRITE_BYTES} first-party service bytes; ceiling ${IDLE_WRITE_HARD_BYTES} bytes/5 min"
    echo "                 ${IDLE_BLOCK_WRITE_BYTES:-?} whole-guest block bytes (context only)"
    if [ "${IDLE_SERVICE_WRITE_BYTES}" -gt "${IDLE_WRITE_HARD_BYTES}" ]; then
        if [ "${EMULATED}" -eq 1 ]; then
            annotate warning "Punar first-party idle writes ${IDLE_SERVICE_WRITE_BYTES} bytes ${LABEL} exceed the ${IDLE_WRITE_HARD_BYTES}-byte five-minute ceiling, but this is a TCG-emulated run — indicative only"
        else
            annotate error "Punar first-party idle writes ${IDLE_SERVICE_WRITE_BYTES} bytes ${LABEL} exceed the ${IDLE_WRITE_HARD_BYTES}-byte five-minute ceiling (PERFORMANCE_BUDGETS.md §2.5)"
            fail=1
        fi
    else
        echo "==> OK: Punar first-party writes remained within the stabilized-idle ceiling"
    fi
fi

if [ "${EMULATED}" -eq 1 ]; then
    annotate warning "performance numbers are from a TCG-emulated run ${LABEL}: indicative only, never a source of published baselines (PERFORMANCE_BUDGETS.md §5.2)"
fi

if [ "${fail}" -eq 1 ]; then
    echo "==> FAIL: stabilized-idle performance budget gate" >&2
    exit 1
fi
echo "==> PASS: stabilized-idle performance gate (RAM + services PSS + CPU + first-party writes + zram)"
