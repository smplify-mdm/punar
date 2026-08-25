#!/usr/bin/env bash
# Idle-RAM budget gate (PERFORMANCE_BUDGETS.md §1.1/§5.1; milestone-1.md §8).
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
# and the thresholds do NOT move (punard since M3, punar-agentd since M7 —
# milestone-7.md §11):
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
# TCG-emulated runs (PUNAR_RAM_ACCEL != kvm) NEVER fail the build on a
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

[ -f "${REPORT}" ] \
    || die "check-budgets: report not found: ${REPORT} (run tools/boot-test.sh --mode desktop first)"

MEAN_MB="$(get_field PUNAR_RAM_MEAN_MB)"
MAX_MB="$(get_field PUNAR_RAM_MAX_MB)"
ACCEL="$(get_field PUNAR_RAM_ACCEL)"
IMAGE="$(get_field PUNAR_RAM_IMAGE)"
SERVICES_MB="$(get_field PUNAR_SERVICES_RSS_MB)"
require_number PUNAR_RAM_MEAN_MB "${MEAN_MB}"
require_number PUNAR_RAM_MAX_MB "${MAX_MB}"

# Environment label per PERFORMANCE_BUDGETS.md §2.2: only KVM runs gate.
if [ "${ACCEL}" = "kvm" ]; then
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
echo "    services: ${SERVICES_MB:-missing} MB (summed PSS, punard + punar-agentd cgroups — §1.2/§2.3:"
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
# means punard was not alive at stabilized idle (or the report predates M3),
# which no emulation slowness explains. Numeric breaches follow the same
# TCG-downgrade rule as the whole-system gate above.
case "${SERVICES_MB:-missing}" in
    ''|missing|absent)
        annotate error "Punar services RSS is '${SERVICES_MB:-missing}' — a Punar service (punard.service or punar-agentd.service) was not running at stabilized idle, or the guest never emitted PUNAR_SERVICES_RSS_MB; a dead daemon is a gate failure even on emulated runs (milestone-3.md §9, milestone-7.md §11)"
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

if [ "${EMULATED}" -eq 1 ]; then
    annotate warning "RAM numbers are from a TCG-emulated run ${LABEL}: indicative only, never a source of published baselines (PERFORMANCE_BUDGETS.md §5.2)"
fi

if [ "${fail}" -eq 1 ]; then
    echo "==> FAIL: RAM budget gate (whole-system idle and/or Punar services)" >&2
    exit 1
fi
echo "==> PASS: RAM budget gate (whole-system idle + Punar services)"
