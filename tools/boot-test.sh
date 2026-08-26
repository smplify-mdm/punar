#!/usr/bin/env bash
# QEMU boot test for the Punar images (spec 74.3 "boot"; milestone-1.md §7–§10).
#
# Two modes, chosen with --mode or inferred from the image filename
# (*punar-desktop* -> desktop, anything else -> minimal):
#
# minimal (M0 smoke test — behavior unchanged from Milestone 0):
#   Boots the qcow2 headless under UEFI (OVMF/edk2) with the serial console
#   on ttyS0 captured to a log, and waits for a deterministic marker:
#     primary:  "PUNAR_BOOT_OK"  — punar-boot-marker.service at multi-user
#     fallback: a getty "login:" prompt on the serial console
#
# desktop (M1 graphical acceptance gate — milestone-1.md §7–§9):
#   Boots with the survey-decided VM shape for the minimum-target machine
#   (PERFORMANCE_BUDGETS.md §5.1: -m 8192 -smp 4) and -device virtio-vga
#   (no virgl; the guest renders via mesa llvmpipe), plus a dedicated
#   virtio-serial export channel (name=punar.export), then waits through
#   three phases on the serial console:
#     1. "PUNAR_DESKTOP_OK"      compositor up + punar-shell constructed
#                                (punar-desktop-marker.service)
#     2. "PUNAR_RAM_MEAN_MB=<n> PUNAR_RAM_MAX_MB=<n>"
#                                canonical idle-RAM measurement, performed
#                                IN THE GUEST by punar-idle-ram.service with
#                                the method fixed by PERFORMANCE_BUDGETS.md
#                                §2.1–2.2 (10 min stabilize after the
#                                graphical session is up, then a 5-minute
#                                window sampling MemTotal - MemAvailable
#                                every 10 s; mean and max). This script only
#                                waits for and records the guest's numbers —
#                                it does not sample, and it does not shorten
#                                the canonical stabilization.
#     3. "PUNAR_EXPORT_END" on the export channel — the guest streams
#        `tar -C /run/punar | base64` (screenshot.png, meminfo,
#        ram-samples.txt, and since M2 the m2-report.txt / punar-m2.png /
#        m2-*.json exercise artifacts) between PUNAR_EXPORT_BEGIN/END
#        sentinels. The M2 exercise (punar-m2-check.service, started by
#        idle-ram.sh strictly between the sampling window and the export)
#        runs inside this phase's wait — EXPORT_TIMEOUT covers it.
#     4. M2 verdict (milestone-2.md §7): parse the exported m2-report.txt.
#        PUNAR_M2_FAIL (or a truncated report) hard-fails the gate; a
#        MISSING report is a ::warning:: under KVM and info-only under TCG
#        (an emulated run that could not even export is already flagged).
#     5. M3 verdict (milestone-3.md §8): same pattern for m3-report.txt
#        (punar-m3-check.service — daemon/CLI/authz/audit/firewall
#        exercise, run after the M2 exercise, before the export). Phase 2
#        additionally captures PUNAR_SERVICES_RSS_MB=<n|absent> — the
#        guest's summed-PSS reading of the Punar service cgroups at idle
#        (punard.service since M3, plus punar-agentd.service since M7 —
#        PERFORMANCE_BUDGETS.md §2.3) — into ram-report.txt for
#        check-budgets.sh (fail > 150 MB, warn > 100 MB; absent/missing
#        fails even under TCG).
#     6. M4 verdict (milestone-4.md §10): same pattern for m4-report.txt
#        (punar-m4-check.service — policy effective/explain provenance,
#        preference-layer set cycle, section 52 compliance in status, and
#        the timer-driven firewall-drift demo: nft destroy -> the vendored
#        punard-reconcile.timer's reconcile restores the table within
#        375 s and audits reconcile.remediate — run after the M3 exercise,
#        before the export; EXPORT_TIMEOUT covers its worst case).
#     7. M5 verdict (milestone-5.md §10): same pattern for m5-report.txt
#        (punar-m5-check.service — the full enrollment journey against the
#        in-VM dev/CI mock control plane: enroll -> managed policy/explain/
#        set -> category-only compliance/inventory sync -> offline ->
#        recovery -> offline unenroll -> personal restore, plus the
#        enrolled/personal bar screenshots — run after the M4 exercise,
#        before the export).
#     8. M6 verdict (milestone-6.md §10): same pattern for m6-report.txt
#        (punar-m6-check.service — the punar-env developer-environment
#        journey as the punar user against rootless podman: preloaded
#        offline base image load, init idempotence + scaffold, up with
#        --network none and the /workspace bind, shell exit-code
#        passthrough, D-014 status render with the declared/enforcement
#        labels verbatim, agent stub honesty, destroy — run after the M5
#        exercise, before the export; no screenshots, m6-status.txt is
#        the human evidence).
#     9. M7 verdict (milestone-7.md §12): same pattern for m7-report.txt
#        (punar-m7-check.service — the AI agent registry journey: the
#        punar-agentd daemon/socket preflight, a MOCK managed session
#        launched through `punar-env agent claude-code` (the offline VM has
#        no real agent binary), registry truth in registry.jsonl, scope
#        cgroup attribution, `punarctl agents inspect`, a real innocuous
#        process detected as UNKNOWN and SUSPECTED, /run/punar/agents.json,
#        the AI-panel screenshot with both rows, end of life, the audit
#        lifecycle lines and negative probes on the new socket — run after
#        the M6 exercise, before the export).
#    10. M8 verdict (milestone-8.md §12): same pattern for m8-report.txt
#        (punar-m8-check.service — the AI Access Ledger journey: the
#        ledger-store preflight, a managed mock session whose children are
#        generated deterministically (fifo-blocked shell + git, plus one
#        short-lived capability call punard denies), the scope cgroup read
#        straight from /sys/fs/cgroup, the schema-exact `agents.access`
#        summary with honest not-yet-observed rows for network destinations
#        (M12), MCP servers (M9+) and credential classes (M9), the Level-4
#        denial joined to the audit trail BY EVENT ID, the privacy
#        regression asserting no path/argv/comm ever reached disk, the
#        counts-only agents.list fingerprint, the panel screenshot, the
#        14-day retention deadline, an owner purge and its tombstone, the
#        no-resurrection drain, a retention prune against an injected
#        backdated ledger, and negative probes proving no export path
#        exists — run after the M7 exercise, before the export).
#    11. M9 verdict (milestone-9.md §12): same pattern for m9-report.txt
#        (punar-m9-check.service — the approval gate, the credential broker
#        and just-in-time privilege: the punar-secrets preflight (socket
#        modes, the root-owned approval/grant stores, the vendor .wants
#        symlink AND multi-user.target Wants=), an agent-originated
#        capabilities.set answered `approval_required` with exit 4 and
#        NOTHING applied (checked against a live nft read, never a cached
#        descriptor), the pending approval object validated TWICE — by jq
#        in the guest and, on this host, against schemas/audit/approval.json
#        — the agent's own attempt to resolve it refused and audited as
#        self_approval_refused, the Plate D-003 overlay screenshot with the
#        card on screen asserted through the shell's own IPC, the human
#        resolve that finally executes the mutation with BOTH pointer
#        directions and BOTH identities in the trail, an unanswered approval
#        expiring without executing anything, allow/request/deny credential
#        classes against the MOCK provider, a 5-second credential really
#        expiring and a revoke really revoking, THE REDACTION SWEEP (every
#        issued value grepped for across every file Punar writes, the whole
#        export tar, the journal and every punar process's environ and
#        cmdline, with a negative control), the M8 ledger's credential rows
#        filling in for real, a one-minute privilege grant that works and
#        then does not, and the negative probes — run after the M8 exercise,
#        before the export).
#    12. M10 verdict (milestone-10.md §16): same pattern for m10-report.txt
#        (punar-m10-check.service — the shadow-AI detection MVP: the scan
#        timer's vendor-wants symlink and 240 s cadence asserted from
#        `systemctl show`, a real sleeping fixture in ~punar/Downloads
#        detected BY THE TIMER with no manual scan in the window (proved
#        from the trigger recorded in the audit event), exactly one alert
#        per signature across repeated passes, a clear and a restart inside
#        the 24 h quiet window, the D-009 card rendered through the shell's
#        own IPC and screenshotted, the do-not-disturb breakthrough for a
#        second signature, the unknown-agent ledger validated TWICE — by jq
#        in the guest and, on this host, against
#        schemas/ai-agent/ledger-summary.json — an enrolled device
#        answering an authorized inventory query within one reconcile pass
#        with no inbound listener anywhere, an out-of-scope query refused
#        by the DEVICE and audited, the role gate refusing independently at
#        the mock, the whole query log printed by the UNPRIVILEGED user,
#        both personal-device gates proven separately, a purge that leaves
#        the query log and audit trail intact, and the fleet view's `—`
#        where nobody answered — run after the M9 exercise, before the
#        export).
#   Host-side results land in <proof-dir> (default
#   os/images/out/desktop-proof):
#     punar-desktop-screenshot.png  grim capture — proof of real rendering
#     punar-m2.png                  grim capture with the overview open (M2)
#     punar-m5.png                  grim capture, enrolled bar chrome (M5)
#     punar-m5-personal.png         grim capture, restored personal bar (M5)
#     ram-report.txt                key=value idle-RAM + services-RSS numbers
#     ram-samples.txt, meminfo      raw guest measurement data
#     m2-report.txt, m2-*.json      M2 exercise verdict + hyprctl snapshots
#     m3-report.txt, m3-*.json      M3 exercise verdict + punarctl/nft
#                                   snapshots (+ m3-deny-stderr.txt)
#     m4-report.txt, m4-*.json      M4 exercise verdict + policy/status/
#                                   audit snapshots (+ m4-explain-*.txt)
#     m5-report.txt, m5-*.json      M5 exercise verdict + enrollment/policy
#                                   snapshots (+ m5-*.txt explains/stderr,
#                                   m5-received-*.jsonl mock received-state)
#     m6-report.txt, m6-*.txt       M6 exercise verdict + punar-env status
#     m6-*.json                     render/JSON, podman info/inspect/ps
#                                   snapshots (no screenshots — CLI milestone)
#     m7-report.txt, m7-*.txt       M7 exercise verdict + the agent launch
#                                   block, inspect render and list render
#     m7-*.json, m7-registry.jsonl  agents list/scan/agents.json snapshots and
#                                   the schema-exact registry transition log
#     punar-m7.png                  grim capture, AI panel with a managed row
#                                   and an unknown row (M7, Plate D-005)
#     m8-report.txt, m8-*.txt       M8 exercise verdict + the launch block,
#                                   the privacy ledger render and the purge
#     m8-*.json                     agents.access result, the stored ledger
#                                   record, index.json, the panel's runtime
#                                   view, the attributed audit denial
#     punar-m8.png                  grim capture, AI panel with the D-005
#                                   ledger register (M8)
#     m9-report.txt, m9-*.txt       M9 exercise verdict + the launch block,
#                                   the approval_required / denial / secrets
#                                   card renders and the redaction sweep
#                                   (counts only — never a value)
#     m9-*.json                     approvals list/get snapshots, the
#                                   exported approval document this script
#                                   re-validates against the shipped schema,
#                                   the agents.access result and the audit
#                                   slices both pointer directions are
#                                   proven against
#     punar-m9.png                  grim capture, the Plate D-003 approval
#                                   overlay with a live contract card (M9)
#     m10-report.txt, m10-*.txt     M10 exercise verdict + the alert
#                                   register render, the query log the
#                                   unprivileged user printed, the purge
#                                   render and the mock's fleet output
#     m10-*.json, m10-*.jsonl       agents.json and alerts.json snapshots,
#                                   the alert register, the detection
#                                   ledger summary this script re-validates
#                                   against the shipped schema, the
#                                   schema-exact detection records and their
#                                   sibling index, the local query log, and
#                                   the answered/refused query documents
#     punar-m10.png                 grim capture, the Plate D-009 shadow-AI
#                                   alert card (M10)
#     serial.log                    full serial console log (also on failure)
#   The budget VERDICT is not applied here: tests/performance/
#   check-budgets.sh reads ram-report.txt and gates against
#   PERFORMANCE_BUDGETS.md (fail > 1536 MB mean, warn > 1024 MB).
#   A missing/corrupt export or screenshot is a warning, not a failure —
#   the guest treats a failed grim the same way (its absence is a signal),
#   and the RAM gate rests on the serial numbers. The exercise verdicts
#   are the exception: a delivered PUNAR_M2..M10_FAIL fails here.
#
# KVM is used when /dev/kvm is present and accessible; otherwise the test
# degrades to TCG software emulation with a visible warning (and a GitHub
# Actions ::warning:: annotation in CI) and longer default timeouts. In
# desktop mode a TCG run additionally labels the RAM numbers
# "(VM, emulated)" — indicative only, never a gate (budgets §5.2).
#
# Usage: tools/boot-test.sh [--mode minimal|desktop] [image.qcow2] [proof-dir]
# Environment:
#   PUNAR_BOOT_TIMEOUT     minimal: seconds to wait for the boot marker
#                          (default: 300 KVM, 1200 TCG)
#   PUNAR_DESKTOP_TIMEOUT  desktop: seconds to wait for PUNAR_DESKTOP_OK
#                          (default: 900 KVM, 3600 TCG)
#   PUNAR_RAM_TIMEOUT      desktop: seconds after PUNAR_DESKTOP_OK to wait
#                          for the RAM result line; must cover the guest's
#                          fixed 10 min + 5 min measurement
#                          (default: 1200 KVM, 2400 TCG)
#   PUNAR_EXPORT_TIMEOUT   desktop: seconds to wait for the export sentinel
#                          — must also cover the in-guest M2..M8 exercises,
#                          which run between the RAM result and the export
#                          (default: 2400 KVM, 4500 TCG)
#   PUNAR_PROOF_DIR        desktop: where to land the collected files
#                          (default: os/images/out/desktop-proof)
#
# Requirements: qemu-system-x86_64 and an OVMF/edk2 x86_64 firmware pair
# (Ubuntu: apt install qemu-system-x86 ovmf; Arch: pacman -S qemu-base edk2-ovmf;
# macOS: brew install qemu — TCG only, Apple Silicon cannot KVM-accelerate x86).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
    # Print this file's header comment (everything up to the first
    # non-comment line) as the help text.
    awk 'NR > 1 && !/^#/ {exit} NR > 1 {sub(/^# ?/, ""); print}' "${BASH_SOURCE[0]}"
}

warn() {
    echo "warning: $*" >&2
    if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
        echo "::warning::$*"
    fi
}

die() {
    echo "error: $*" >&2
    exit 1
}

# --- argument parsing --------------------------------------------------------
MODE=""
ARG_IMAGE=""
ARG_PROOF_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --mode)
            [ $# -ge 2 ] || die "--mode requires a value (minimal|desktop)"
            MODE="$2"
            shift 2
            ;;
        --mode=*)
            MODE="${1#--mode=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            die "unknown option: $1 (see --help)"
            ;;
        *)
            if [ -z "${ARG_IMAGE}" ]; then
                ARG_IMAGE="$1"
            elif [ -z "${ARG_PROOF_DIR}" ]; then
                ARG_PROOF_DIR="$1"
            else
                die "unexpected argument: $1 (see --help)"
            fi
            shift
            ;;
    esac
done

IMAGE="${ARG_IMAGE:-${REPO_ROOT}/os/images/out/punar-dev-x86_64.qcow2}"
PROOF_DIR="${ARG_PROOF_DIR:-${PUNAR_PROOF_DIR:-${REPO_ROOT}/os/images/out/desktop-proof}}"

if [ -z "${MODE}" ]; then
    case "$(basename "${IMAGE}")" in
        *punar-desktop*) MODE="desktop" ;;
        *)               MODE="minimal" ;;
    esac
fi
case "${MODE}" in
    minimal|desktop) ;;
    *) die "invalid --mode '${MODE}' (expected minimal or desktop)" ;;
esac

[ -f "${IMAGE}" ] || die "image not found: ${IMAGE} (run tools/build-image.sh first)"
command -v qemu-system-x86_64 >/dev/null 2>&1 \
    || die "qemu-system-x86_64 not found (Ubuntu: apt install qemu-system-x86)"

# --- firmware ----------------------------------------------------------------
# Locate an OVMF/edk2 firmware code+vars pair. Paths are a controlled list
# (Ubuntu, Arch, Homebrew, MacPorts) and contain no colons.
OVMF_CODE=""
OVMF_VARS=""
for pair in \
    "/usr/share/OVMF/OVMF_CODE_4M.fd:/usr/share/OVMF/OVMF_VARS_4M.fd" \
    "/usr/share/OVMF/OVMF_CODE.fd:/usr/share/OVMF/OVMF_VARS.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.4m.fd:/usr/share/edk2/x64/OVMF_VARS.4m.fd" \
    "/usr/share/edk2/x64/OVMF_CODE.fd:/usr/share/edk2/x64/OVMF_VARS.fd" \
    "/opt/homebrew/share/qemu/edk2-x86_64-code.fd:/opt/homebrew/share/qemu/edk2-i386-vars.fd" \
    "/usr/local/share/qemu/edk2-x86_64-code.fd:/usr/local/share/qemu/edk2-i386-vars.fd"
do
    code="${pair%%:*}"
    vars="${pair##*:}"
    if [ -f "${code}" ] && [ -f "${vars}" ]; then
        OVMF_CODE="${code}"
        OVMF_VARS="${vars}"
        break
    fi
done
[ -n "${OVMF_CODE}" ] || die "no OVMF/edk2 UEFI firmware found (Ubuntu: apt install ovmf)"

# --- accelerator -------------------------------------------------------------
# KVM when present and accessible, else TCG + warning.
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL="kvm"
    CPU="host"
    DEFAULT_BOOT_TIMEOUT=300
    DEFAULT_DESKTOP_TIMEOUT=900
    DEFAULT_RAM_TIMEOUT=1200
    # Covers the in-guest M2 exercise (a few minutes under KVM), the M3
    # exercise (seconds), the M4 exercise — whose drift demo waits on
    # wall-clock timer firings, worst case 375 s even under KVM — and the
    # M5 enrollment exercise (reconcile RPCs plus two bounded 10 s
    # screenshot waits, a few minutes) and the M6 punar-env exercise
    # (podman load of a ~1.3 MB archive, one container create, a handful
    # of execs — seconds under KVM) and the M7 agent-registry exercise
    # (bounded 15 min in-guest: a 120 s registration wait, screenshot
    # settles, a 60 s teardown wait — a minute or two under KVM) and the
    # M8 ledger exercise (bounded 15 min in-guest; ~5 min of bounded waits
    # in the worst case — a 180 s launch+children wait, a screenshot
    # settle, a 60 s teardown wait and a 30 s socket wait around the one
    # deliberate punar-agentd restart — a minute or two under KVM) — all
    # of which run before the guest starts streaming the export — and the
    # M9 approval/credential/privilege exercise (bounded 20 min in-guest;
    # its longest single wait is the SHIPPED 300 s approval TTL, started
    # early so the credential and privilege groups run inside the window,
    # plus a 65 s grant-expiry wait and a 180 s launch wait) and the M10
    # shadow-AI exercise (bounded 15 min in-guest; its one unavoidable wait
    # is 300 s — the 240 s scan period plus 30 s AccuracySec plus slack —
    # because group 3 waits for the timer to fire ON ITS OWN, and a timer
    # firing is wall clock under any accelerator). Raised from M9's 3600 to
    # keep the same headroom now that an eleventh bounded in-guest exercise
    # sits between the RAM result and the export.
    DEFAULT_EXPORT_TIMEOUT=4200
    echo "==> /dev/kvm present and accessible: using KVM acceleration"
else
    ACCEL="tcg"
    CPU="max"
    DEFAULT_BOOT_TIMEOUT=1200
    DEFAULT_DESKTOP_TIMEOUT=3600
    DEFAULT_RAM_TIMEOUT=2400
    # TCG: the in-guest M2 exercise before the export is the slow part
    # (window spawns, quickshell relaunch — bounded at 25 min in-guest),
    # plus the M3 exercise (bounded 10 min), the M4 drift demo (375 s
    # wall clock — timer firings are wall-clock even under TCG), the
    # M5 enrollment exercise (bounded 15 min in-guest), the M6
    # punar-env exercise (bounded 10 min in-guest, minutes in practice)
    # and the M7 agent-registry exercise (bounded 15 min in-guest; the
    # quickshell IPC round trips and grim are the slow parts under TCG)
    # and the M8 ledger exercise (bounded 15 min in-guest; under TCG the
    # slow parts are the same quickshell/grim round trips plus the one
    # punar-agentd restart the retention-prune assertion needs) and the M9
    # approval/credential/privilege exercise (bounded 20 min in-guest; its
    # waits are wall-clock TTLs — a 300 s approval expiry and a 65 s grant
    # expiry — so they cost the same under TCG as under KVM, while the
    # quickshell/grim round trips are the slow parts) and the M10 shadow-AI
    # exercise (bounded 15 min in-guest; its 300 s detection-timer wait is
    # wall clock, so it costs the same under TCG, and the quickshell/grim
    # round trips and the mock enroll/unenroll cycle are the slow parts).
    DEFAULT_EXPORT_TIMEOUT=7800
    warn "/dev/kvm unavailable: degrading to TCG software emulation (slow; boot may take many minutes)"
    if [ "${MODE}" = "desktop" ]; then
        warn "desktop mode under TCG: RAM numbers will be labeled '(VM, emulated)' and are indicative only (PERFORMANCE_BUDGETS.md §5.2)"
    fi
fi
BOOT_TIMEOUT="${PUNAR_BOOT_TIMEOUT:-${DEFAULT_BOOT_TIMEOUT}}"
DESKTOP_TIMEOUT="${PUNAR_DESKTOP_TIMEOUT:-${DEFAULT_DESKTOP_TIMEOUT}}"
RAM_TIMEOUT="${PUNAR_RAM_TIMEOUT:-${DEFAULT_RAM_TIMEOUT}}"
EXPORT_TIMEOUT="${PUNAR_EXPORT_TIMEOUT:-${DEFAULT_EXPORT_TIMEOUT}}"

# --- workdir + cleanup -------------------------------------------------------
WORKDIR="$(mktemp -d)"
SERIAL_LOG="${WORKDIR}/serial.log"
EXPORT_RAW="${WORKDIR}/export.b64"
VARS_COPY="${WORKDIR}/OVMF_VARS.fd"
QEMU_PID=""

# Invoked indirectly via the EXIT trap below.
# shellcheck disable=SC2329
cleanup() {
    if [ -n "${QEMU_PID}" ] && kill -0 "${QEMU_PID}" 2>/dev/null; then
        kill "${QEMU_PID}" 2>/dev/null || true
        wait "${QEMU_PID}" 2>/dev/null || true
    fi
    rm -rf "${WORKDIR}"
}
trap cleanup EXIT

cp "${OVMF_VARS}" "${VARS_COPY}"

# --- shared helpers ----------------------------------------------------------

# wait_for_pattern <file> <grep -E regex> <timeout-secs> <description>
# Polls <file> for the pattern until the deadline; fails early if qemu dies.
# Sets WAIT_ELAPSED (seconds) either way. Prints a liveness note every ~2 min
# so long desktop phases do not look hung in CI logs.
WAIT_ELAPSED=0
wait_for_pattern() {
    local file="$1" regex="$2" timeout="$3" desc="$4"
    local start deadline now last_note
    start="$(date +%s)"
    deadline=$((start + timeout))
    last_note="${start}"
    while :; do
        now="$(date +%s)"
        WAIT_ELAPSED=$((now - start))
        if [ -f "${file}" ] && grep -aqE "${regex}" "${file}"; then
            return 0
        fi
        if [ "${now}" -ge "${deadline}" ]; then
            echo "error: no '${desc}' within ${timeout}s (accel=${ACCEL})" >&2
            return 1
        fi
        if ! kill -0 "${QEMU_PID}" 2>/dev/null; then
            echo "error: qemu exited while waiting for ${desc}" >&2
            return 1
        fi
        if [ $((now - last_note)) -ge 120 ]; then
            echo "    ... waiting for ${desc} (${WAIT_ELAPSED}s elapsed, timeout ${timeout}s)"
            last_note="${now}"
        fi
        sleep 2
    done
}

dump_serial_tail() {
    echo "==> Last 80 lines of serial console:" >&2
    if [ -f "${SERIAL_LOG}" ]; then
        tail -n 80 "${SERIAL_LOG}" >&2 || true
    else
        echo "(no serial output captured)" >&2
    fi
}

# Desktop mode: keep the serial log around for CI artifact upload even when
# the run fails — it is the primary diagnostic for a broken session chain.
preserve_serial_log() {
    if [ -f "${SERIAL_LOG}" ]; then
        mkdir -p "${PROOF_DIR}"
        cp "${SERIAL_LOG}" "${PROOF_DIR}/serial.log" || true
    fi
}

# =============================================================================
# minimal mode — M0 smoke test (unchanged semantics)
# =============================================================================
run_minimal() {
    local marker_primary='PUNAR_BOOT_OK'
    local marker_regex='PUNAR_BOOT_OK|login:'

    local qemu_args=(
        -machine "q35,accel=${ACCEL}"
        -cpu "${CPU}"
        -m 2048
        -smp 2
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${VARS_COPY}"
        -drive "file=${IMAGE},format=qcow2,if=virtio"
        -snapshot
        -display none
        -vga none
        -serial "file:${SERIAL_LOG}"
        -monitor none
        -nic none
        -no-reboot
    )

    echo "==> Booting ${IMAGE} (mode=minimal)"
    echo "    accel=${ACCEL} timeout=${BOOT_TIMEOUT}s firmware=${OVMF_CODE}"
    qemu-system-x86_64 "${qemu_args[@]}" &
    QEMU_PID=$!

    if ! wait_for_pattern "${SERIAL_LOG}" "${marker_regex}" "${BOOT_TIMEOUT}" "boot marker"; then
        dump_serial_tail
        exit 1
    fi

    if grep -aq "${marker_primary}" "${SERIAL_LOG}"; then
        echo "==> PASS: primary marker '${marker_primary}' after ${WAIT_ELAPSED}s (accel=${ACCEL})"
    else
        echo "==> PASS: fallback marker (login prompt) after ${WAIT_ELAPSED}s (accel=${ACCEL}); primary marker not seen"
    fi
    echo "==> Marker context from serial console:"
    grep -aE "${marker_regex}|MemTotal|MemAvailable" "${SERIAL_LOG}" | tail -n 10 || true
    exit 0
}

# =============================================================================
# desktop mode — M1 graphical gate + idle-RAM collection (milestone-1.md §7–§9)
# =============================================================================
run_desktop() {
    local desktop_marker='PUNAR_DESKTOP_OK'
    local ram_regex='PUNAR_RAM_MEAN_MB=[0-9]+ PUNAR_RAM_MAX_MB=[0-9]+'
    local desktop_ok_secs=""

    mkdir -p "${PROOF_DIR}"
    rm -f "${PROOF_DIR}/punar-desktop-screenshot.png" \
          "${PROOF_DIR}/punar-m2.png" \
          "${PROOF_DIR}/ram-report.txt" \
          "${PROOF_DIR}/ram-samples.txt" \
          "${PROOF_DIR}/ram-processes.txt" \
          "${PROOF_DIR}/meminfo" \
          "${PROOF_DIR}/wifi-report.txt" \
          "${PROOF_DIR}"/wifi-*.txt \
          "${PROOF_DIR}/surfaces-report.txt" \
          "${PROOF_DIR}"/surfaces-*.json \
          "${PROOF_DIR}"/surfaces-*.txt \
          "${PROOF_DIR}"/surfaces-*.png \
          "${PROOF_DIR}/surfaces-baseline.png" \
          "${PROOF_DIR}/m2-report.txt" \
          "${PROOF_DIR}"/m2-*.json \
          "${PROOF_DIR}/m3-report.txt" \
          "${PROOF_DIR}"/m3-*.json \
          "${PROOF_DIR}/m3-deny-stderr.txt" \
          "${PROOF_DIR}/m4-report.txt" \
          "${PROOF_DIR}"/m4-*.json \
          "${PROOF_DIR}"/m4-explain-*.txt \
          "${PROOF_DIR}/m5-report.txt" \
          "${PROOF_DIR}"/m5-*.json \
          "${PROOF_DIR}"/m5-*.jsonl \
          "${PROOF_DIR}"/m5-*.txt \
          "${PROOF_DIR}/punar-m5.png" \
          "${PROOF_DIR}/punar-m5-personal.png" \
          "${PROOF_DIR}/m6-report.txt" \
          "${PROOF_DIR}"/m6-*.json \
          "${PROOF_DIR}"/m6-*.txt \
          "${PROOF_DIR}/m7-report.txt" \
          "${PROOF_DIR}"/m7-*.json \
          "${PROOF_DIR}"/m7-*.jsonl \
          "${PROOF_DIR}"/m7-*.txt \
          "${PROOF_DIR}/punar-m7.png" \
          "${PROOF_DIR}/m8-report.txt" \
          "${PROOF_DIR}"/m8-*.json \
          "${PROOF_DIR}"/m8-*.txt \
          "${PROOF_DIR}/punar-m8.png" \
          "${PROOF_DIR}/m9-report.txt" \
          "${PROOF_DIR}"/m9-*.json \
          "${PROOF_DIR}"/m9-*.txt \
          "${PROOF_DIR}/punar-m9.png" \
          "${PROOF_DIR}/m10-report.txt" \
          "${PROOF_DIR}"/m10-*.json \
          "${PROOF_DIR}"/m10-*.jsonl \
          "${PROOF_DIR}"/m10-*.txt \
          "${PROOF_DIR}/punar-m10.png" \
          "${PROOF_DIR}/serial.log"

    # VM shape per PERFORMANCE_BUDGETS.md §5.1 (minimum target: 4 vCPU, 8 GB)
    # and milestone-1.md §6/§9: virtio-vga (guest KMS, llvmpipe rendering, no
    # virgl needed under -display none) + the punar.export virtio-serial
    # channel captured to a plain host file. -nic none matches the minimal
    # test; budgets §2.1 item 5 prefers idle-with-network — recorded as a
    # deviation in tests/performance/README.md until guest networking lands.
    local qemu_args=(
        -machine "q35,accel=${ACCEL}"
        -cpu "${CPU}"
        -m 8192
        -smp 4
        -drive "if=pflash,format=raw,readonly=on,file=${OVMF_CODE}"
        -drive "if=pflash,format=raw,file=${VARS_COPY}"
        -drive "file=${IMAGE},format=qcow2,if=virtio"
        -snapshot
        -display none
        -vga none
        -device virtio-vga
        -serial "file:${SERIAL_LOG}"
        -monitor none
        -nic none
        -no-reboot
        -device virtio-serial-pci
        -chardev "file,id=punarexp,path=${EXPORT_RAW}"
        -device "virtserialport,chardev=punarexp,name=punar.export"
    )

    echo "==> Booting ${IMAGE} (mode=desktop)"
    echo "    accel=${ACCEL} timeouts: desktop=${DESKTOP_TIMEOUT}s ram=${RAM_TIMEOUT}s export=${EXPORT_TIMEOUT}s"
    echo "    firmware=${OVMF_CODE} proof-dir=${PROOF_DIR}"
    qemu-system-x86_64 "${qemu_args[@]}" &
    QEMU_PID=$!

    # Phase 1: graphical session up (greetd -> Hyprland -> punar-shell ->
    # desktop-ready.sh -> punar-desktop-marker.service).
    if ! wait_for_pattern "${SERIAL_LOG}" "${desktop_marker}" "${DESKTOP_TIMEOUT}" "${desktop_marker}"; then
        preserve_serial_log
        dump_serial_tail
        exit 1
    fi
    desktop_ok_secs="${WAIT_ELAPSED}"
    echo "==> ${desktop_marker} after ${desktop_ok_secs}s (accel=${ACCEL})"

    # Phase 2: the in-guest canonical measurement (fixed 10 min stabilize +
    # 5 min sampling window — PERFORMANCE_BUDGETS.md §2.1–2.2; ~16 min wall
    # clock, sleeps are wall-clock even under TCG).
    echo "==> Waiting for in-guest idle-RAM measurement (canonical ~16 min; punar-idle-ram.service)"
    if ! wait_for_pattern "${SERIAL_LOG}" "${ram_regex}" "${RAM_TIMEOUT}" "idle-RAM result (PUNAR_RAM_MEAN_MB)"; then
        preserve_serial_log
        dump_serial_tail
        exit 1
    fi

    local ram_line ram_mean ram_max
    ram_line="$(grep -aoE "${ram_regex}" "${SERIAL_LOG}" | tail -n 1)"
    ram_mean="${ram_line#PUNAR_RAM_MEAN_MB=}"
    ram_mean="${ram_mean%% *}"
    ram_max="${ram_line##*PUNAR_RAM_MAX_MB=}"
    echo "==> Idle RAM from guest: mean=${ram_mean} MB max=${ram_max} MB"

    # M3 services-RSS line (milestone-3.md §9): the guest emits
    # PUNAR_SERVICES_RSS_MB=<n|absent> immediately after the RAM result
    # (summed PSS over EVERY Punar service cgroup — punard.service and,
    # since M7, punar-agentd.service — PERFORMANCE_BUDGETS.md §2.3; the var
    # name keeps RSS as the fixed consumer contract). Short
    # wait only; if it never appears (pre-M3 guest image) record `missing`
    # — check-budgets.sh fails both `absent` and `missing`, even under TCG
    # (a dead daemon is not an emulation artifact).
    local services_rss_regex='PUNAR_SERVICES_RSS_MB=([0-9]+|absent)'
    local services_rss="missing"
    if wait_for_pattern "${SERIAL_LOG}" "${services_rss_regex}" 120 "services-RSS line (PUNAR_SERVICES_RSS_MB)"; then
        services_rss="$(grep -aoE "${services_rss_regex}" "${SERIAL_LOG}" | tail -n 1)"
        services_rss="${services_rss#PUNAR_SERVICES_RSS_MB=}"
        echo "==> Services RSS from guest (summed PSS, punard + punar-agentd cgroups): ${services_rss} MB"
    else
        warn "desktop-test: no PUNAR_SERVICES_RSS_MB line after the RAM result (pre-M3 guest image?); recording 'missing'"
    fi

    # Phase 3: artifact export on the virtio-serial channel (milestone-1.md
    # §9). Non-fatal: the RAM gate rests on the serial numbers above, and the
    # guest deliberately continues without a screenshot too.
    local export_ok=0
    if wait_for_pattern "${EXPORT_RAW}" '^PUNAR_EXPORT_END$' "${EXPORT_TIMEOUT}" "PUNAR_EXPORT_END on export channel"; then
        export_ok=1
    else
        warn "desktop-test: no artifact export received on punar.export within ${EXPORT_TIMEOUT}s; screenshot/meminfo/ram-samples will be missing"
    fi

    if [ "${export_ok}" -eq 1 ]; then
        local guest_dir="${WORKDIR}/guest-export"
        mkdir -p "${guest_dir}"
        if awk '/^PUNAR_EXPORT_END$/{exit} inblock{print} /^PUNAR_EXPORT_BEGIN$/{inblock=1}' "${EXPORT_RAW}" \
                | base64 -d > "${WORKDIR}/export.tar" \
                && tar -xf "${WORKDIR}/export.tar" -C "${guest_dir}"; then
            if [ -f "${guest_dir}/screenshot.png" ]; then
                cp "${guest_dir}/screenshot.png" "${PROOF_DIR}/punar-desktop-screenshot.png"
                echo "==> Screenshot landed: ${PROOF_DIR}/punar-desktop-screenshot.png"
            else
                warn "desktop-test: export received but contains no screenshot.png (grim failed in guest?)"
            fi
            for f in ram-samples.txt ram-processes.txt meminfo m2-report.txt punar-m2.png \
                     m3-report.txt m3-deny-stderr.txt \
                     m4-report.txt m4-explain-timezone.txt \
                     m4-explain-unknown.txt \
                     wifi-report.txt wifi-link.txt wifi-devices.txt \
                     surfaces-report.txt surfaces-latency.txt \
                     surfaces-commandcenter.png surfaces-systemcontrol.png \
                     surfaces-notifications.png surfaces-shortcuts.png \
                     surfaces-aipanel.png surfaces-overview.png \
                     surfaces-approval.png \
                     m5-report.txt punar-m5.png punar-m5-personal.png \
                     m7-report.txt punar-m7.png \
                     m8-report.txt punar-m8.png \
                     m9-report.txt punar-m9.png \
                     m10-report.txt punar-m10.png; do
                if [ -f "${guest_dir}/${f}" ]; then
                    cp "${guest_dir}/${f}" "${PROOF_DIR}/${f}"
                fi
            done
            # M2 hyprctl -j snapshots (m2-layout-*.json, m2-clients*.json,
            # m2-workspaces*.json) — diagnostics for the phase-4 verdict —
            # the M3 punarctl --json / nft -j snapshots (m3-*.json) —
            # diagnostics for the phase-5 verdict — the M4 policy/status/
            # audit snapshots (m4-*.json) for the phase-6 verdict — and the
            # M5 enrollment snapshots (m5-*.json/.txt: enroll results,
            # managed explains, denial stderr) plus the mock control
            # plane's received-state copies (m5-received-*.jsonl — the
            # category-only compliance/inventory privacy evidence) for the
            # phase-7 verdict — and the M6 punar-env snapshots
            # (m6-*.txt/.json: m6-report.txt, the D-014 status render +
            # --json object, podman info/inspect/ps evidence) for the
            # phase-8 verdict — and the M7 agent-registry snapshots
            # (m7-*.txt/.json/.jsonl: m7-report.txt, the launch block, the
            # inspect and list renders, agents list/scan/agents.json and the
            # schema-exact registry transition log) for the phase-9 verdict
            # — and the M8 ledger snapshots (m8-*.txt/.json: m8-report.txt,
            # the launch block with its labelled dev/CI children, the
            # agents.access result, the stored ledger record and index.json,
            # the panel's runtime view, the attributed audit denial that the
            # Level-4 join is proven against, and the privacy/purge renders)
            # for the phase-10 verdict — and the M9 approval/credential
            # snapshots (m9-*.txt/.json: m9-report.txt, the launch block,
            # the approval_required and denial renders, the credential
            # cards (stderr only — the VALUE never touches a file), the
            # redaction sweep's COUNTS, the approvals list/get objects, the
            # exported approval document phase 11 re-validates against
            # schemas/audit/approval.json, the agents.access result showing
            # the ledger's credential rows filled in, and the audit slices
            # both pointer directions are proven against) for the phase-11
            # verdict. No M9 artifact carries a credential value — that is
            # asserted in-guest by m9-check group 9 against this very tar,
            # which is why the exercise runs before the export.
            for f in "${guest_dir}"/m2-*.json "${guest_dir}"/m3-*.json \
                     "${guest_dir}"/m4-*.json "${guest_dir}"/m5-*.json \
                     "${guest_dir}"/m5-*.jsonl "${guest_dir}"/m5-*.txt \
                     "${guest_dir}"/m6-*.json "${guest_dir}"/m6-*.txt \
                     "${guest_dir}"/m7-*.json "${guest_dir}"/m7-*.jsonl \
                     "${guest_dir}"/m7-*.txt \
                     "${guest_dir}"/m8-*.json "${guest_dir}"/m8-*.txt \
                     "${guest_dir}"/m9-*.json "${guest_dir}"/m9-*.txt \
                     "${guest_dir}"/m10-*.json "${guest_dir}"/m10-*.jsonl \
                     "${guest_dir}"/m10-*.txt; do
                if [ -f "${f}" ]; then
                    cp "${f}" "${PROOF_DIR}/"
                fi
            done
        else
            warn "desktop-test: failed to decode/untar the punar.export payload (corrupt channel capture?)"
        fi
    fi

    # ram-report.txt — the file tests/performance/check-budgets.sh gates on.
    # Environment labels per PERFORMANCE_BUDGETS.md §2.2/§5.2: VM under KVM,
    # VM-emulated under TCG (indicative only, never gated).
    local env_label="VM"
    if [ "${ACCEL}" != "kvm" ]; then
        env_label="VM-emulated"
    fi
    {
        echo "# Punar idle-RAM report — generated by tools/boot-test.sh (desktop mode)"
        echo "# Method: PERFORMANCE_BUDGETS.md §2.1–2.2, measured in-guest by punar-idle-ram.service"
        echo "# (MemTotal - MemAvailable; 10 min stabilize, 5 min window, 10 s cadence; mean+max)."
        echo "# PUNAR_DESKTOP_OK_HOST_SECS is host wall clock from qemu start to the marker —"
        echo "# an informational boot-to-desktop proxy (budgets §2.6), not a measured boot metric."
        echo "# PUNAR_SERVICES_RSS_MB is the summed PSS (smaps_rollup) of the pids in EVERY"
        echo "# Punar service cgroup at stabilized idle — punard.service and, since M7,"
        echo "# punar-agentd.service (PERFORMANCE_BUDGETS.md §2.3; the variable name keeps"
        echo "# RSS as the fixed consumer contract, the value is summed PSS)."
        echo "PUNAR_RAM_MEAN_MB=${ram_mean}"
        echo "PUNAR_RAM_MAX_MB=${ram_max}"
        echo "PUNAR_SERVICES_RSS_MB=${services_rss}"
        echo "PUNAR_RAM_ACCEL=${ACCEL}"
        echo "PUNAR_RAM_ENV_LABEL=${env_label}"
        echo "PUNAR_RAM_IMAGE=$(basename "${IMAGE}")"
        echo "PUNAR_RAM_TIMESTAMP=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "PUNAR_DESKTOP_OK_HOST_SECS=${desktop_ok_secs}"
    } > "${PROOF_DIR}/ram-report.txt"

    preserve_serial_log

    # Phase 4: M2 exercise verdict (milestone-2.md §7). The guest wrote
    # /run/punar/m2-report.txt (per-assertion ok/FAIL lines + a final
    # PUNAR_M2_OK / PUNAR_M2_FAIL line) via punar-m2-check.service; it
    # arrived in the phase-3 export. Hard gate: a delivered FAIL — or a
    # truncated report, meaning the guest crashed mid-exercise — fails
    # this script. A MISSING report degrades: the report is also echoed to
    # the serial console, so serial is checked as the fallback verdict;
    # with no verdict anywhere it is a ::warning:: under KVM and info-only
    # under TCG (an emulated run is already flagged and not M2-gated).
    local m2_report="${PROOF_DIR}/m2-report.txt"
    if [ -f "${m2_report}" ]; then
        if grep -q 'PUNAR_M2_FAIL' "${m2_report}"; then
            echo "error: M2 exercise reported PUNAR_M2_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m2_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M2_OK' "${m2_report}"; then
            echo "==> M2 exercise: PUNAR_M2_OK ($(grep -c '^ok' "${m2_report}" || true) assertions passed)"
        else
            echo "error: m2-report.txt carries no PUNAR_M2_OK/PUNAR_M2_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m2_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M2_FAIL' "${SERIAL_LOG}"; then
        echo "error: M2 exercise reported PUNAR_M2_FAIL on the serial console (export did not deliver m2-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M2_OK' "${SERIAL_LOG}"; then
        echo "==> M2 exercise: PUNAR_M2_OK (verdict from serial console; export did not deliver m2-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m2-report.txt in the export and no M2 verdict on serial — the M2 exercise did not run" >&2
        exit 1
    else
        echo "==> M2 exercise: no report under TCG (informational only; emulated runs are not M2-gated)"
    fi

    # Phase 5: M3 exercise verdict (milestone-3.md §8) — same pattern as the
    # M2 gate. The guest wrote /run/punar/m3-report.txt (per-assertion
    # ok/FAIL lines + a final PUNAR_M3_OK / PUNAR_M3_FAIL line) via
    # punar-m3-check.service; it arrived in the phase-3 export. Hard gate: a
    # delivered FAIL — or a truncated report — fails this script. A MISSING
    # report degrades: serial carries the echoed report as the fallback
    # verdict; with no verdict anywhere it is a ::warning:: under KVM and
    # info-only under TCG. Note a silently-dead punard cannot slip through
    # the missing-report path: check-budgets.sh hard-fails on
    # PUNAR_SERVICES_RSS_MB=absent even under TCG.
    local m3_report="${PROOF_DIR}/m3-report.txt"
    if [ -f "${m3_report}" ]; then
        if grep -q 'PUNAR_M3_FAIL' "${m3_report}"; then
            echo "error: M3 exercise reported PUNAR_M3_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m3_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M3_OK' "${m3_report}"; then
            echo "==> M3 exercise: PUNAR_M3_OK ($(grep -c '^ok' "${m3_report}" || true) assertions passed)"
        else
            echo "error: m3-report.txt carries no PUNAR_M3_OK/PUNAR_M3_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m3_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M3_FAIL' "${SERIAL_LOG}"; then
        echo "error: M3 exercise reported PUNAR_M3_FAIL on the serial console (export did not deliver m3-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M3_OK' "${SERIAL_LOG}"; then
        echo "==> M3 exercise: PUNAR_M3_OK (verdict from serial console; export did not deliver m3-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m3-report.txt in the export and no M3 verdict on serial — the M3 exercise did not run" >&2
        exit 1
    else
        echo "==> M3 exercise: no report under TCG (informational only; emulated runs are not M3-gated)"
    fi

    # Phase 6: M4 exercise verdict (milestone-4.md §10) — same pattern as
    # the M2/M3 gates. The guest wrote /run/punar/m4-report.txt
    # (per-assertion ok/FAIL lines + a final PUNAR_M4_OK / PUNAR_M4_FAIL
    # line) via punar-m4-check.service: policy effective/explain over both
    # personal source kinds, the preference-layer set cycle, section 52
    # compliance, and the timer-driven firewall-drift demo. Hard gate: a
    # delivered FAIL — or a truncated report — fails this script. A MISSING
    # report degrades: serial carries the echoed report as the fallback
    # verdict; with no verdict anywhere it is a ::warning:: under KVM and
    # info-only under TCG.
    local m4_report="${PROOF_DIR}/m4-report.txt"
    if [ -f "${m4_report}" ]; then
        if grep -q 'PUNAR_M4_FAIL' "${m4_report}"; then
            echo "error: M4 exercise reported PUNAR_M4_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m4_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M4_OK' "${m4_report}"; then
            echo "==> M4 exercise: PUNAR_M4_OK ($(grep -c '^ok' "${m4_report}" || true) assertions passed)"
        else
            echo "error: m4-report.txt carries no PUNAR_M4_OK/PUNAR_M4_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m4_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M4_FAIL' "${SERIAL_LOG}"; then
        echo "error: M4 exercise reported PUNAR_M4_FAIL on the serial console (export did not deliver m4-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M4_OK' "${SERIAL_LOG}"; then
        echo "==> M4 exercise: PUNAR_M4_OK (verdict from serial console; export did not deliver m4-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m4-report.txt in the export and no M4 verdict on serial — the M4 exercise did not run" >&2
        exit 1
    else
        echo "==> M4 exercise: no report under TCG (informational only; emulated runs are not M4-gated)"
    fi

    # Phase 7: M5 exercise verdict (milestone-5.md §10) — same pattern as
    # the M2/M3/M4 gates. The guest wrote /run/punar/m5-report.txt
    # (per-assertion ok/FAIL lines + a final PUNAR_M5_OK / PUNAR_M5_FAIL
    # line) via punar-m5-check.service: the mock control plane's
    # never-enabled discipline, the full enroll→managed→offline→unenroll
    # journey (spec 49/55), spec-40 managed explain, org-pinned set
    # behaviors, category-only compliance/inventory on the mock's received
    # side (spec 24/54), and the enrolled/personal bar screenshots. Hard
    # gate: a delivered FAIL — or a truncated report — fails this script.
    # A MISSING report degrades: serial carries the echoed report as the
    # fallback verdict; with no verdict anywhere it is a ::warning:: under
    # KVM and info-only under TCG.
    local m5_report="${PROOF_DIR}/m5-report.txt"
    if [ -f "${m5_report}" ]; then
        if grep -q 'PUNAR_M5_FAIL' "${m5_report}"; then
            echo "error: M5 exercise reported PUNAR_M5_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m5_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M5_OK' "${m5_report}"; then
            echo "==> M5 exercise: PUNAR_M5_OK ($(grep -c '^ok' "${m5_report}" || true) assertions passed)"
        else
            echo "error: m5-report.txt carries no PUNAR_M5_OK/PUNAR_M5_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m5_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M5_FAIL' "${SERIAL_LOG}"; then
        echo "error: M5 exercise reported PUNAR_M5_FAIL on the serial console (export did not deliver m5-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M5_OK' "${SERIAL_LOG}"; then
        echo "==> M5 exercise: PUNAR_M5_OK (verdict from serial console; export did not deliver m5-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m5-report.txt in the export and no M5 verdict on serial — the M5 exercise did not run" >&2
        exit 1
    else
        echo "==> M5 exercise: no report under TCG (informational only; emulated runs are not M5-gated)"
    fi

    # Phase 8: M6 exercise verdict (milestone-6.md §10) — same pattern as
    # the M2–M5 gates. The guest wrote /run/punar/m6-report.txt
    # (per-assertion ok/FAIL lines + a final PUNAR_M6_OK / PUNAR_M6_FAIL
    # line) via punar-m6-check.service: rootless podman preflight, the
    # Atlas fixture journey (init idempotence, up from the preloaded
    # offline base with --network none and the /workspace bind, shell
    # exit-code passthrough + host-side rootless write proof, the D-014
    # status render with the fixture's declared values and enforcement
    # labels verbatim, agent stub honesty, destroy with project files
    # intact). Hard gate: a delivered FAIL — or a truncated report — fails
    # this script. A MISSING report degrades: serial carries the echoed
    # report as the fallback verdict; with no verdict anywhere it is a
    # ::warning:: under KVM and info-only under TCG.
    local m6_report="${PROOF_DIR}/m6-report.txt"
    if [ -f "${m6_report}" ]; then
        if grep -q 'PUNAR_M6_FAIL' "${m6_report}"; then
            echo "error: M6 exercise reported PUNAR_M6_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m6_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M6_OK' "${m6_report}"; then
            echo "==> M6 exercise: PUNAR_M6_OK ($(grep -c '^ok' "${m6_report}" || true) assertions passed)"
        else
            echo "error: m6-report.txt carries no PUNAR_M6_OK/PUNAR_M6_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m6_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M6_FAIL' "${SERIAL_LOG}"; then
        echo "error: M6 exercise reported PUNAR_M6_FAIL on the serial console (export did not deliver m6-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M6_OK' "${SERIAL_LOG}"; then
        echo "==> M6 exercise: PUNAR_M6_OK (verdict from serial console; export did not deliver m6-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m6-report.txt in the export and no M6 verdict on serial — the M6 exercise did not run" >&2
        exit 1
    else
        echo "==> M6 exercise: no report under TCG (informational only; emulated runs are not M6-gated)"
    fi

    # Phase 9: M7 exercise verdict (milestone-7.md §12) — same pattern as
    # the M2–M6 gates. The guest wrote /run/punar/m7-report.txt
    # (per-assertion ok/FAIL lines + a final PUNAR_M7_OK / PUNAR_M7_FAIL
    # line) via punar-m7-check.service: punar-agentd daemon/socket/tmpfiles
    # preflight, a MOCK managed session through `punar-env agent claude-code`
    # (the offline VM has no real agent binary — the stand-in labels itself),
    # registry truth (list + the schema-exact registry.jsonl + the workspace
    # touch), scope-cgroup attribution, the `punarctl agents inspect` detail
    # with its PERSONAL DEFAULTS citation and MILESTONE 8 ledger line, a real
    # innocuous process detected as UNKNOWN/SUSPECTED, agents.json, the AI
    # panel screenshot, end of life, the audit lifecycle lines and negative
    # probes on the new socket. Hard gate: a delivered FAIL — or a truncated
    # report — fails this script. A MISSING report degrades: serial carries
    # the echoed report as the fallback verdict; with no verdict anywhere it
    # is a ::warning:: under KVM and info-only under TCG.
    local m7_report="${PROOF_DIR}/m7-report.txt"
    if [ -f "${m7_report}" ]; then
        if grep -q 'PUNAR_M7_FAIL' "${m7_report}"; then
            echo "error: M7 exercise reported PUNAR_M7_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m7_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M7_OK' "${m7_report}"; then
            echo "==> M7 exercise: PUNAR_M7_OK ($(grep -c '^ok' "${m7_report}" || true) assertions passed)"
        else
            echo "error: m7-report.txt carries no PUNAR_M7_OK/PUNAR_M7_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m7_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M7_FAIL' "${SERIAL_LOG}"; then
        echo "error: M7 exercise reported PUNAR_M7_FAIL on the serial console (export did not deliver m7-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M7_OK' "${SERIAL_LOG}"; then
        echo "==> M7 exercise: PUNAR_M7_OK (verdict from serial console; export did not deliver m7-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        # HARD, not a warning (regression 2026-08-25): m8-check.sh shipped
        # non-executable, its unit failed to start, no report was produced,
        # and a green run claimed a milestone that never ran. A check that
        # silently does not run is worse than one that fails.
        echo "error: no m7-report.txt in the export and no M7 verdict on serial — the M7 exercise did not run" >&2
        exit 1
    else
        echo "==> M7 exercise: no report under TCG (informational only; emulated runs are not M7-gated)"
    fi

    # Phase 10: M8 exercise verdict (milestone-8.md §12) — same pattern as
    # the M2–M7 gates. The guest wrote /run/punar/m8-report.txt (per-assertion
    # ok/FAIL lines + a final PUNAR_M8_OK / PUNAR_M8_FAIL line) via
    # punar-m8-check.service: the AI Access Ledger journey — ledger-store
    # preflight, a managed mock session with deterministic fifo-blocked
    # children, the scope cgroup read directly from /sys/fs/cgroup (source A),
    # the schema-exact `agents.access` summary with its honest
    # not-yet-observed rows for the categories no mediation point observes
    # yet (M12/M9+/M9), the Level-4 denial JOINED to the audit trail by event
    # id (source B), the privacy regression that asserts what is NOT on disk,
    # the counts-only `agents.list` fingerprint, the panel screenshot, the
    # 14-day retention deadline, an owner purge with its tombstone, the
    # no-resurrection drain, a retention prune against an injected backdated
    # ledger, and negative probes proving no export path exists. Hard gate: a
    # delivered FAIL — or a truncated report — fails this script. A MISSING
    # report degrades exactly as M2–M7 do.
    local m8_report="${PROOF_DIR}/m8-report.txt"
    if [ -f "${m8_report}" ]; then
        if grep -q 'PUNAR_M8_FAIL' "${m8_report}"; then
            echo "error: M8 exercise reported PUNAR_M8_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m8_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M8_OK' "${m8_report}"; then
            echo "==> M8 exercise: PUNAR_M8_OK ($(grep -c '^ok' "${m8_report}" || true) assertions passed)"
        else
            echo "error: m8-report.txt carries no PUNAR_M8_OK/PUNAR_M8_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m8_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M8_FAIL' "${SERIAL_LOG}"; then
        echo "error: M8 exercise reported PUNAR_M8_FAIL on the serial console (export did not deliver m8-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M8_OK' "${SERIAL_LOG}"; then
        echo "==> M8 exercise: PUNAR_M8_OK (verdict from serial console; export did not deliver m8-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m8-report.txt in the export and no M8 verdict on serial — the M8 exercise did not run" >&2
        exit 1
    else
        echo "==> M8 exercise: no report under TCG (informational only; emulated runs are not M8-gated)"
    fi

    # Phase 11: M9 exercise verdict (milestone-9.md §12) — same pattern as
    # the M2–M8 gates. The guest wrote /run/punar/m9-report.txt (per-assertion
    # ok/FAIL lines + a final PUNAR_M9_OK / PUNAR_M9_FAIL line) via
    # punar-m9-check.service: the approval gate, the mock credential broker
    # and just-in-time privilege — an agent-originated mutation answered
    # `approval_required` with nothing applied, the agent's own attempt to
    # approve it refused and audited, the Plate D-003 overlay screenshot, the
    # human resolve that finally executes it with both pointer directions in
    # the audit trail, an unanswered approval expiring, allow/request/deny
    # credential classes, a credential that really expires, THE REDACTION
    # SWEEP, the M8 ledger's credential rows filling in, and a one-minute
    # privilege grant. Hard gate: a delivered FAIL — or a truncated report —
    # fails this script. A MISSING report degrades exactly as M2–M8 do.
    local m9_report="${PROOF_DIR}/m9-report.txt"
    if [ -f "${m9_report}" ]; then
        if grep -q 'PUNAR_M9_FAIL' "${m9_report}"; then
            echo "error: M9 exercise reported PUNAR_M9_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m9_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M9_OK' "${m9_report}"; then
            echo "==> M9 exercise: PUNAR_M9_OK ($(grep -c '^ok' "${m9_report}" || true) assertions passed)"
        else
            echo "error: m9-report.txt carries no PUNAR_M9_OK/PUNAR_M9_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m9_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M9_FAIL' "${SERIAL_LOG}"; then
        echo "error: M9 exercise reported PUNAR_M9_FAIL on the serial console (export did not deliver m9-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M9_OK' "${SERIAL_LOG}"; then
        echo "==> M9 exercise: PUNAR_M9_OK (verdict from serial console; export did not deliver m9-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m9-report.txt in the export and no M9 verdict on serial — the M9 exercise did not run" >&2
        exit 1
    else
        echo "==> M9 exercise: no report under TCG (informational only; emulated runs are not M9-gated)"
    fi

    # Phase 11b: the OTHER half of the M9 approval-document assertion.
    #
    # The desktop image ships no JSON-Schema validator — no python, no
    # jsonschema — so m9-check asserts the approval object's shape with jq
    # in the guest and exports the document. Here it is replayed against the
    # SHIPPED schemas/audit/approval.json, so a drift between what punard
    # actually emitted and what schemas/ promises fails CI instead of
    # passing an in-guest spot-check (milestone-9.md §12 group 3).
    #
    # Run through the same containerized validator tools/validate-schemas.sh
    # uses, because this host is not assumed to have jsonschema either. A
    # validation FAILURE is fatal; a missing docker is a warning, since the
    # jq half already ran in the guest and the contracts job validates the
    # committed fixtures on every push regardless.
    local m9_doc="${PROOF_DIR}/m9-approval-doc.json"
    if [ -s "${m9_doc}" ]; then
        if command -v docker >/dev/null 2>&1; then
            if docker run --rm -v "${REPO_ROOT}:/w" -v "${PROOF_DIR}:/proof:ro" \
                    -w /w python:3.12-slim sh -c \
                    "pip install -q jsonschema pyyaml referencing && \
                     python tools/validate_schemas.py \
                       --document /proof/m9-approval-doc.json \
                       --schema schemas/audit/approval.json"; then
                echo "==> M9 approval document validates against schemas/audit/approval.json"
            else
                echo "error: the approval object punard emitted does NOT validate against schemas/audit/approval.json" >&2
                exit 1
            fi
        else
            warn "desktop-test: docker is unavailable, so the exported M9 approval document was not re-validated against schemas/audit/approval.json (the in-guest jq shape assertions still ran)"
        fi
    else
        warn "desktop-test: no m9-approval-doc.json in the export; the host-side schema replay was skipped"
    fi

    # Phase 12: M10 exercise verdict (milestone-10.md §16) — same pattern as
    # the M2–M9 gates. The guest wrote /run/punar/m10-report.txt (per-assertion
    # ok/FAIL lines + a final PUNAR_M10_OK / PUNAR_M10_FAIL line) via
    # punar-m10-check.service: periodic shadow-AI detection fired BY THE
    # TIMER with no manual scan anywhere in the window (proved from the
    # trigger recorded in the audit event, not from the wall clock), exactly
    # one alert per signature across repeated passes, a clear and a restart,
    # the D-009 card rendered and screenshotted with `suspected` and
    # `nothing was blocked` in it and the plate's `api.foo.ai` deliberately
    # absent, the unknown-agent ledger with its Level-4 reference and its
    # honest empty categories, an enrolled device answering an authorized
    # inventory query within ONE reconcile pass over a path with no inbound
    # listener, an out-of-scope query refused BY THE DEVICE and audited, the
    # role gate refusing independently at the mock, the whole query log
    # printed by the UNPRIVILEGED user, a personal device answering nothing
    # across three passes (gate A) and refusing a forced question with no
    # enrollment file (gate B), a purge that leaves the query log and the
    # audit trail intact, and the fleet view's `—` where nobody answered.
    # Hard gate: a delivered FAIL — or a truncated report — fails this
    # script. A MISSING report degrades exactly as M2–M9 do.
    local m10_report="${PROOF_DIR}/m10-report.txt"
    if [ -f "${m10_report}" ]; then
        if grep -q 'PUNAR_M10_FAIL' "${m10_report}"; then
            echo "error: M10 exercise reported PUNAR_M10_FAIL; failing assertions:" >&2
            grep '^FAIL' "${m10_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_M10_OK' "${m10_report}"; then
            echo "==> M10 exercise: PUNAR_M10_OK ($(grep -c '^ok' "${m10_report}" || true) assertions passed)"
        else
            echo "error: m10-report.txt carries no PUNAR_M10_OK/PUNAR_M10_FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${m10_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_M10_FAIL' "${SERIAL_LOG}"; then
        echo "error: M10 exercise reported PUNAR_M10_FAIL on the serial console (export did not deliver m10-report.txt)" >&2
        exit 1
    elif grep -aq 'PUNAR_M10_OK' "${SERIAL_LOG}"; then
        echo "==> M10 exercise: PUNAR_M10_OK (verdict from serial console; export did not deliver m10-report.txt)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no m10-report.txt in the export and no M10 verdict on serial — the M10 exercise did not run" >&2
        exit 1
    else
        echo "==> M10 exercise: no report under TCG (informational only; emulated runs are not M10-gated)"
    fi

    # Phase 12e: zram. Spec 282 ("Use zram ...") and 294 ("aggressive zram")
    # mandate it and the image shipped NONE until 2026-08-26 — no swap of any
    # kind, nothing reclaimable under pressure. zram-generator is a systemd
    # generator that runs at early boot, so a malformed config or a missing
    # module leaves the machine silently swapless, which is indistinguishable
    # from a machine that never wanted swap. Asserted on the running guest.
    local ram_report="${PROOF_DIR}/ram-report.txt"
    if [ -f "${ram_report}" ] && grep -q '^PUNAR_ZRAM_PRESENT=' "${ram_report}"; then
        local zpresent zactive zalgo zsize
        zpresent="$(grep '^PUNAR_ZRAM_PRESENT=' "${ram_report}" | cut -d= -f2)"
        zactive="$(grep '^PUNAR_ZRAM_SWAP_ACTIVE=' "${ram_report}" | cut -d= -f2)"
        zalgo="$(grep '^PUNAR_ZRAM_ALGORITHM=' "${ram_report}" | cut -d= -f2 || true)"
        zsize="$(grep '^PUNAR_ZRAM_DISKSIZE_MB=' "${ram_report}" | cut -d= -f2 || true)"
        if [ "${zpresent}" != "yes" ]; then
            echo "error: no /sys/block/zram0 on the guest — spec 282/294 zram did not materialise" >&2
            exit 1
        fi
        if [ "${zactive}" != "yes" ]; then
            echo "error: zram0 exists but is not an active swap device (/proc/swaps) — the generator ran and produced nothing usable" >&2
            exit 1
        fi
        echo "==> zram: active, ${zsize:-?} MB at ${zalgo:-?}"
    else
        echo "==> zram: no facts in ram-report.txt (older guest image); not gated this run"
    fi

    # Phase 12d: wireless verdict. A primary development machine is a laptop,
    # and until iwd landed this image had no Wi-Fi path at all. The hardware is
    # simulated (mac80211_hwsim) precisely so the shipped configuration is
    # EXERCISED rather than reasoned about — the failure mode DHCP still has.
    # A kernel without the simulator reports info and claims nothing.
    local wifi_report="${PROOF_DIR}/wifi-report.txt"
    if [ -f "${wifi_report}" ]; then
        if grep -q 'PUNAR_WIFI_FAIL' "${wifi_report}"; then
            echo "error: wireless exercise reported PUNAR_WIFI_FAIL; failing assertions:" >&2
            grep '^FAIL' "${wifi_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_WIFI_OK' "${wifi_report}"; then
            echo "==> Wireless: PUNAR_WIFI_OK ($(grep -c '^ok' "${wifi_report}" || true) assertions passed)"
            grep '^info' "${wifi_report}" >&2 || true
        else
            echo "error: wifi-report.txt carries no verdict (guest crashed mid-exercise?)" >&2
            exit 1
        fi
    elif grep -aq 'PUNAR_WIFI_FAIL' "${SERIAL_LOG}"; then
        echo "error: wireless exercise reported PUNAR_WIFI_FAIL on the serial console" >&2
        exit 1
    elif grep -aq 'PUNAR_WIFI_OK' "${SERIAL_LOG}"; then
        echo "==> Wireless: PUNAR_WIFI_OK (verdict from serial console)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no wifi-report.txt and no verdict on serial — the wireless exercise did not run" >&2
        exit 1
    else
        echo "==> Wireless: no report under TCG (informational only)"
    fi

    # Phase 12c: desktop-surfaces verdict.
    #
    # It runs FIRST in the guest and is gated LAST here, and the split is
    # deliberate. Gating it first meant a single surfaces failure exited the
    # script before any M2..M10 verdict was parsed, so a run that lost one
    # assertion reported nothing about the other 561 — the operator had to
    # download artifacts to learn whether the milestones had passed. Every
    # milestone verdict now prints before this gate is applied.
    #
    # It is the check that answers
    # "can a person actually use this machine" — the thirteen shell surfaces
    # open and close on a live session, the browser starts as a NATIVE
    # Wayland client with /etc/chromium-flags.conf applied (read back from
    # the process's own argv, not from the file), the system can open a link
    # at all (xdg-open present, resolving to a desktop entry that exists),
    # an UNENROLLED device carries no chromium managed policy, and the lock
    # screen's PAM stack exists so locking is not a one-way door.
    #
    # Everything above it — qmllint, `hyprland --config ok` — is static. This
    # is the only gate that fails when a surface parses perfectly and then
    # refuses to open. Same hard-gate contract as M2-M10: a delivered FAIL or
    # a truncated report fails this script; a missing report is fatal under
    # KVM and informational under TCG.
    local surfaces_report="${PROOF_DIR}/surfaces-report.txt"
    if [ -f "${surfaces_report}" ]; then
        if grep -q 'PUNAR_SURFACES_FAIL' "${surfaces_report}"; then
            echo "error: desktop-surfaces exercise reported PUNAR_SURFACES_FAIL; failing assertions:" >&2
            grep '^FAIL' "${surfaces_report}" >&2 || true
            exit 1
        elif grep -q 'PUNAR_SURFACES_OK' "${surfaces_report}"; then
            echo "==> Desktop surfaces: PUNAR_SURFACES_OK ($(grep -c '^ok' "${surfaces_report}" || true) assertions passed)"
        else
            echo "error: surfaces-report.txt carries no PUNAR_SURFACES_OK/FAIL verdict (guest crashed mid-exercise?)" >&2
            tail -n 20 "${surfaces_report}" >&2 || true
            exit 1
        fi
    elif grep -aq 'PUNAR_SURFACES_FAIL' "${SERIAL_LOG}"; then
        echo "error: desktop-surfaces exercise reported PUNAR_SURFACES_FAIL on the serial console (export did not deliver the report)" >&2
        exit 1
    elif grep -aq 'PUNAR_SURFACES_OK' "${SERIAL_LOG}"; then
        echo "==> Desktop surfaces: PUNAR_SURFACES_OK (verdict from serial console; export did not deliver the report)"
    elif [ "${ACCEL}" = "kvm" ]; then
        echo "error: no surfaces-report.txt in the export and no verdict on serial — the desktop-surfaces exercise did not run" >&2
        exit 1
    else
        echo "==> Desktop surfaces: no report under TCG (informational only; emulated runs are not surfaces-gated)"
    fi

    # Phase 12b: the other half of the M10 unknown-agent-ledger assertion,
    # for the same reason phase 11b exists. The image has no JSON-Schema
    # validator, so m10-check checks the detection's ledger summary with jq
    # in the guest and exports the document; here it is replayed against the
    # SHIPPED schemas/ai-agent/ledger-summary.json. That split is deliberate
    # and is the assertion that keeps the M8 Decision-0 law honest for a
    # third milestone: an unknown agent's ledger validates against the
    # UNCHANGED schema, or M10 bent a shipped contract to fit
    # (milestone-10.md §6.3, §16 group 6).
    local m10_doc="${PROOF_DIR}/m10-detection-summary.json"
    if [ -s "${m10_doc}" ]; then
        if command -v docker >/dev/null 2>&1; then
            if docker run --rm -v "${REPO_ROOT}:/w" -v "${PROOF_DIR}:/proof:ro" \
                    -w /w python:3.12-slim sh -c \
                    "pip install -q jsonschema pyyaml referencing && \
                     python tools/validate_schemas.py \
                       --document /proof/m10-detection-summary.json \
                       --schema schemas/ai-agent/ledger-summary.json"; then
                echo "==> M10 detection ledger validates against schemas/ai-agent/ledger-summary.json"
            else
                echo "error: the unknown-agent ledger punar-agentd emitted does NOT validate against schemas/ai-agent/ledger-summary.json" >&2
                exit 1
            fi
        else
            warn "desktop-test: docker is unavailable, so the exported M10 detection ledger was not re-validated against schemas/ai-agent/ledger-summary.json (the in-guest jq shape assertions still ran)"
        fi
    else
        warn "desktop-test: no m10-detection-summary.json in the export; the host-side schema replay was skipped"
    fi

    echo "==> PASS: desktop gate complete (accel=${ACCEL}, ${desktop_marker} after ${desktop_ok_secs}s)"
    echo "==> Idle RAM (${env_label}): mean=${ram_mean} MB max=${ram_max} MB — verdict is check-budgets.sh's"
    echo "==> Collected files in ${PROOF_DIR}:"
    ls -l "${PROOF_DIR}" || true
    exit 0
}

case "${MODE}" in
    minimal) run_minimal ;;
    desktop) run_desktop ;;
esac
