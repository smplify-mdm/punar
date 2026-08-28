#!/bin/sh
# Idle-RAM measurement + CI artifact export (milestone-1.md §8–§9).
# Runs as root via punar-idle-ram.service, started by the desktop marker
# service after PUNAR_DESKTOP_OK.
#
# Canonical method is fixed by PERFORMANCE_BUDGETS.md §2.1–2.2 and is NOT
# renegotiated here: stabilize 10 minutes after graphical-session-up with no
# input, then a 5-minute window sampling used = MemTotal - MemAvailable
# every 10 s; report mean and max. The env overrides below exist for local
# iteration only — any run that uses them is non-canonical and must be
# labeled as such (spec 1.22).

STABILIZE_SECS="${PUNAR_RAM_STABILIZE_SECS:-600}"
SAMPLE_COUNT="${PUNAR_RAM_SAMPLE_COUNT:-30}"
SAMPLE_INTERVAL="${PUNAR_RAM_SAMPLE_INTERVAL:-10}"
RUN_DIR=/run/punar
EXPORT_PORT=/dev/virtio-ports/punar.export
RUNTIME_REPORT="${RUN_DIR}/runtime-report.txt"
PUNAR_SERVICE_UNITS="punard.service punar-agentd.service punar-secrets.service"

mkdir -p "${RUN_DIR}"
: > "${RUNTIME_REPORT}"

emit_fact() {
    echo "$1"
    echo "$1" >> "${RUNTIME_REPORT}"
}

monotonic_ms() {
    awk '{printf "%.0f\n", $1 * 1000}' /proc/uptime
}

capture_service_counters() {
    destination="$1"
    : > "${destination}"
    for unit in ${PUNAR_SERVICE_UNITS}; do
        capture_cgroup_counters "${unit%.service}" \
            "/sys/fs/cgroup/system.slice/${unit}" "${destination}"
    done
    # Timer-triggered reconcile and agent discovery run in a persistent,
    # low-priority slice. Measuring the slice catches their cumulative work
    # even though each oneshot service cgroup disappears between snapshots.
    capture_cgroup_counters background \
        /sys/fs/cgroup/punar.slice/punar-background.slice "${destination}"
}

capture_cgroup_counters() {
    label="$1"
    cgroup="$2"
    destination="$3"
    cpu_usec=absent
    write_bytes=absent
    if [ -r "${cgroup}/cpu.stat" ]; then
        cpu_usec="$(awk '$1 == "usage_usec" {print $2; exit}' "${cgroup}/cpu.stat")"
    fi
    if [ -r "${cgroup}/io.stat" ]; then
        write_bytes="$(awk '
            {
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^wbytes=/) {
                        split($i, pair, "=")
                        total += pair[2]
                    }
                }
            }
            END {printf "%.0f\n", total + 0}
        ' "${cgroup}/io.stat")"
    fi
    case "${cpu_usec}" in ''|*[!0-9]*) cpu_usec=absent ;; esac
    case "${write_bytes}" in ''|*[!0-9]*) write_bytes=absent ;; esac
    printf '%s %s %s\n' "${label}" "${cpu_usec}" "${write_bytes}" >> "${destination}"
}

system_cpu_counters() {
    awk '/^cpu / {
        total = 0
        for (i = 2; i <= NF; i++) total += $i
        idle = $5 + $6
        printf "%.0f %.0f\n", total, total - idle
        exit
    }' /proc/stat
}

block_write_sectors() {
    total=0
    found=0
    for stat in /sys/block/vd*/stat /sys/block/sd*/stat \
        /sys/block/nvme*n*/stat /sys/block/mmcblk*/stat; do
        [ -r "${stat}" ] || continue
        found=1
        sectors="$(awk '{print $7}' "${stat}")"
        case "${sectors}" in ''|*[!0-9]*) sectors=0 ;; esac
        total=$((total + sectors))
    done
    if [ "${found}" -eq 1 ]; then
        echo "${total}"
    else
        echo absent
    fi
}

echo "punar: idle-ram: stabilizing ${STABILIZE_SECS}s, then ${SAMPLE_COUNT} samples every ${SAMPLE_INTERVAL}s"
sleep "${STABILIZE_SECS}"

: > "${RUN_DIR}/ram-samples.txt"

# Canonical idle is connected idle, not an artificially quiet offline guest.
# At the ten-minute boundary require both an up non-loopback link and the
# default route installed by DHCP. `/proc` and sysfs keep this probe tiny and
# avoid adding iproute2 or a polling process to the base image.
network_link_up=no
for operstate in /sys/class/net/*/operstate; do
    [ -r "${operstate}" ] || continue
    interface="${operstate%/operstate}"
    interface="${interface##*/}"
    [ "${interface}" = lo ] && continue
    case "$(cat "${operstate}")" in
        up|unknown) network_link_up=yes ;;
    esac
done
network_default_route="$(awk '
    NR > 1 && $1 != "lo" && $2 == "00000000" { found = 1 }
    END { print found ? "yes" : "no" }
' /proc/net/route)"
network_online=no
if [ "${network_link_up}" = yes ] && [ "${network_default_route}" = yes ]; then
    network_online=yes
fi
emit_fact "PUNAR_NETWORK_LINK_UP=${network_link_up}"
emit_fact "PUNAR_NETWORK_DEFAULT_ROUTE=${network_default_route}"
emit_fact "PUNAR_NETWORK_ONLINE=${network_online}"

counter_start="${RUN_DIR}/idle-counters-start.txt"
counter_end="${RUN_DIR}/idle-counters-end.txt"
window_start_ms="$(monotonic_ms)"
capture_service_counters "${counter_start}"
system_cpu_counters > "${RUN_DIR}/idle-system-cpu-start.txt"
block_write_sectors > "${RUN_DIR}/idle-block-write-start.txt"
sum=0
max=0
n=0
while [ "${n}" -lt "${SAMPLE_COUNT}" ]; do
    total_kb="$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)"
    avail_kb="$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)"
    used_mb=$(((total_kb - avail_kb) / 1024))
    echo "$(date -u +%s) ${used_mb}" >> "${RUN_DIR}/ram-samples.txt"
    sum=$((sum + used_mb))
    if [ "${used_mb}" -gt "${max}" ]; then
        max="${used_mb}"
    fi
    n=$((n + 1))
    # Sleep after the last sample too: 30 samples at a 10 s cadence describe
    # the complete 300 s canonical window, rather than ending at t=290 s.
    sleep "${SAMPLE_INTERVAL}"
done

mean=$((sum / SAMPLE_COUNT))

window_end_ms="$(monotonic_ms)"
capture_service_counters "${counter_end}"
system_cpu_counters > "${RUN_DIR}/idle-system-cpu-end.txt"
block_write_sectors > "${RUN_DIR}/idle-block-write-end.txt"
window_ms=$((window_end_ms - window_start_ms))
if [ "${window_ms}" -le 0 ]; then
    window_ms=1
fi

runtime_complete=yes
service_cpu_max_bps=0
service_write_bytes=0
while read -r counter_name start_cpu start_write; do
    end_line="$(awk -v wanted="${counter_name}" '$1 == wanted {print; exit}' "${counter_end}")"
    end_cpu=absent
    end_write=absent
    read -r _end_unit end_cpu end_write <<EOF
${end_line}
EOF
    case "${start_cpu}:${end_cpu}:${start_write}:${end_write}" in
        *absent*|*[!0-9:]* )
            runtime_complete=no
            echo "punar: idle-runtime: missing cgroup counter for ${counter_name}" >&2
            continue
            ;;
    esac
    cpu_delta=$((end_cpu - start_cpu))
    write_delta=$((end_write - start_write))
    if [ "${cpu_delta}" -lt 0 ] || [ "${write_delta}" -lt 0 ]; then
        runtime_complete=no
        echo "punar: idle-runtime: counter moved backwards for ${counter_name}" >&2
        continue
    fi
    # Hundredths of a percentage point of one CPU: 50 bps == 0.50%.
    cpu_bps=$((cpu_delta * 10000 / (window_ms * 1000)))
    if [ "${cpu_bps}" -gt "${service_cpu_max_bps}" ]; then
        service_cpu_max_bps="${cpu_bps}"
    fi
    service_write_bytes=$((service_write_bytes + write_delta))
    unit_key="$(printf '%s' "${counter_name}" | tr '[:lower:]-' '[:upper:]_')"
    emit_fact "PUNAR_IDLE_CPU_${unit_key}_BPS=${cpu_bps}"
    emit_fact "PUNAR_IDLE_WRITE_${unit_key}_BYTES=${write_delta}"
done < "${counter_start}"

system_total_start=0
system_busy_start=0
system_total_end=0
system_busy_end=0
read -r system_total_start system_busy_start < "${RUN_DIR}/idle-system-cpu-start.txt"
read -r system_total_end system_busy_end < "${RUN_DIR}/idle-system-cpu-end.txt"
system_total_delta=$((system_total_end - system_total_start))
system_busy_delta=$((system_busy_end - system_busy_start))
system_cpu_bps=0
if [ "${system_total_delta}" -gt 0 ] && [ "${system_busy_delta}" -ge 0 ]; then
    system_cpu_bps=$((system_busy_delta * 10000 / system_total_delta))
else
    runtime_complete=no
fi

block_start="$(cat "${RUN_DIR}/idle-block-write-start.txt")"
block_end="$(cat "${RUN_DIR}/idle-block-write-end.txt")"
block_write_bytes=0
case "${block_start}:${block_end}" in
    *[!0-9:]* ) runtime_complete=no ;;
    *)
        block_write_bytes=$(((block_end - block_start) * 512))
        if [ "${block_write_bytes}" -lt 0 ]; then
            runtime_complete=no
            block_write_bytes=0
        fi
        ;;
esac

emit_fact "PUNAR_IDLE_RUNTIME_PRESENT=${runtime_complete}"
emit_fact "PUNAR_IDLE_WINDOW_MS=${window_ms}"
emit_fact "PUNAR_IDLE_CPU_MAX_BPS=${service_cpu_max_bps}"
emit_fact "PUNAR_IDLE_SERVICE_WRITE_BYTES=${service_write_bytes}"
emit_fact "PUNAR_IDLE_SYSTEM_CPU_BPS=${system_cpu_bps}"
emit_fact "PUNAR_IDLE_BLOCK_WRITE_BYTES=${block_write_bytes}"

# The line the CI desktop test greps for (gates: fail mean > 1536 MB hard
# ceiling, warn > 1024 MB target; TCG runs are warn-only, labeled emulated).
emit_fact "PUNAR_RAM_MEAN_MB=${mean}"
emit_fact "PUNAR_RAM_MAX_MB=${max}"
# Preserve the one-line serial marker consumed by the host boot harness.
echo "PUNAR_RAM_MEAN_MB=${mean} PUNAR_RAM_MAX_MB=${max}"

# Services-RSS sample (milestone-3.md §9, milestone-7.md §11): taken right
# here — still at stabilized idle, strictly BEFORE the M2..M7 exercises start
# below. Canonical metric per PERFORMANCE_BUDGETS.md §2.3: summed PSS
# (/proc/<pid>/smaps_rollup `Pss:` lines) over the pids of EVERY Punar
# first-party service cgroup — cgroup attribution, never process-name
# matching. The env var name says RSS (fixed consumer contract); the VALUE is
# summed PSS, stated wherever it is reported.
#
# M7 grew the unit list honestly (punar-agentd.service) and M9 grows it
# again: punar-secrets.service is a THIRD resident daemon, so it is summed
# into the SAME single number the budget is judged against (spec 6.2 budgets
# the services total, not per-daemon; thresholds unchanged — target 100 MB,
# MVP ceiling 150 MB). Adding a daemon and quietly leaving it out of the sum
# would make the budget say something untrue; raising the threshold to make
# room would be worse. If three daemons do not fit, the honest responses in
# order are: report the number, trim the broker (it carries no policy-engine
# copy — it asks punard), reconsider socket activation, and only then discuss
# folding daemons together (milestone-9.md §11).
#
# A unit whose cgroup is missing or empty makes the whole value `absent` — a
# dead daemon is a gated failure in tests/performance/check-budgets.sh, even
# under TCG, and that must not be maskable by a live sibling. The list grows
# again as siblings ship (netd M12, ...).
services_rss=absent
pss_kb=0
all_units_ok=1
for unit in ${PUNAR_SERVICE_UNITS}; do
    unit_procs="/sys/fs/cgroup/system.slice/${unit}/cgroup.procs"
    unit_got=0
    if [ -r "${unit_procs}" ]; then
        while IFS= read -r svc_pid; do
            pid_pss="$(awk '/^Pss:/ {print $2}' "/proc/${svc_pid}/smaps_rollup" 2>/dev/null)"
            if [ -n "${pid_pss}" ]; then
                pss_kb=$((pss_kb + pid_pss))
                unit_got=1
            fi
        done < "${unit_procs}"
    fi
    if [ "${unit_got}" -eq 0 ]; then
        echo "punar: idle-ram: no readable pids in the ${unit} cgroup — services RSS reported absent" >&2
        all_units_ok=0
    fi
done
if [ "${all_units_ok}" -eq 1 ]; then
    # Integer MB, rounded up.
    services_rss=$(((pss_kb + 1023) / 1024))
fi
emit_fact "PUNAR_SERVICES_RSS_MB=${services_rss}"
echo "punar: idle-ram: summed PSS over: ${PUNAR_SERVICE_UNITS}"

# WHO IS ACTUALLY HOLDING THE MEMORY. The whole-system idle figure has drifted
# 115 MB above its target and the only attribution available was "the commit
# that added thirteen surfaces" — true, but not actionable: that commit also
# added wallpapers, a theme system and a notification daemon, and the shell,
# the compositor and llvmpipe's software-rendering buffers are all in the same
# anonymous total. Optimising against that is guesswork.
#
# So every process with a readable smaps_rollup is ranked by PSS at stabilized
# idle, strictly inside the same window as the numbers above. PSS, not RSS,
# because Qt and Mesa share a great deal and RSS would double-count it: the
# PSS column sums to something meaningful, which is the property that makes it
# worth measuring at all.
#
# Read-only, no new process beyond this loop, and it runs AFTER both samples
# so it cannot perturb either.
# ZRAM, ASSERTED ON THE RUNNING MACHINE. Spec 282/294 mandate it and the image
# shipped none until now. A config file that is present but produced no device
# is the failure this reports: zram-generator is a systemd GENERATOR, so it runs
# at early boot and a malformed unit or a missing kernel module leaves the
# machine silently swapless — which looks exactly like a machine that never
# wanted swap. Reported as facts for the host gate to judge, not decided here.
if [ -e /sys/block/zram0 ]; then
    zram_disksize="$(cat /sys/block/zram0/disksize 2>/dev/null || echo 0)"
    zram_algo="$(sed -n 's/.*\[\([a-z0-9]*\)\].*/\1/p' /sys/block/zram0/comp_algorithm 2>/dev/null | head -1)"
    zram_active="$(awk 'NR>1 && $1 ~ /zram/ {print "yes"; exit}' /proc/swaps 2>/dev/null)"
    emit_fact "PUNAR_ZRAM_PRESENT=yes"
    emit_fact "PUNAR_ZRAM_DISKSIZE_MB=$((zram_disksize / 1024 / 1024))"
    emit_fact "PUNAR_ZRAM_ALGORITHM=${zram_algo:-unknown}"
    emit_fact "PUNAR_ZRAM_SWAP_ACTIVE=${zram_active:-no}"
else
    emit_fact "PUNAR_ZRAM_PRESENT=no"
    emit_fact "PUNAR_ZRAM_SWAP_ACTIVE=no"
fi

ram_procs="${RUN_DIR:-/run/punar}/ram-processes.txt"
{
    echo "# Per-process PSS at stabilized idle — the attribution for PUNAR_RAM_MEAN_MB."
    echo "# PSS (proportional set size): shared pages divided among their sharers, so"
    echo "# this column SUMS meaningfully. Sorted descending, kB."
    for pid_dir in /proc/[0-9]*; do
        pid="${pid_dir#/proc/}"
        pss="$(awk '/^Pss:/ {print $2}' "${pid_dir}/smaps_rollup" 2>/dev/null)"
        [ -n "${pss}" ] || continue
        comm="$(tr -d '\0' < "${pid_dir}/comm" 2>/dev/null)"
        [ -n "${comm}" ] || comm="?"
        printf '%s\t%s\t%s\n' "${pss}" "${pid}" "${comm}"
    done | sort -rn -k1,1
} > "${ram_procs}" 2>/dev/null || true
if [ -s "${ram_procs}" ]; then
    total_pss="$(awk -F'\t' '/^[0-9]/ {t += $1} END {printf "%d", (t + 1023) / 1024}' "${ram_procs}")"
    echo "PUNAR_RAM_PSS_TOTAL_MB=${total_pss} (sum of per-process PSS; see ram-processes.txt)"
    echo "# top five by PSS:"
    awk -F'\t' '/^[0-9]/ {printf "#   %6.1f MB  %s\n", $1/1024, $3}' "${ram_procs}" | head -5
fi

# Wireless exercise, before the surfaces check: it runs as root, loads the
# kernel's wireless simulator and leaves an extra interface behind, so it must
# not land in the middle of a check that counts windows or measures latency.
systemctl start punar-wifi-check.service \
    || echo "punar: idle-ram: punar-wifi-check.service failed to start" >&2

# Per-surface construction/resident-cost instrument. It runs after the
# canonical idle window so fifteen fresh probe processes cannot pollute the
# whole-system budget, and before the normal surface gate so the latter proves
# the untouched production shell still works after the probes have exited.
# The report is hard-gated host-side; this orchestration layer keeps going so a
# failure still exports every diagnostic and every later milestone verdict.
systemctl start punar-surface-cost-check.service \
    || echo "punar: idle-ram: punar-surface-cost-check.service failed to start" >&2

# Desktop-surfaces exercise, FIRST of the in-VM checks and strictly AFTER the
# idle sampling window above. First on purpose: it is the only check that
# leaves the session exactly as it found it (every surface closed, the browser
# killed and its absence asserted), so running it before the milestone checks
# means it never inherits their fixtures and they never inherit its browser.
# Same never-fatal contract as the milestone hooks — the verdict lives in
# surfaces-report.txt and tools/boot-test.sh parses it; a missing report is
# its own signal and is a HARD failure there (the m8 lesson).
systemctl start punar-surfaces-check.service \
    || echo "punar: idle-ram: punar-surfaces-check.service failed to start" >&2

# M2 exercise ordering hook (milestone-2.md §7): start punar-m2-check
# SYNCHRONOUSLY (Type=oneshot blocks until done) strictly AFTER the
# sampling window above — so the idle measurement is never polluted — and
# strictly BEFORE the export below, so the m2-report.txt / punar-m2.png /
# m2-*.json files it writes into /run/punar ship in the same tar. Never
# fatal here: the verdict lives in m2-report.txt and the host gate
# (tools/boot-test.sh) parses it; a missing report is its own signal.
systemctl start punar-m2-check.service \
    || echo "punar: idle-ram: punar-m2-check.service failed to start" >&2

# M3 exercise ordering hook (milestone-3.md §8): same pattern — start
# punar-m3-check SYNCHRONOUSLY strictly AFTER the M2 exercise and strictly
# BEFORE the export below, so the m3-report.txt / m3-*.json files it writes
# into /run/punar ship in the same tar and its hostname mutation never
# pollutes the idle window (sampled far above). Never fatal here: the verdict
# lives in m3-report.txt and the host gate (tools/boot-test.sh) parses it.
systemctl start punar-m3-check.service \
    || echo "punar: idle-ram: punar-m3-check.service failed to start" >&2

# M4 exercise ordering hook (milestone-4.md §10.1): start punar-m4-check
# SYNCHRONOUSLY strictly AFTER the M3 exercise (whose set calls establish
# the user-preference provenance m4-check asserts on) and strictly BEFORE
# the export below, so m4-report.txt / m4-*.json / m4-explain-*.txt ship in
# the same tar and the timer-driven drift demo (worst case 375 s) never
# touches the idle window. Never fatal here: the verdict lives in
# m4-report.txt and the host gate (tools/boot-test.sh) parses it.
systemctl start punar-m4-check.service \
    || echo "punar: idle-ram: punar-m4-check.service failed to start" >&2

# M5 exercise ordering hook (milestone-5.md §10.1): start punar-m5-check
# SYNCHRONOUSLY strictly AFTER the M4 exercise (whose set cycle left the
# user-preference provenance the enrollment journey pins over and restores
# to) and strictly BEFORE the export below, so m5-report.txt / m5-*.json /
# m5-received-*.jsonl / punar-m5*.png ship in the same tar. The check
# starts and stops the never-enabled punar-mock-smplify.service itself, so
# the dev/CI mock runs only inside this window — structurally outside the
# idle-RAM sampling (far above) and the punard.service-cgroup RSS sample.
# Never fatal here: the verdict lives in m5-report.txt and the host gate
# (tools/boot-test.sh) parses it.
systemctl start punar-m5-check.service \
    || echo "punar: idle-ram: punar-m5-check.service failed to start" >&2

# M6 exercise ordering hook (milestone-6.md §8/§10): start punar-m6-check
# SYNCHRONOUSLY strictly AFTER the M5 exercise (which restored the
# personal pre-state and the shipped reconcile timer) and strictly BEFORE
# the export below, so m6-report.txt / m6-status.txt / m6-status.json /
# m6-podman-info.json / m6-podman-ps.txt / m6-*.txt snapshots ship in the
# same tar. The rootless podman containers it creates live only inside
# this window — structurally outside the idle-RAM sampling (far above)
# and the punard.service-cgroup RSS sample (punar-env is a user CLI, not
# a service). Never fatal here: the verdict lives in m6-report.txt and
# the host gate (tools/boot-test.sh) parses it.
systemctl start punar-m6-check.service \
    || echo "punar: idle-ram: punar-m6-check.service failed to start" >&2

# M7 exercise ordering hook (milestone-7.md §12): start punar-m7-check
# SYNCHRONOUSLY strictly AFTER the M6 exercise (which destroyed its
# container and left ~punar/atlas in place — the project the managed agent
# session runs in) and strictly BEFORE the export below, so m7-report.txt /
# m7-launch.txt / m7-inspect.txt / m7-agents-*.json / punar-m7.png ship in
# the same tar. The mock agent session and the foo-agent detection fixture
# live only inside this window — structurally after the idle-RAM sampling
# and the services-RSS sample far above, so neither the RAM gate nor the
# combined-cgroup PSS reading sees them (the agent runs in its own
# punar-agent-<id>.scope under the user manager, not in a service cgroup).
# Never fatal here: the verdict lives in m7-report.txt and the host gate
# (tools/boot-test.sh) parses it.
systemctl start punar-m7-check.service \
    || echo "punar: idle-ram: punar-m7-check.service failed to start" >&2

# M8 exercise ordering hook (milestone-8.md §12): start punar-m8-check
# SYNCHRONOUSLY strictly AFTER the M7 exercise (which left ~punar/atlas and
# a registry this exercise re-establishes rather than inherits) and strictly
# BEFORE the export below, so m8-report.txt / m8-access.json /
# m8-ledger-file.json / m8-index.json / m8-privacy.txt / m8-agents-list.json /
# m8-audit-denial.json / m8-purge.txt / punar-m8.png ship in the same tar.
# The second managed agent session, its fifo-blocked children and the
# synthetic backdated ledger live only inside this window — structurally
# after the idle-RAM sampling and the services-RSS sample far above, so
# neither gate sees them (the agent runs in its own punar-agent-<id>.scope
# under the user manager, not in a service cgroup; M8 adds no new daemon, so
# the services list above is unchanged). The exercise restarts
# punar-agentd once, deliberately, to prove retention pruning against an
# injected backdated ledger; that restart is inside this window too.
# Never fatal here: the verdict lives in m8-report.txt and the host gate
# (tools/boot-test.sh) parses it.
systemctl start punar-m8-check.service \
    || echo "punar: idle-ram: punar-m8-check.service failed to start" >&2

# M9 exercise ordering hook (milestone-9.md §12): start punar-m9-check
# SYNCHRONOUSLY strictly AFTER the M8 exercise (which purged its own ledger
# and left the registry clean) and strictly BEFORE the export below, so
# m9-report.txt / m9-*.json / m9-*.txt / punar-m9.png ship in the same tar.
#
# Everything this exercise creates lives only inside this window: a third
# managed agent session, the approvals and grants it raises, and — the
# reason the ordering matters more here than anywhere else — MOCK CREDENTIAL
# TOKENS. They are held in shell variables that are never exported and never
# written to a file, and group 9 then greps the whole export tar, the audit
# trail, every ledger file and every punar process's /proc/*/environ and
# /proc/*/cmdline for each of them. That sweep is the headline assertion of
# the milestone, and it can only be honest if it runs before the tar is
# built — which is exactly where this line puts it.
#
# The services-RSS sample far above already closed, and punar-secrets was
# resident for it (it is in PUNAR_SERVICE_UNITS), so the third daemon is in
# the budget number rather than hiding behind this window. The agent runs in
# its own punar-agent-<id>.scope under the user manager, not in a service
# cgroup, so it perturbs neither gate.
# Never fatal here: the verdict lives in m9-report.txt and the host gate
# (tools/boot-test.sh) parses it.
systemctl start punar-m9-check.service \
    || echo "punar: idle-ram: punar-m9-check.service failed to start" >&2

# M10 exercise ordering hook (milestone-10.md §16): start punar-m10-check
# SYNCHRONOUSLY strictly AFTER the M9 exercise (which resolved its
# approvals, revoked its grants and left the personal pre-state) and
# strictly BEFORE the export below, so m10-report.txt / m10-*.json /
# m10-*.txt / m10-*.jsonl / punar-m10.png ship in the same tar.
#
# TIMEOUT MATH, stated rather than copied (the unit carries the full
# table): the exercise's one unavoidable wait is 300 s — the 240 s scan
# period plus 30 s AccuracySec plus 30 s slack — because group 3 waits for
# `punar-agentd-scan.timer` to fire ON ITS OWN, with no manual scan
# anywhere in the window. That is the whole point of the group, so the
# wait is absorbed rather than removed: the fixture is launched first and
# the later groups run inside the window. TimeoutStartSec=15min is TCG
# headroom on top.
#
# What this window contains, and why no budget gate sees it: two sleeping
# shell fixtures in ~punar/Downloads, the never-enabled dev/CI control
# plane (started and stopped by the script), and an enroll/unenroll cycle
# that is restored before it exits. The idle-RAM sampling and the
# services-PSS sample both closed far above. M10 adds NO new daemon —
# the scan pass is a transient `punarctl` every four minutes, not a
# resident process — so PUNAR_SERVICE_UNITS above is unchanged.
#
# The one thing this hook must NOT do is stop punar-agentd-scan.timer for
# the measurement window: budgets are measured against the shipping
# configuration, and a 240 s timer is half the frequency of one the RAM
# window has contained since M4.
# Never fatal here: the verdict lives in m10-report.txt and the host gate
# (tools/boot-test.sh) parses it.
systemctl start punar-m10-check.service \
    || echo "punar: idle-ram: punar-m10-check.service failed to start" >&2

# Artifact export (milestone-1.md §9): tar /run/punar, base64 it onto the
# dedicated virtio-serial channel between sentinel lines. QEMU captures the
# channel to a host file; CI decodes between the sentinels. Fallback if this
# channel misbehaves: qemu-guest-agent (packaged in the snapshot, unshipped).
if [ -e "${EXPORT_PORT}" ]; then
    {
        echo "PUNAR_EXPORT_BEGIN"
        tar -C "${RUN_DIR}" -cf - . | base64
        echo "PUNAR_EXPORT_END"
    } > "${EXPORT_PORT}"
    echo "punar: idle-ram: artifact export written to ${EXPORT_PORT}"
else
    echo "punar: idle-ram: no ${EXPORT_PORT} (VM started without the export channel); skipping export"
fi
