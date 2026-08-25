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

echo "punar: idle-ram: stabilizing ${STABILIZE_SECS}s, then ${SAMPLE_COUNT} samples every ${SAMPLE_INTERVAL}s"
sleep "${STABILIZE_SECS}"

: > "${RUN_DIR}/ram-samples.txt"
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
    if [ "${n}" -lt "${SAMPLE_COUNT}" ]; then
        sleep "${SAMPLE_INTERVAL}"
    fi
done

mean=$((sum / SAMPLE_COUNT))

# The line the CI desktop test greps for (gates: fail mean > 1536 MB hard
# ceiling, warn > 1024 MB target; TCG runs are warn-only, labeled emulated).
echo "PUNAR_RAM_MEAN_MB=${mean} PUNAR_RAM_MAX_MB=${max}"

# M3 services-RSS sample (milestone-3.md §9): taken right here — still at
# stabilized idle, strictly BEFORE the M2/M3 exercises start below. Canonical
# metric per PERFORMANCE_BUDGETS.md §2.3: summed PSS (/proc/<pid>/smaps_rollup
# `Pss:` lines) over the pids of the punard.service cgroup — cgroup
# attribution, never process-name matching. The env var name says RSS (fixed
# consumer contract); the VALUE is summed PSS, stated wherever it is reported.
# `absent` (cgroup missing or empty — punard dead) is a gated failure in
# tests/performance/check-budgets.sh, even under TCG. The unit list grows as
# sibling services ship (agentd M7, netd M12, ...).
CGROUP_PROCS=/sys/fs/cgroup/system.slice/punard.service/cgroup.procs
services_rss=absent
if [ -r "${CGROUP_PROCS}" ]; then
    pss_kb=0
    got=0
    while IFS= read -r svc_pid; do
        pid_pss="$(awk '/^Pss:/ {print $2}' "/proc/${svc_pid}/smaps_rollup" 2>/dev/null)"
        if [ -n "${pid_pss}" ]; then
            pss_kb=$((pss_kb + pid_pss))
            got=1
        fi
    done < "${CGROUP_PROCS}"
    if [ "${got}" -eq 1 ]; then
        # Integer MB, rounded up.
        services_rss=$(((pss_kb + 1023) / 1024))
    fi
fi
echo "PUNAR_SERVICES_RSS_MB=${services_rss}"

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
