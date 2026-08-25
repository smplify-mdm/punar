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
