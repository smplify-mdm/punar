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
PUNAR_SERVICE_UNITS="punard.service punar-agentd.service punar-secrets.service"
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
echo "PUNAR_SERVICES_RSS_MB=${services_rss} (summed PSS over: ${PUNAR_SERVICE_UNITS})"

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
