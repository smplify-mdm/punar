#!/bin/sh
# M5 in-VM enrollment exercise (milestone-5.md §10; SPEC sections 24, 38–40,
# 49–52, 54, 55). Runs AS ROOT via punar-m5-check.service; unprivileged
# paths use runuser -u punar (the m4-check pattern). idle-ram.sh starts this
# synchronously AFTER punar-m4-check.service and BEFORE the artifact export,
# so everything written into /run/punar here (m5-report.txt, m5-*.json /
# m5-*.txt snapshots, m5-received-*.jsonl, punar-m5.png,
# punar-m5-personal.png) ships in the same export tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m5-report.txt
# (`PUNAR_M5_OK` / `PUNAR_M5_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh phase 7) parses the exported report and
# hard-fails on PUNAR_M5_FAIL or a truncated report.
#
# The journey (milestone-5.md §10.2, 19 assertion groups): personal
# pre-state → enroll against the dev/CI mock control plane
# (punar-mock-smplify, started and stopped ONLY by this script — its
# never-enabled discipline is itself assertion 1) → managed policy.d +
# spec-40 explain → managed-set behaviors (non-root denial citing the org
# policy; root recorded-but-overridden) → compliance/inventory sync
# asserted on the mock's RECEIVED side (exact category-only key allowlists
# — the spec 24/54 privacy assertion) → offline (spec 55: cached policy
# enforced, transition-audited unreachable) → recovery (latest-wins: one
# new line) → offline unenroll → personal restore. Screenshots capture the
# enrolled bar chrome and the restored calm-paper bar as human evidence;
# every machine assertion reads files/IPC directly.
#
# Timer determinism: m4-check phase B deliberately leaves
# punard-reconcile.timer running (shipped default); this script stops it at
# the top — every sync below has exactly one actor, the script's own
# `punarctl reconcile` calls — and restarts it at the end (assertion 19).
set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m5-report.txt"
CTL=/usr/bin/punarctl
STATE_DIR=/var/lib/punar
POLICY_D="${STATE_DIR}/policy.d"
AUDIT_LOG=/var/log/punar/audit.jsonl
STATUS_JSON="${RUN_DIR}/status.json"
TIMER=punard-reconcile.timer
MOCK=punar-mock-smplify.service
MOCK_SOCK=/run/punar-mock-smplify/api.sock
MOCK_STATE=/var/lib/punar-mock-smplify
RC_FILE="${MOCK_STATE}/received-compliance.jsonl"
RI_FILE="${MOCK_STATE}/received-inventory.jsonl"
FAILED=0

: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }

# check_eq <name> <expected> <actual>
check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        note "FAIL $1 (expected '$2', got '$3')"
        FAILED=1
    fi
}

# jq_check <name> <json-file> <jq filter that must be truthy>
jq_check() {
    if jq -e "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq filter: $3; input head: $(head -c 240 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# line_count <file> — 0 for a missing file (the pre-first-report state).
line_count() {
    if [ -f "$1" ]; then
        wc -l < "$1" | tr -d ' '
    else
        echo 0
    fi
}

# capture_shot <output-basename> — grim under the session user with the
# m2-check session-env discovery (this script is root; the compositor is
# punar's). The preceding sleep is the bounded FileView pickup wait
# (milestone-5.md §10.1): the shell reload is event-driven but not
# synchronous with the status.json write; the screenshot is human
# evidence, while every machine assertion reads the file/IPC directly.
capture_shot() {
    sleep 10
    shot_uid="$(id -u punar 2>/dev/null)"
    shot_run="/run/user/${shot_uid}"
    shot_wl=""
    for s in "${shot_run}"/wayland-*; do
        case "${s}" in
            *.lock) ;;
            *) [ -e "${s}" ] && shot_wl="$(basename "${s}")" && break ;;
        esac
    done
    if [ -n "${shot_wl}" ] && runuser -u punar -- env \
            XDG_RUNTIME_DIR="${shot_run}" WAYLAND_DISPLAY="${shot_wl}" \
            grim "${RUN_DIR}/$1" 2>/dev/null; then
        note "ok   grim captured $1 (session-user capture)"
    else
        note "FAIL grim capture $1 (wayland=${shot_wl:-none})"
        FAILED=1
    fi
}

# token_grep_zero <label> — the raw device token must appear in NO punard
# surface: audit log, status.json, layer stores, enrollment.json, or any
# snapshot this script exported. (The mock's own devices.json legitimately
# holds the token — that is the server side of the trust boundary and is
# deliberately NOT copied into /run/punar.)
token_grep_zero() {
    tg_found=0
    for f in "${AUDIT_LOG}" "${STATUS_JSON}" "${STATE_DIR}/preferences.json" \
             "${STATE_DIR}/os-defaults.json" "${STATE_DIR}/enrollment.json" \
             "${RUN_DIR}"/m5-*.json "${RUN_DIR}"/m5-*.txt \
             "${RUN_DIR}"/m5-*.jsonl; do
        [ -f "${f}" ] || continue
        if grep -qF "${TOKEN}" "${f}" 2>/dev/null; then
            note "FAIL device token appears in ${f} ($1)"
            FAILED=1
            tg_found=1
        fi
    done
    [ "${tg_found}" -eq 0 ] && note "ok   device token appears in no punard surface ($1)"
}

# Single-actor determinism for every sync assertion below (§10.1).
systemctl stop "${TIMER}" >/dev/null 2>&1

# --- 1. mock discipline + start (the check owns the mock's lifetime) ---------
mock_enabled="$(systemctl is-enabled "${MOCK}" 2>/dev/null || true)"
if [ "${mock_enabled}" = "enabled" ]; then
    note "FAIL ${MOCK} is enabled (dev/CI mock must never be enabled)"
    FAILED=1
else
    note "ok   ${MOCK} not enabled (is-enabled: ${mock_enabled:-nonexistent})"
fi
if systemctl start "${MOCK}" >/dev/null 2>&1; then
    note "ok   ${MOCK} started by the check"
else
    note "FAIL ${MOCK} failed to start"
    FAILED=1
fi
i=0
while [ "${i}" -lt 15 ] && [ ! -S "${MOCK_SOCK}" ]; do i=$((i + 1)); sleep 1; done
if [ -S "${MOCK_SOCK}" ]; then
    note "ok   mock socket ${MOCK_SOCK} present after ${i}s"
else
    note "FAIL mock socket ${MOCK_SOCK} absent after 15s"
    FAILED=1
fi

# --- 2. pre-state personal ---------------------------------------------------
jq_check "pre-enroll status.json: enrolled false" "${STATUS_JSON}" \
    '.enrolled == false'
"${CTL}" --json enroll status > "${RUN_DIR}/m5-enroll-status-pre.json" 2>&1
jq_check "pre-enroll enroll status: enrolled false" \
    "${RUN_DIR}/m5-enroll-status-pre.json" '.enrolled == false'
if [ -z "$(ls -A "${POLICY_D}" 2>/dev/null)" ]; then
    note "ok   policy.d empty pre-enroll (unmanaged-first)"
else
    note "FAIL policy.d not empty pre-enroll: $(find "${POLICY_D}" -mindepth 1 2>/dev/null | tr '\n' ' ')"
    FAILED=1
fi
"${CTL}" --json status > "${RUN_DIR}/m5-status-pre.json" 2>&1
jq_check "pre-enroll punarctl status: mode personal, no org field" \
    "${RUN_DIR}/m5-status-pre.json" \
    '.mode == "personal" and (has("org") | not)'

# --- 3. enroll acme.com (the §49 chain against the mock) ---------------------
if "${CTL}" --json enroll start acme.com \
        > "${RUN_DIR}/m5-enroll-start.json" 2>&1; then
    note "ok   punarctl --json enroll start acme.com exit 0"
else
    note "FAIL enroll start exit $?: $(head -c 240 "${RUN_DIR}/m5-enroll-start.json")"
    FAILED=1
fi
jq_check "enroll result: Acme / Acme Engineering, attestation simulated, eng-baseline-v12" \
    "${RUN_DIR}/m5-enroll-start.json" \
    '.org.name == "Acme" and .org.display_name == "Acme Engineering"
     and .attestation == "simulated"
     and .policy_ids == ["eng-baseline-v12"]'

# --- 4. store modes + the token never leaves its file ------------------------
check_eq "enrollment.json owner mode" "root:root 600" \
    "$(stat -c '%U:%G %a' "${STATE_DIR}/enrollment.json" 2>/dev/null)"
check_eq "device-token owner mode" "root:root 600" \
    "$(stat -c '%U:%G %a' "${STATE_DIR}/device-token" 2>/dev/null)"
TOKEN="$(cat "${STATE_DIR}/device-token" 2>/dev/null)"
if [ -n "${TOKEN}" ]; then
    note "ok   device token read once by the check (held in memory only)"
else
    note "FAIL device-token file empty or unreadable"
    FAILED=1
    # A defined non-empty sentinel keeps the greps below meaningful.
    TOKEN="__PUNAR_M5_NO_TOKEN__"
fi
"${CTL}" --json enroll status > "${RUN_DIR}/m5-enroll-status.json" 2>&1
token_grep_zero "post-enroll"

# --- 5. policy.d carries the envelope with the embedded payload --------------
check_eq "policy.d/eng-baseline-v12.json mode" "600" \
    "$(stat -c '%a' "${POLICY_D}/eng-baseline-v12.json" 2>/dev/null)"
jq_check "policy.d file is the envelope with embedded DeviceDesiredState payload" \
    "${POLICY_D}/eng-baseline-v12.json" \
    '.policy_id == "eng-baseline-v12" and .policy.kind == "DeviceDesiredState"'

# --- 6. spec 40 managed explain, now real ------------------------------------
"${CTL}" --json policy explain security.firewall \
    > "${RUN_DIR}/m5-explain-managed.json" 2>&1
jq_check "explain security.firewall: organization_baseline rank 2, Acme Engineering Baseline, override not permitted" \
    "${RUN_DIR}/m5-explain-managed.json" \
    '.source.kind == "organization_baseline" and .source.rank == 2
     and .source.policy_id == "eng-baseline-v12"
     and .source.name == "Acme Engineering Baseline"
     and .user_override_permitted == false'
"${CTL}" policy explain security.firewall \
    > "${RUN_DIR}/m5-explain-managed.txt" 2>&1
if grep -q  'Acme Engineering Baseline' "${RUN_DIR}/m5-explain-managed.txt" \
        && grep -q  'eng-baseline-v12' "${RUN_DIR}/m5-explain-managed.txt" \
        && grep -qi 'not permitted'    "${RUN_DIR}/m5-explain-managed.txt"; then
    note "ok   human explain renders the managed spec-40 layout (org name, policy id, Not permitted)"
else
    note "FAIL human managed explain layout: $(head -c 240 "${RUN_DIR}/m5-explain-managed.txt" 2>/dev/null)"
    FAILED=1
fi

# --- 7. non-root set on the pinned path: exit 3, org-citing denial -----------
runuser -u punar -- "${CTL}" capabilities set security.firewall disabled \
    >/dev/null 2>"${RUN_DIR}/m5-set-user-stderr.txt"
check_eq "non-root set on org-pinned path exit code" 3 "$?"
if grep -q  'Acme Engineering Baseline' "${RUN_DIR}/m5-set-user-stderr.txt" \
        && grep -q 'eng-baseline-v12' "${RUN_DIR}/m5-set-user-stderr.txt" \
        && grep -q 'Next step' "${RUN_DIR}/m5-set-user-stderr.txt"; then
    note "ok   denial stderr cites the pinning org policy (not 'personal defaults') in section-73 prose"
else
    note "FAIL denial stderr voice: $(head -c 240 "${RUN_DIR}/m5-set-user-stderr.txt" 2>/dev/null || echo empty)"
    FAILED=1
fi
"${CTL}" --json audit tail -n 20 > "${RUN_DIR}/m5-audit-deny.json" 2>&1
jq_check "denial audited: capabilities.set deny with policy_ids [eng-baseline-v12]" \
    "${RUN_DIR}/m5-audit-deny.json" \
    '.events | any(.action == "capabilities.set"
       and .resource == "security.firewall"
       and .decision == "deny" and .result == "denied"
       and .policy_ids == ["eng-baseline-v12"])'

# --- 8. root set on the pinned path: recorded-but-overridden -----------------
if "${CTL}" --json capabilities set security.firewall disabled \
        > "${RUN_DIR}/m5-set-root.json" 2>&1; then
    note "ok   root set disabled on org-pinned path exit 0 (recorded, not applied)"
else
    note "FAIL root set disabled exit $?: $(head -c 240 "${RUN_DIR}/m5-set-root.json")"
    FAILED=1
fi
jq_check "set result: changed false, overridden true, effective_state enabled" \
    "${RUN_DIR}/m5-set-root.json" \
    '.changed == false and .overridden == true
     and .effective_state == "enabled"'
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "ok   nft table intact (the org value held; the preference was only recorded)"
else
    note "FAIL nft table gone after overridden set (org value did not hold)"
    FAILED=1
fi
"${CTL}" --json audit tail -n 20 > "${RUN_DIR}/m5-audit-noop.json" 2>&1
jq_check "overridden set audited: capabilities.set noop with policy_ids [eng-baseline-v12]" \
    "${RUN_DIR}/m5-audit-noop.json" \
    '.events | any(.action == "capabilities.set"
       and .resource == "security.firewall"
       and .decision == "allow" and .result == "noop"
       and .policy_ids == ["eng-baseline-v12"])'
"${CTL}" capabilities set security.firewall disabled \
    > "${RUN_DIR}/m5-set-root.txt" 2>&1
if grep -q 'Recorded, not applied' "${RUN_DIR}/m5-set-root.txt"; then
    note "ok   human set renders the 'Recorded, not applied' verdict"
else
    note "FAIL human overridden-set verdict: $(head -c 240 "${RUN_DIR}/m5-set-root.txt" 2>/dev/null)"
    FAILED=1
fi
# Deliberate re-record (milestone-5.md §5.4): the enabled preference is
# what post-unenroll assertion 16 restores to — green, not a trap.
if "${CTL}" capabilities set security.firewall enabled >/dev/null 2>&1; then
    note "ok   root re-recorded security.firewall enabled (post-unenroll restore target)"
else
    note "FAIL re-record security.firewall enabled exit $?"
    FAILED=1
fi

# --- 9. sync: the mock's RECEIVED compliance (category states ONLY) ----------
if "${CTL}" --json reconcile > "${RUN_DIR}/m5-reconcile-a.json" 2>&1; then
    note "ok   punarctl --json reconcile exit 0 (managed, mock up)"
else
    note "FAIL reconcile exit $?: $(head -c 240 "${RUN_DIR}/m5-reconcile-a.json")"
    FAILED=1
fi
jq_check "reconcile result: compliance overall compliant" \
    "${RUN_DIR}/m5-reconcile-a.json" '.compliance.overall == "compliant"'
DEVICE_ID="$(cat "${STATE_DIR}/device-id" 2>/dev/null)"
rc_count_a="$(line_count "${RC_FILE}")"
if [ "${rc_count_a}" -ge 1 ]; then
    note "ok   received-compliance.jsonl has ${rc_count_a} line(s)"
else
    note "FAIL received-compliance.jsonl empty or absent"
    FAILED=1
fi
tail -n 1 "${RC_FILE}" > "${RUN_DIR}/m5-received-compliance-last.json" 2>/dev/null
jq_check "last received compliance: device id matches, overall compliant, exactly 3 category/state pairs, exact key allowlists (spec 24/54: states, never values)" \
    "${RUN_DIR}/m5-received-compliance-last.json" \
    "(keys | sort) == [\"device_id\", \"received_at\", \"report\"]
     and .device_id == \"${DEVICE_ID}\"
     and (.report | keys | sort) == [\"categories\", \"overall\"]
     and .report.overall == \"compliant\"
     and (.report.categories | length) == 3
     and (.report.categories | all((keys | sort) == [\"category\", \"state\"]))"

# --- 10. inventory: sent once at enroll, then hash-gated ---------------------
ri_count="$(line_count "${RI_FILE}")"
check_eq "received-inventory.jsonl line count (sent at enroll only)" 1 "${ri_count}"
tail -n 1 "${RI_FILE}" > "${RUN_DIR}/m5-received-inventory-last.json" 2>/dev/null
jq_check "received inventory: os/kernel non-empty, 3 capability rows, exact key allowlists (device info + capability states, nothing behavioral)" \
    "${RUN_DIR}/m5-received-inventory-last.json" \
    "(keys | sort) == [\"device_id\", \"inventory\", \"received_at\"]
     and .device_id == \"${DEVICE_ID}\"
     and (.inventory | keys | sort) == [\"capabilities\", \"hostname\", \"kernel\", \"os\"]
     and (.inventory.os | keys | sort) == [\"id\", \"pretty_name\", \"version_id\"]
     and (.inventory.os.id | length) > 0
     and (.inventory.kernel | length) > 0
     and (.inventory.capabilities | length) == 3
     and (.inventory.capabilities | all((keys | sort) == [\"capability\", \"current_state\", \"supported\"]))"
"${CTL}" --json reconcile > "${RUN_DIR}/m5-reconcile-b.json" 2>&1
rc_count_b="$(line_count "${RC_FILE}")"
if [ "${rc_count_b}" -gt "${rc_count_a}" ]; then
    note "ok   second reconcile grew received-compliance (${rc_count_a} -> ${rc_count_b})"
else
    note "FAIL second reconcile did not grow received-compliance (${rc_count_a} -> ${rc_count_b})"
    FAILED=1
fi
check_eq "received-inventory.jsonl still 1 line after second reconcile (hash gate)" 1 \
    "$(line_count "${RI_FILE}")"

# --- 11. status surfaces flip to managed -------------------------------------
check_eq "status.json mode" "644" "$(stat -c '%a' "${STATUS_JSON}" 2>/dev/null)"
cp "${STATUS_JSON}" "${RUN_DIR}/m5-statusfile-managed.json" 2>/dev/null
jq_check "status.json: enrolled, Acme Engineering, compliant" \
    "${RUN_DIR}/m5-statusfile-managed.json" \
    '.enrolled == true and .org_name == "Acme Engineering"
     and .compliance_overall == "compliant"'
"${CTL}" --json status > "${RUN_DIR}/m5-status-managed.json" 2>&1
jq_check "punarctl status: mode managed, org acme" \
    "${RUN_DIR}/m5-status-managed.json" \
    '.mode == "managed" and .enrolled == true and .org.id == "acme"'

# --- 12. screenshot: enrolled bar chrome (org name + dot + state word) -------
capture_shot punar-m5.png

# --- 13. offline (spec 55): cached policy enforced, transition audited -------
systemctl stop "${MOCK}" >/dev/null 2>&1
if "${CTL}" --json reconcile > "${RUN_DIR}/m5-reconcile-offline.json" 2>&1; then
    note "ok   reconcile exit 0 with the control plane down"
else
    note "FAIL offline reconcile exit $?: $(head -c 240 "${RUN_DIR}/m5-reconcile-offline.json")"
    FAILED=1
fi
jq_check "offline reconcile: cached org policy still compliant" \
    "${RUN_DIR}/m5-reconcile-offline.json" '.compliance.overall == "compliant"'
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "ok   nft table present offline (cached policy.d enforced without the mock)"
else
    note "FAIL nft table absent offline"
    FAILED=1
fi
# Second offline pass: proves the transition-only audit below (one
# unreachable event across repeated failing retries, never one per pass).
"${CTL}" --json reconcile >/dev/null 2>&1
"${CTL}" --json enroll status > "${RUN_DIR}/m5-enroll-status-offline.json" 2>&1
jq_check "enroll status offline: last_sync unreachable, pending true" \
    "${RUN_DIR}/m5-enroll-status-offline.json" \
    '.last_sync.result == "unreachable" and .last_sync.pending == true'
unreachable_events="$(jq -s '[.[] | select(.action == "enroll.sync" and .result == "unreachable")] | length' "${AUDIT_LOG}" 2>/dev/null)"
check_eq "enroll.sync unreachable events (transition-only, across 2 failing passes)" 1 \
    "${unreachable_events}"

# --- 14. recovery: latest-wins queue = exactly one new line ------------------
rc_count_c="$(line_count "${RC_FILE}")"
check_eq "no compliance lines arrived while offline" "${rc_count_b}" "${rc_count_c}"
systemctl start "${MOCK}" >/dev/null 2>&1
i=0
while [ "${i}" -lt 15 ] && [ ! -S "${MOCK_SOCK}" ]; do i=$((i + 1)); sleep 1; done
"${CTL}" --json reconcile > "${RUN_DIR}/m5-reconcile-recovery.json" 2>&1
"${CTL}" --json enroll status > "${RUN_DIR}/m5-enroll-status-recovery.json" 2>&1
jq_check "enroll status after recovery: last_sync success, pending false" \
    "${RUN_DIR}/m5-enroll-status-recovery.json" \
    '.last_sync.result == "success" and .last_sync.pending == false'
check_eq "received-compliance grew by exactly one line (latest-wins: the queue is a flag, not a spool)" \
    "$((rc_count_c + 1))" "$(line_count "${RC_FILE}")"
recovery_events="$(jq -s '[.[] | select(.action == "enroll.sync" and .result == "success")] | length' "${AUDIT_LOG}" 2>/dev/null)"
check_eq "enroll.sync recovery events (one per outage, not per retry)" 1 \
    "${recovery_events}"

# Snapshot the mock's received side for the export BEFORE unenrolling
# (the mock keeps history after unenroll — honest: unenrollment stops the
# future flow, it cannot retract the past; devices.json is deliberately
# NOT exported, it holds the server-side token record).
cp "${RC_FILE}" "${RUN_DIR}/m5-received-compliance.jsonl" 2>/dev/null
cp "${RI_FILE}" "${RUN_DIR}/m5-received-inventory.jsonl" 2>/dev/null

# --- 15. unenroll OFFLINE (local restore needs no counterparty) --------------
systemctl stop "${MOCK}" >/dev/null 2>&1
if "${CTL}" --json enroll stop > "${RUN_DIR}/m5-enroll-stop.json" 2>&1; then
    note "ok   punarctl --json enroll stop exit 0 with the control plane DOWN"
else
    note "FAIL enroll stop exit $?: $(head -c 240 "${RUN_DIR}/m5-enroll-stop.json")"
    FAILED=1
fi
jq_check "enroll stop result: unenrolled, removed eng-baseline-v12" \
    "${RUN_DIR}/m5-enroll-stop.json" \
    '.enrolled == false and .removed_policy_ids == ["eng-baseline-v12"]'
if [ -z "$(ls -A "${POLICY_D}" 2>/dev/null)" ]; then
    note "ok   policy.d empty after unenroll"
else
    note "FAIL policy.d not empty after unenroll: $(find "${POLICY_D}" -mindepth 1 2>/dev/null | tr '\n' ' ')"
    FAILED=1
fi
if [ ! -e "${STATE_DIR}/enrollment.json" ] && [ ! -e "${STATE_DIR}/device-token" ]; then
    note "ok   enrollment.json and device-token removed"
else
    note "FAIL enrollment.json or device-token survived unenroll"
    FAILED=1
fi

# --- 16. personal state restored (the preference recorded in 8 resurfaces) ---
"${CTL}" --json policy explain security.firewall \
    > "${RUN_DIR}/m5-explain-personal.json" 2>&1
jq_check "explain after unenroll: local_user_preference rank 5, enabled, override permitted" \
    "${RUN_DIR}/m5-explain-personal.json" \
    '.source.kind == "local_user_preference" and .source.rank == 5
     and .effective_value == "enabled"
     and .user_override_permitted == true'
"${CTL}" policy explain security.firewall \
    > "${RUN_DIR}/m5-explain-personal.txt" 2>&1
if grep -q  'Personal preference' "${RUN_DIR}/m5-explain-personal.txt" \
        && grep -qi 'permitted' "${RUN_DIR}/m5-explain-personal.txt"; then
    note "ok   human explain back to the personal spec-40 layout (Personal preference, Permitted)"
else
    note "FAIL human personal explain layout: $(head -c 240 "${RUN_DIR}/m5-explain-personal.txt" 2>/dev/null)"
    FAILED=1
fi
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "ok   nft table stands after unenroll (the §5.4 deliberate re-record kept it green)"
else
    note "FAIL nft table gone after unenroll"
    FAILED=1
fi
"${CTL}" --json status > "${RUN_DIR}/m5-status-personal.json" 2>&1
jq_check "punarctl status after unenroll: mode personal, no org field" \
    "${RUN_DIR}/m5-status-personal.json" \
    '.mode == "personal" and .enrolled == false and (has("org") | not)'
cp "${STATUS_JSON}" "${RUN_DIR}/m5-statusfile-personal.json" 2>/dev/null
jq_check "status.json after unenroll: enrolled false" \
    "${RUN_DIR}/m5-statusfile-personal.json" '.enrolled == false'

# --- 17. screenshot: chrome gone (calm paper) --------------------------------
capture_shot punar-m5-personal.png

# --- 18. full audit lifecycle + the final token sweep ------------------------
if jq -s -e 'any(.[]; .action == "enroll.start" and .result == "success"
                 and .policy_ids == ["eng-baseline-v12"])' \
        "${AUDIT_LOG}" >/dev/null 2>&1; then
    note "ok   audit: enroll.start success with policy_ids [eng-baseline-v12]"
else
    note "FAIL audit: no enroll.start success event"
    FAILED=1
fi
if jq -s -e 'any(.[]; .action == "enroll.stop" and .result == "success"
                 and .policy_ids == ["eng-baseline-v12"])' \
        "${AUDIT_LOG}" >/dev/null 2>&1; then
    note "ok   audit: enroll.stop success with policy_ids [eng-baseline-v12]"
else
    note "FAIL audit: no enroll.stop success event"
    FAILED=1
fi
token_grep_zero "final sweep"

# --- 19. teardown: shipped defaults restored ---------------------------------
mock_active="$(systemctl is-active "${MOCK}" 2>/dev/null)"
if [ "${mock_active}" != "active" ]; then
    note "ok   ${MOCK} stopped at exit (is-active: ${mock_active})"
else
    note "FAIL ${MOCK} still active at exit"
    FAILED=1
fi
if systemctl start "${TIMER}" >/dev/null 2>&1; then
    note "ok   ${TIMER} restarted (shipped default restored)"
else
    note "FAIL ${TIMER} failed to restart"
    FAILED=1
fi
check_eq "${TIMER} is-active after restore" active \
    "$(systemctl is-active "${TIMER}" 2>/dev/null)"

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M5_OK"
else
    note "PUNAR_M5_FAIL"
fi
# Full report onto stdout -> journal+console -> serial log, so a failed
# export still leaves the per-assertion detail (and the verdict fallback
# tools/boot-test.sh greps for) in serial.log.
cat "${REPORT}"
exit 0
