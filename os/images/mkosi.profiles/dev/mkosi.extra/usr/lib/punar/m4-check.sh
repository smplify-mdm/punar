#!/bin/sh
# M4 in-VM policy/reconcile exercise (milestone-4.md §10; SPEC sections 39,
# 40, 42, 43, 52, 73). Runs AS ROOT via punar-m4-check.service; the
# unprivileged read path uses runuser -u punar. idle-ram.sh starts this
# synchronously AFTER punar-m3-check.service and BEFORE the artifact export,
# so everything written into /run/punar here (m4-report.txt, m4-*.json
# snapshots, m4-explain-*.txt) ships in the same export tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m4-report.txt
# (`PUNAR_M4_OK` / `PUNAR_M4_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh) parses the exported report and hard-fails on
# PUNAR_M4_FAIL or a truncated report.
#
# Timer determinism (milestone-4.md §10.1): phase A (assertions 1–8) runs
# with punard-reconcile.timer STOPPED (m3-check stopped it at its top; we
# stop again defensively) so every state change below has exactly one actor.
# Phase B (the drift demo, assertions 9–10) starts the timer and leaves it
# running — the shipped default.
#
# State inherited from m3-check (order matters, used deliberately):
# system.hostname and security.firewall were `capabilities.set` by m3-check
# → both carry USER-PREFERENCE provenance (rank 5); time.timezone was never
# set → OS-DEFAULT provenance (rank 6). Both source kinds get exercised.
#
# Assertions (milestone-4.md §10.2; machine checks via --json + jq):
#   1  punard-reconcile.timer wired via vendor wants (symlink + Wants —
#      mkosi's /etc preset wipe); is-active after the phase-B start
#   2  layer stores exist 0600 root:root; M3 desired.json absent (fresh
#      install — the migration path is host-cargo-test-only, §10.3)
#   3  policy.effective as user punar: 3 entries, full entry shape,
#      user_override_permitted true everywhere (personal mode)
#   4  explain time.timezone -> os_secure_default rank 6 (JSON) + the spec
#      section 40 layout in human output
#   5  explain security.firewall -> local_user_preference rank 5 ("Personal
#      preference") — m3-check's set recorded the preference
#   6  set firewall disabled -> table really gone, explain shows
#      disabled/compliant (disabled by your own preference IS compliant —
#      desired == observed), preferences.json carries the entry (set_by root)
#   7  re-enable -> table back, explain enabled/compliant
#   8  status compliance block: overall compliant, 4 per-capability rows,
#      drift_remediated_total captured as baseline B
#   9  DRIFT DEMO (timer-driven): start timer, destroy the nft table, table
#      restored within 375 s (3 x 120 s periods + 15 s AccuracySec slack);
#      reconcile.remediate success audit event with policy_ids
#      ["personal-defaults"]; drift_remediated_total >= B+1; overall
#      compliant again
#   10 loop protection NOT tripped: no attempts_exhausted event anywhere in
#      the audit log, no non_compliant capability in status
#   11 unknown path -> exit 1, section-73 voice naming the path
#   12 no write-side policy method: debug rpc policy.set -> unknown_method
set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m4-report.txt"
CTL=/usr/bin/punarctl
STATE_DIR=/var/lib/punar
AUDIT_LOG=/var/log/punar/audit.jsonl
TIMER=punard-reconcile.timer
# 3 timer periods (OnBootSec/OnUnitActiveSec=120) + AccuracySec=15 slack.
DRIFT_BUDGET_SECS=375
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

# =============================================================================
# Phase A — timer stopped (deterministic single-actor state changes)
# =============================================================================
systemctl stop "${TIMER}" >/dev/null 2>&1

# --- 1a. timer vendored (enablement survived the mkosi /etc preset wipe) -----
# Vendor-wants units report is-enabled=disabled (enablement state tracks
# /etc only — the same semantics observed with greetd/punard). Assert the
# wiring itself: the symlink exists AND multi-user.target Wants the timer.
if [ -L "/usr/lib/systemd/system/multi-user.target.wants/${TIMER}" ] \
    && systemctl show -p Wants multi-user.target 2>/dev/null | grep -q "${TIMER}"; then
    note "ok   ${TIMER} wired via vendor wants (symlink + multi-user Wants)"
else
    note "FAIL ${TIMER} vendor wants wiring missing (symlink or Wants)"
    FAILED=1
fi

# --- 2. layer stores (milestone-4.md §3.1) -----------------------------------
check_eq "${STATE_DIR}/os-defaults.json owner mode" "root:root 600" \
    "$(stat -c '%U:%G %a' "${STATE_DIR}/os-defaults.json" 2>/dev/null)"
check_eq "${STATE_DIR}/preferences.json owner mode (created by m3-check's sets)" "root:root 600" \
    "$(stat -c '%U:%G %a' "${STATE_DIR}/preferences.json" 2>/dev/null)"
if [ -e "${STATE_DIR}/desired.json" ]; then
    note "FAIL ${STATE_DIR}/desired.json exists (M3 store on a fresh M4 image?)"
    FAILED=1
else
    note "ok   ${STATE_DIR}/desired.json absent (fresh install; migration is host-test-only)"
fi

# --- 3. policy.effective as user punar (read path open to group punar) -------
if runuser -u punar -- "${CTL}" --json policy effective \
        > "${RUN_DIR}/m4-effective.json" 2>&1; then
    note "ok   punarctl --json policy effective exit 0 (user punar)"
else
    note "FAIL punarctl --json policy effective exit $? (user punar): $(head -c 240 "${RUN_DIR}/m4-effective.json")"
    FAILED=1
fi
jq_check "effective document: four named entries, full shape, override permitted everywhere" \
    "${RUN_DIR}/m4-effective.json" \
    '(.entries | length) == 4
     and ([.entries[].path] | sort
          == ["security.firewall", "system.update_channel", "time.timezone", "update.status"])
     and (.entries | all(
       has("path") and has("effective_value") and has("compliance_state")
       and (.source | has("kind") and has("rank") and has("policy_id") and has("name"))
       and .user_override_permitted == true))'

# --- 4. OS-default provenance: time.timezone (never set) ---------------------
"${CTL}" --json policy explain time.timezone \
    > "${RUN_DIR}/m4-explain-timezone.json" 2>&1
jq_check "explain time.timezone: os_secure_default, rank 6, personal-defaults, compliant" \
    "${RUN_DIR}/m4-explain-timezone.json" \
    '.source.kind == "os_secure_default" and .source.rank == 6
     and .source.policy_id == "personal-defaults"
     and .compliance_state == "compliant"'
"${CTL}" policy explain time.timezone \
    > "${RUN_DIR}/m4-explain-timezone.txt" 2>&1
if grep -qi 'effective value' "${RUN_DIR}/m4-explain-timezone.txt" \
        && grep -q  'OS default'      "${RUN_DIR}/m4-explain-timezone.txt" \
        && grep -q  'personal-defaults' "${RUN_DIR}/m4-explain-timezone.txt" \
        && grep -qi 'permitted'       "${RUN_DIR}/m4-explain-timezone.txt" \
        && grep -qi 'compliant'       "${RUN_DIR}/m4-explain-timezone.txt"; then
    note "ok   human explain renders the spec section 40 layout (value/source/policy/override/compliance)"
else
    note "FAIL human explain layout: $(head -c 240 "${RUN_DIR}/m4-explain-timezone.txt" 2>/dev/null)"
    FAILED=1
fi

# --- 5. user-preference provenance: security.firewall (m3-check set it) ------
"${CTL}" --json policy explain security.firewall \
    > "${RUN_DIR}/m4-explain-firewall.json" 2>&1
jq_check "explain security.firewall: local_user_preference, rank 5, enabled" \
    "${RUN_DIR}/m4-explain-firewall.json" \
    '.source.kind == "local_user_preference" and .source.rank == 5
     and .source.name == "Personal preference"
     and .effective_value == "enabled"'

# --- 6. set writes the preference layer; disabled-by-choice IS compliant -----
if "${CTL}" capabilities set security.firewall disabled >/dev/null 2>&1; then
    note "ok   capabilities set security.firewall disabled exit 0 (root)"
else
    note "FAIL capabilities set security.firewall disabled exit $?"
    FAILED=1
fi
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "FAIL nft table still present after set disabled (apply did not happen)"
    FAILED=1
else
    note "ok   nft table gone after set disabled (really applied)"
fi
"${CTL}" --json policy explain security.firewall \
    > "${RUN_DIR}/m4-explain-firewall-disabled.json" 2>&1
jq_check "explain after disable: effective disabled AND compliant (own preference == observed)" \
    "${RUN_DIR}/m4-explain-firewall-disabled.json" \
    '.effective_value == "disabled" and .compliance_state == "compliant"'
jq_check "preferences.json carries the security.firewall entry (set_by root)" \
    "${STATE_DIR}/preferences.json" \
    '.preferences["security.firewall"].value == "disabled"
     and .preferences["security.firewall"].set_by == "root"'

# --- 7. re-enable (the state the rest of the exercise and the demo need) -----
if "${CTL}" capabilities set security.firewall enabled >/dev/null 2>&1; then
    note "ok   capabilities set security.firewall enabled exit 0 (root)"
else
    note "FAIL capabilities set security.firewall enabled exit $?"
    FAILED=1
fi
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "ok   nft table back after re-enable"
else
    note "FAIL nft table absent after re-enable"
    FAILED=1
fi
"${CTL}" --json policy explain security.firewall \
    > "${RUN_DIR}/m4-explain-firewall-enabled.json" 2>&1
jq_check "explain after re-enable: effective enabled, compliant" \
    "${RUN_DIR}/m4-explain-firewall-enabled.json" \
    '.effective_value == "enabled" and .compliance_state == "compliant"'

# --- 8. status compliance block (section 52, personal scope) + baseline B ----
"${CTL}" --json status > "${RUN_DIR}/m4-status-a.json" 2>&1
jq_check "status compliance: overall compliant, 4 capability rows, counter is a number" \
    "${RUN_DIR}/m4-status-a.json" \
    '.compliance.overall == "compliant"
     and (.compliance.capabilities | length) == 4
     and (.compliance.capabilities | all(.state == "compliant"))
     and (.compliance.drift_remediated_total | type) == "number"'
BASELINE="$(jq -r '.compliance.drift_remediated_total' "${RUN_DIR}/m4-status-a.json" 2>/dev/null)"
case "${BASELINE}" in
    ''|*[!0-9]*)
        note "FAIL drift_remediated_total baseline not a non-negative integer: '${BASELINE}'"
        FAILED=1
        BASELINE=0
        ;;
    *)
        # The exact value is order-dependent (m3-check's amended step 7 already
        # drove one timer-less remediation) — assert type + monotonicity only.
        note "ok   drift_remediated_total baseline B=${BASELINE}"
        ;;
esac

# =============================================================================
# Phase B — the timer-driven firewall-drift demo (milestone-4.md §10.2 #9)
# =============================================================================
# Start the timer, then destroy the table and wait for the AUTONOMOUS path to
# restore it. A timer restarted long after boot may elapse immediately
# (OnBootSec=120 is already in the past) and reconcile cleanly before the
# destroy lands — the next OnUnitActiveSec=120 firing then remediates; the
# 375 s budget (3 periods + AccuracySec slack) covers every interleaving.
if systemctl start "${TIMER}" >/dev/null 2>&1; then
    note "ok   ${TIMER} started for the drift demo"
else
    note "FAIL ${TIMER} failed to start"
    FAILED=1
fi
check_eq "${TIMER} is-active (autonomous path armed)" active \
    "$(systemctl is-active "${TIMER}" 2>/dev/null)"

nft destroy table inet punar-base >/dev/null 2>&1
if nft -j list table inet punar-base >/dev/null 2>&1; then
    # Informational, not a FAIL: either destroy failed (then no new
    # remediation happens and the counter assertion below fails) or the
    # timer's immediate elapse already remediated in the race window (then
    # the counter assertion below passes) — the B+1 check disambiguates.
    note "note table present immediately after destroy (raced a timer firing? counter check disambiguates)"
else
    note "ok   drift injected (nft table inet punar-base destroyed)"
fi

demo_start="$(date +%s)"
demo_deadline=$((demo_start + DRIFT_BUDGET_SECS))
restored=0
while [ "$(date +%s)" -lt "${demo_deadline}" ]; do
    if nft -j list table inet punar-base >/dev/null 2>&1; then
        restored=1
        break
    fi
    sleep 5
done
demo_elapsed=$(($(date +%s) - demo_start))
if [ "${restored}" -eq 1 ]; then
    note "ok   table restored by the timer-driven reconcile after ${demo_elapsed}s (budget ${DRIFT_BUDGET_SECS}s)"
else
    note "FAIL table NOT restored within ${DRIFT_BUDGET_SECS}s (timer-driven remediation absent)"
    FAILED=1
fi

"${CTL}" --json audit tail -n 50 > "${RUN_DIR}/m4-audit-tail.json" 2>&1
jq_check "reconcile.remediate success audit event (firewall, policy_ids [personal-defaults])" \
    "${RUN_DIR}/m4-audit-tail.json" \
    '.events | any(.action == "reconcile.remediate"
       and .resource == "security.firewall"
       and .decision == "allow" and .result == "success"
       and .policy_ids == ["personal-defaults"])'

"${CTL}" --json status > "${RUN_DIR}/m4-status-b.json" 2>&1
jq_check "post-demo status: overall compliant, counter incremented past B=${BASELINE}" \
    "${RUN_DIR}/m4-status-b.json" \
    ".compliance.overall == \"compliant\"
     and .compliance.drift_remediated_total >= $((BASELINE + 1))
     and (.compliance.last_remediation_at | type) == \"string\""

# --- 10. loop protection untriggered (happy path never exhausts attempts) ----
# Direct read of the full audit log (we are root); `audit tail -n` windows
# would miss early events. attempts_exhausted anywhere = a remediation loop
# fired 3 consecutive failures — never expected in this exercise.
jq -e -s 'any(.result == "attempts_exhausted")' "${AUDIT_LOG}" >/dev/null 2>&1
case "$?" in
    1)
        note "ok   no attempts_exhausted event in the full audit log"
        ;;
    0)
        note "FAIL attempts_exhausted event found in ${AUDIT_LOG} (loop protection tripped)"
        FAILED=1
        ;;
    *)
        note "FAIL ${AUDIT_LOG} unreadable/malformed for the attempts_exhausted scan"
        FAILED=1
        ;;
esac
jq_check "no capability is non_compliant in status" \
    "${RUN_DIR}/m4-status-b.json" \
    '.compliance.capabilities | all(.state != "non_compliant")'

# --- 11. unknown path -> section-73 voice, exit 1 ----------------------------
runuser -u punar -- "${CTL}" policy explain security.doesnotexist \
    >/dev/null 2>"${RUN_DIR}/m4-explain-unknown.txt"
check_eq "explain unknown path exit code" 1 "$?"
if grep -q 'security.doesnotexist' "${RUN_DIR}/m4-explain-unknown.txt" \
        && grep -q 'punarctl policy effective' "${RUN_DIR}/m4-explain-unknown.txt" \
        && grep -q 'Next step' "${RUN_DIR}/m4-explain-unknown.txt"; then
    note "ok   unknown-path stderr names the path and reads as section-73 prose"
else
    note "FAIL unknown-path stderr voice: $(head -c 240 "${RUN_DIR}/m4-explain-unknown.txt" 2>/dev/null || echo empty)"
    FAILED=1
fi

# --- 12. no write-side policy method (section 60 posture) --------------------
probe_out="$("${CTL}" debug rpc policy.set 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -q 'policy.set'; then
    note "ok   debug rpc policy.set rejected (unknown_method, exit ${rc})"
else
    note "FAIL debug rpc policy.set (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi

# The timer stays RUNNING from here on — that is the shipped default
# (milestone-4.md §10.1); later reconciles are clean no-ops.

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M4_OK"
else
    note "PUNAR_M4_FAIL"
fi
# Full report onto stdout -> journal+console -> serial log, so a failed
# export still leaves the per-assertion detail (and the verdict fallback
# tools/boot-test.sh greps for) in serial.log.
cat "${REPORT}"
exit 0
