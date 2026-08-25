#!/bin/sh
# M3 in-VM daemon/CLI exercise (milestone-3.md §8; spec 74.4 "unauthorized
# IPC", section 60 no-exec, section 73 denial voice). Runs AS ROOT via
# punar-m3-check.service (no User= — the service manager is the decided root
# path); unprivileged paths use runuser -u punar / -u nobody (util-linux, in
# base). idle-ram.sh starts this synchronously AFTER punar-m2-check.service
# and BEFORE the artifact export, so the hostname mutation never touches the
# idle-RAM window and everything written into /run/punar here (m3-report.txt,
# m3-*.json snapshots) ships in the same export tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m3-report.txt
# (`PUNAR_M3_OK` / `PUNAR_M3_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh) parses the exported report and hard-fails on
# PUNAR_M3_FAIL or a truncated report.
#
# Assertions (milestone-3.md §8; all machine checks via --json + jq):
#   1  punard.service active from boot (vendor wants enablement worked)
#   2  /run/punard 750 root:punar; punard.sock a socket, 660 root:punar
#   3  root `punarctl --json status`: v1, personal, unenrolled, dev_ id, 3 caps
#   4  punar-user read path: capabilities list shows security.firewall
#      enabled/nftables/local; cross-checked against a live nft table read
#   5  allowed mutation (root): hostname -> punar-m3, kernel+file agree,
#      audit event allow/success/user_id root
#   6  denial (section-73 test): punar-user set -> exit 3, stderr carries
#      "administrator" + "personal defaults", hostname unchanged, audit
#      deny/denied/policy_ids [personal-defaults]
#   7  drift: destroy table -> reconcile reports drift_count 1 (NO
#      remediation in M3), set security.firewall enabled restores the table,
#      second reconcile is clean
#   8  audit tail -n 20: every event has all 12 schema-required keys, evt_/
#      agt_ prefixes, decision enum, RFC 3339 timestamp
#   9  socket authz negative: nobody cannot even connect (0660 root:punar)
#   10 no-exec probe (section 60): debug rpc system.exec / shell.run ->
#      unknown_method surfaced, nonzero exit
set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m3-report.txt"
CTL=/usr/bin/punarctl
SOCK_DIR=/run/punard
SOCK="${SOCK_DIR}/punard.sock"
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

# --- 1. daemon up from boot --------------------------------------------------
check_eq "punard.service active (vendor wants enablement)" active \
    "$(systemctl is-active punard.service 2>/dev/null)"

# --- 2. socket-path permission contract (ipc.md 1.1-1.2) ---------------------
check_eq "${SOCK_DIR} owner:group mode" "root:punar 750" \
    "$(stat -c '%U:%G %a' "${SOCK_DIR}" 2>/dev/null)"
check_eq "${SOCK} owner:group mode" "root:punar 660" \
    "$(stat -c '%U:%G %a' "${SOCK}" 2>/dev/null)"
if [ -S "${SOCK}" ]; then
    note "ok   ${SOCK} is a unix socket"
else
    note "FAIL ${SOCK} is not a unix socket"
    FAILED=1
fi

# --- 3. status (root) --------------------------------------------------------
if "${CTL}" --json status > "${RUN_DIR}/m3-status.json" 2>&1; then
    note "ok   punarctl --json status exit 0 (root)"
else
    note "FAIL punarctl --json status exit $? (root): $(head -c 240 "${RUN_DIR}/m3-status.json")"
    FAILED=1
fi
jq_check "status shape (protocol 1, personal, unenrolled, dev_ id, 3 capabilities)" \
    "${RUN_DIR}/m3-status.json" \
    '.protocol_version == 1 and .mode == "personal" and .enrolled == false
     and (.device_id | test("^dev_[A-Za-z0-9]+$")) and .capabilities_total == 3'

# --- 4. read path as user punar + live nftables cross-check ------------------
if runuser -u punar -- "${CTL}" --json capabilities \
        > "${RUN_DIR}/m3-capabilities.json" 2>&1; then
    note "ok   punarctl --json capabilities exit 0 (user punar; group-punar read path)"
else
    note "FAIL punarctl --json capabilities exit $? (user punar): $(head -c 240 "${RUN_DIR}/m3-capabilities.json")"
    FAILED=1
fi
jq_check "security.firewall descriptor (current_state enabled, nftables, local)" \
    "${RUN_DIR}/m3-capabilities.json" \
    '[.capabilities[] | select(.capability == "security.firewall"
        and .current_state == "enabled" and .verification == "nftables"
        and .managed_by == "local")] | length == 1'
if nft -j list table inet punar-base > "${RUN_DIR}/m3-nft-table.json" 2>/dev/null; then
    note "ok   nft table inet punar-base exists (descriptor state is a live read)"
else
    note "FAIL nft -j list table inet punar-base exited nonzero (boot reconcile did not apply the baseline?)"
    FAILED=1
fi

# --- 5. allowed mutation (root): system.hostname -----------------------------
if "${CTL}" capabilities set system.hostname punar-m3 >/dev/null 2>&1; then
    note "ok   capabilities set system.hostname punar-m3 exit 0 (root)"
else
    note "FAIL capabilities set system.hostname punar-m3 exit $? (root)"
    FAILED=1
fi
check_eq "kernel hostname after set" punar-m3 "$(cat /proc/sys/kernel/hostname 2>/dev/null)"
check_eq "/etc/hostname after set" punar-m3 "$(cat /etc/hostname 2>/dev/null)"
"${CTL}" --json audit tail -n 1 > "${RUN_DIR}/m3-audit-allow.json" 2>/dev/null
jq_check "audit event for allowed set (allow/success/root)" \
    "${RUN_DIR}/m3-audit-allow.json" \
    '.events | last | (.action == "capabilities.set" and .resource == "system.hostname"
     and .decision == "allow" and .result == "success" and .user_id == "root")'

# --- 6. denial as user punar (section-73 voice, exit 3, audited deny) --------
DENY_ERR="${RUN_DIR}/m3-deny-stderr.txt"
runuser -u punar -- "${CTL}" capabilities set system.hostname mallory \
    >/dev/null 2>"${DENY_ERR}"
check_eq "denied set exit code (user punar)" 3 "$?"
if grep -qi 'administrator' "${DENY_ERR}" && grep -qi 'personal defaults' "${DENY_ERR}"; then
    note "ok   denial stderr carries the section-73 voice (administrator + personal defaults)"
else
    note "FAIL denial stderr voice check: $(head -c 240 "${DENY_ERR}" 2>/dev/null || echo empty)"
    FAILED=1
fi
check_eq "hostname unchanged after denial" punar-m3 "$(cat /proc/sys/kernel/hostname 2>/dev/null)"
"${CTL}" --json audit tail -n 1 > "${RUN_DIR}/m3-audit-deny.json" 2>/dev/null
jq_check "audit event for denial (deny/denied/punar/personal-defaults)" \
    "${RUN_DIR}/m3-audit-deny.json" \
    '.events | last | (.decision == "deny" and .result == "denied"
     and .user_id == "punar" and .policy_ids == ["personal-defaults"])'

# --- 7. drift report (no remediation) + real firewall apply ------------------
nft destroy table inet punar-base >/dev/null 2>&1
if "${CTL}" --json reconcile > "${RUN_DIR}/m3-reconcile-drift.json" 2>&1; then
    note "ok   reconcile exit 0 with table destroyed (root)"
else
    note "FAIL reconcile exit $? with table destroyed"
    FAILED=1
fi
jq_check "reconcile reports exactly the firewall drift" \
    "${RUN_DIR}/m3-reconcile-drift.json" \
    '.drift_count == 1 and ([.capabilities[] | select(.capability == "security.firewall"
        and .current_state == "disabled" and .drift == true)] | length == 1)'
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "FAIL reconcile remediated the table (M3 must report only; remediation is M4)"
    FAILED=1
else
    note "ok   reconcile did not remediate (table still absent — report-only confirmed)"
fi
if "${CTL}" capabilities set security.firewall enabled >/dev/null 2>&1; then
    note "ok   capabilities set security.firewall enabled exit 0 (root)"
else
    note "FAIL capabilities set security.firewall enabled exit $?"
    FAILED=1
fi
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "ok   nft table restored by the capability apply (real apply+verify)"
else
    note "FAIL nft table absent after set security.firewall enabled"
    FAILED=1
fi
"${CTL}" --json reconcile > "${RUN_DIR}/m3-reconcile-clean.json" 2>/dev/null
jq_check "second reconcile is clean (drift_count 0)" \
    "${RUN_DIR}/m3-reconcile-clean.json" '.drift_count == 0'

# --- 8. audit schema shape over the tail (schemas/audit/audit-event.json) ----
"${CTL}" --json audit tail -n 20 > "${RUN_DIR}/m3-audit-tail.json" 2>/dev/null
jq_check "audit tail: 12 required keys + prefixes + enums + RFC 3339 on every event" \
    "${RUN_DIR}/m3-audit-tail.json" \
    '(.events | length) > 0 and (.events | all(
       (keys | contains(["event_id","timestamp","device_id","user_id",
                         "agent_session_id","project_id","source","action",
                         "resource","decision","policy_ids","result"]))
       and (.event_id | test("^evt_[A-Za-z0-9]+$"))
       and (.agent_session_id | test("^agt_[A-Za-z0-9]+$"))
       and (.decision | IN("allow","deny","approval_required"))
       and (.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$"))
     ))'

# --- 9. socket authz negative (74.4): nobody cannot connect ------------------
runuser -u nobody -- "${CTL}" status >/dev/null 2>&1
rc=$?
if [ "${rc}" -ne 0 ]; then
    note "ok   punarctl status as nobody rejected (exit ${rc}; 0660 root:punar admission)"
else
    note "FAIL punarctl status as nobody succeeded — socket admission broken"
    FAILED=1
fi

# --- 10. no-exec probe (section 60): generic execution must not exist --------
for method in system.exec shell.run; do
    probe_out="$("${CTL}" debug rpc "${method}" 2>&1)"
    rc=$?
    if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -q "${method}"; then
        note "ok   debug rpc ${method} rejected (unknown_method, exit ${rc})"
    else
        note "FAIL debug rpc ${method} (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
        FAILED=1
    fi
done

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M3_OK"
else
    note "PUNAR_M3_FAIL"
fi
# Full report onto stdout -> journal+console -> serial log, so a failed
# export still leaves the per-assertion detail (and the verdict fallback
# tools/boot-test.sh greps for) in serial.log.
cat "${REPORT}"
exit 0
