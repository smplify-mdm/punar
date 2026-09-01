#!/bin/sh
# M9 in-VM exercise: local graphical approval, short-lived mock credentials,
# just-in-time privilege, and the redaction sweep (milestone-9.md §12; SPEC
# sections 20, 28, 29, 48, 53, 60, 73 and 1.22). Runs AS ROOT via
# punar-m9-check.service; every unprivileged step runs as punar through the
# M7/M8 runuser + session-env pattern, and every AGENT-originated step runs
# inside the managed session's own scope cgroup through
# /usr/lib/punar/in-agent-scope.sh. idle-ram.sh starts this synchronously
# AFTER punar-m8-check.service and BEFORE the artifact export, so everything
# written into /run/punar here ships in the same export tar — and, more
# importantly, so the redaction sweep in group 9 runs against the tar that is
# actually shipped.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m9-report.txt
# (`PUNAR_M9_OK` / `PUNAR_M9_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh phase 11) parses the exported report and
# hard-fails on PUNAR_M9_FAIL or a truncated report.
#
# WHAT THIS EXERCISE IS ACTUALLY PROVING — the four laws of the milestone:
#   1. An approval is a GATE, not a notification. Group 2 shows the agent's
#      mutation returning exit 4 with NOTHING applied; group 5 shows the same
#      mutation taking effect only after a human answers, verified against a
#      live nft read rather than a cached descriptor.
#   2. An AI agent may approve NOTHING. Group 4 runs `approvals resolve` from
#      inside the agent's own cgroup and asserts the refusal, the audit
#      record of it, and that the request is still pending afterwards.
#   3. A secret value leaves the broker exactly ONCE, on a fd, and is never
#      written by Punar. Group 9 greps every file Punar owns, the journal,
#      the whole export tar and every punar process's environ and cmdline for
#      the two tokens actually issued — with a negative control proving the
#      grep would have found them.
#   4. Nothing is claimed that has no producer. Group 10 asserts that the M8
#      ledger's credential rows filled in for real and that the rows M9 does
#      not fill are still named with an honest milestone.
#
# HONEST DEVIATION FROM THE WRITTEN PLAN (spec 1.22), stated here and again
# as an `info` line in the report: the plan's group 6 asked for a 15-second
# approval TTL via `capabilities set --ttl 15`. That flag does not exist and
# must not: milestone-9.md §5.1 fixes the `capabilities.set` request shape as
# UNCHANGED, and the image ships no python/socat/nc with which to hand-craft
# a socket frame. The expiry group therefore uses the real shipped TTL
# (300 s) and starts its clock EARLY, so the other groups run inside the
# window and the incremental wall-clock cost is the remainder, not 300 s.
#
# IMAGE TOOLING TRAPS carried from earlier milestones:
#   - No diffutils: compare with sha256sum, never cmp/diff (M6 lesson).
#   - `qs ipc call` clients MUST pass -p /usr/share/punar/shell (M2 lesson).
#   - fmt::verdict uppercases: every rendered-word grep is case-insensitive
#     (M5 lesson).
#   - No python, socat or nc; jq IS present and does all JSON work here.
#   - There is no JSON-Schema validator in the image, so the approval
#     document is checked twice: by jq here, and against
#     schemas/audit/approval.json on the HOST by boot-test phase 11.
#   - A bounded sleep for a KNOWN ttl is a wait, not a poll (spec 6.3).

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m9-report.txt"
CTL=/usr/bin/punarctl
ENV_BIN=/usr/bin/punar-env
IN_SCOPE=/usr/lib/punar/in-agent-scope.sh
SECRETS_UNIT=punar-secrets.service
SECRETS_SOCK=/run/punar-secrets/secrets.sock
SECRETS_RUN_DIR=/run/punar-secrets
CLASSES_FILE=/usr/share/punar/secrets/classes.yaml
AI_DEFAULTS=/usr/share/punar/policy/ai-defaults.yaml
APPROVALS_DIR=/var/lib/punar/approvals
GRANTS_DIR=/var/lib/punar/grants
SUMMARY_FILE=/run/punard/approvals.json
AUDIT_LOG=/var/log/punar/audit.jsonl
LEDGER_DIR=/var/lib/punar/agents/ledger
PUNAR_HOME=/home/punar
ATLAS="${PUNAR_HOME}/atlas"
FIXTURE_DIR=/usr/share/punar/fixtures/projects/atlas
LAUNCH_OUT="${RUN_DIR}/m9-launch.txt"
WANTS_LINK=/usr/lib/systemd/system/multi-user.target.wants/punar-secrets.service
FAILED=0
SID=""
LAUNCH_PID=""
SCOPE_PROCS=""

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

# check_true <name> <status> — 0 is ok, anything else is a failure.
check_true() {
    if [ "$2" -eq 0 ]; then
        note "ok   $1"
    else
        note "FAIL $1 (status $2)"
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

# jq_slurp_check <name> <jsonl-file> <jq filter over the slurped array>
jq_slurp_check() {
    if jq -e -s "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq -s filter: $3; input head: $(head -c 240 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# grep_row <name> <file> <fixed string, matched case-insensitively>
grep_row() {
    if grep -qiF "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (missing: '$3'; head: $(head -c 200 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# audit_count <jq select body> — number of audit events matching.
audit_count() {
    jq -c "select($1)" "${AUDIT_LOG}" 2>/dev/null | wc -l | tr -d ' '
}

# first_apr <file> — the first apr_ id mentioned anywhere in a file.
first_apr() {
    grep -o 'apr_[A-Za-z0-9][A-Za-z0-9]*' "$1" 2>/dev/null | head -n 1
}

# os_timezone — the timezone the OPERATING SYSTEM is actually in, read from
# the one artifact the capability is defined on.
#
# NOT `timedatectl`: that is a D-Bus property of systemd-timedated, which
# reads /etc/localtime once at activation and caches it for the lifetime of
# the (idle-exiting) process. punard owns time.timezone as the
# /etc/localtime symlink and never speaks to timedated (milestone-3.md
# section 4.3: observe = readlink, apply = symlink + rename(2), descriptor
# `verification: "symlink"`), so a timedated read is a STALE PROXY that can
# report the pre-change zone long after the change landed — which is exactly
# what it did in the M9 run. readlink is the ground truth, is uncached, and
# is independent of punard: it goes to the filesystem, not to any Punar
# process or rendered card. Accepts both absolute
# ("/usr/share/zoneinfo/Europe/Berlin") and relative
# ("../usr/share/zoneinfo/UTC") link forms; anything else is "unknown",
# which fails loudly rather than silently.
os_timezone() {
    tz_link="$(readlink /etc/localtime 2>/dev/null)" || tz_link=""
    case "${tz_link}" in
        */zoneinfo/*) printf '%s\n' "${tz_link##*/zoneinfo/}" ;;
        *) printf 'unknown\n' ;;
    esac
}

PUNAR_UID="$(id -u punar 2>/dev/null || echo 1000)"
PUNAR_RUN="/run/user/${PUNAR_UID}"

WL_DISPLAY=""
for wl_sock in "${PUNAR_RUN}"/wayland-*; do
    case "${wl_sock}" in
        *.lock) ;;
        *) [ -e "${wl_sock}" ] && WL_DISPLAY="$(basename "${wl_sock}")" && break ;;
    esac
done

as_punar() {
    runuser -u punar -- env "XDG_RUNTIME_DIR=${PUNAR_RUN}" \
        "DBUS_SESSION_BUS_ADDRESS=unix:path=${PUNAR_RUN}/bus" \
        "WAYLAND_DISPLAY=${WL_DISPLAY}" \
        "HOME=${PUNAR_HOME}" "$@"
}

# in_scope <cmd...> — run one command INSIDE the managed agent session's
# scope cgroup, so punard and punar-secrets attribute it to the agent from
# the kernel's own /proc/<pid>/cgroup and nothing is declared.
#
# The `systemd-run --user` wrapper is not decoration: cgroup v2 delegation
# containment permits the migration only from inside the user manager's
# subtree, and this check runs in system.slice (the M7 hard lesson). Callers
# redirect stdout/stderr themselves.
in_scope() {
    # A unique unit name per call. The counter cannot live in a variable:
    # several call sites put in_scope in a PIPELINE (the token arrives on
    # stdin), which runs it in a subshell, so an incremented counter would
    # be lost and a name could repeat.
    as_punar systemd-run --user --pipe --wait --collect --quiet \
        --unit="punar-m9-agent-$(date -u +%s%N)" \
        -- "${IN_SCOPE}" "${SCOPE_PROCS}" "$@"
}

# --- 1. preflight ------------------------------------------------------------
check_eq "punar-secrets.service is active (the third daemon, counted in the RSS gate)" \
    "active" "$(systemctl is-active "${SECRETS_UNIT}" 2>&1)"
check_eq "broker socket mode/owner (0660 root:punar — admission IS the filesystem)" \
    "660 root punar" "$(stat -c '%a %U %G' "${SECRETS_SOCK}" 2>/dev/null)"
check_eq "broker runtime dir is root-owned (a peer-writable dir is a squattable socket)" \
    "750 root punar" "$(stat -c '%a %U %G' "${SECRETS_RUN_DIR}" 2>/dev/null)"
check_eq "approval store mode/owner (0700 root:root — this file IS the authority record)" \
    "700 root root" "$(stat -c '%a %U %G' "${APPROVALS_DIR}" 2>/dev/null)"
check_eq "grant store mode/owner" \
    "700 root root" "$(stat -c '%a %U %G' "${GRANTS_DIR}" 2>/dev/null)"
# Vendor enablement: assert the SYMLINK and the Wants=, never is-enabled —
# `systemctl is-enabled` reports `disabled` for a /usr/lib .wants unit (the
# M4 lesson, re-learned twice).
if [ -L "${WANTS_LINK}" ]; then
    note "ok   vendor wants symlink exists: ${WANTS_LINK} -> $(readlink "${WANTS_LINK}")"
else
    note "FAIL no vendor wants symlink at ${WANTS_LINK}"
    FAILED=1
fi
if systemctl show multi-user.target --property=Wants --value 2>/dev/null | tr ' ' '\n' \
        | grep -qx 'punar-secrets.service'; then
    note "ok   multi-user.target Wants= lists punar-secrets.service (the symlink took effect)"
else
    note "FAIL punar-secrets.service is not in multi-user.target Wants="
    FAILED=1
fi
for data_file in "${CLASSES_FILE}" "${AI_DEFAULTS}"; do
    if [ -s "${data_file}" ]; then
        note "ok   shipped data file present: ${data_file}"
    else
        note "FAIL missing or empty data file: ${data_file}"
        FAILED=1
    fi
done
# The catalog is DATA: assert the three shipped classes are there and that
# nothing in it looks like a value, a path or a token.
if grep -q 'id: github' "${CLASSES_FILE}" && grep -q 'id: aws-dev' "${CLASSES_FILE}" \
        && grep -q 'id: aws-prod' "${CLASSES_FILE}"; then
    note "ok   the class catalog declares github, aws-dev and aws-prod (kebab on the wire)"
else
    note "FAIL the class catalog does not declare the three M9 classes"
    FAILED=1
fi
grep_row "the AI authority document carries the section 20 credentials block" \
    "${AI_DEFAULTS}" "aws_prod: deny"
grep_row "the AI authority document gates host mutations rather than denying them" \
    "${AI_DEFAULTS}" "firewall: approval_required"

# A clean gate. The M8 exercise's agent made one approval-gated call, so a
# pending approval may already exist; deny it as root so this exercise's
# overlay assertions are about THIS exercise's card. Denying is the honest
# disposal — it is a decision, recorded, not a deletion.
as_punar "${CTL}" --json approvals list > "${RUN_DIR}/m9-approvals-pre.json" 2>/dev/null
for stale in $(jq -r '.approvals[] | select(.approval.status == "pending")
                      | .approval.approval_id' "${RUN_DIR}/m9-approvals-pre.json" 2>/dev/null); do
    as_punar "${CTL}" approvals resolve "${stale}" --decision denied >/dev/null 2>&1
    note "info denied a pre-existing pending approval left by an earlier exercise: ${stale}"
done

# --- 2. (a) an agent-originated mutation raises an approval and changes nothing
if [ ! -f "${ATLAS}/project-environment.yaml" ]; then
    mkdir -p "${ATLAS}"
    cp "${FIXTURE_DIR}/project-environment.yaml" \
       "${FIXTURE_DIR}/project-network-policy.json" "${ATLAS}/" 2>/dev/null
    chown -R punar:punar "${ATLAS}"
    note "info Atlas project re-created from the staged fixture (earlier exercises left none)"
fi
rm -f "${ATLAS}/.punar-agent-fifo"

as_punar systemd-run --user --pipe --wait --collect --quiet \
    --unit=punar-m9-launch --setenv=PUNAR_AGENT_MOCK=1 \
    -- "${ENV_BIN}" -C "${ATLAS}" agent claude-code \
    > "${LAUNCH_OUT}" 2>&1 &
LAUNCH_PID=$!

waited=0
while [ "${waited}" -lt 180 ]; do
    if grep -qi 'Waiting for SIGTERM' "${LAUNCH_OUT}" 2>/dev/null; then
        break
    fi
    if ! kill -0 "${LAUNCH_PID}" 2>/dev/null; then
        break
    fi
    sleep 2
    waited=$((waited + 2))
done
if grep -qi 'Waiting for SIGTERM' "${LAUNCH_OUT}" 2>/dev/null; then
    note "ok   managed agent session launched within ${waited}s"
else
    note "FAIL mock agent never reached its blocking wait after ${waited}s; launch output: $(head -c 400 "${LAUNCH_OUT}" 2>/dev/null)"
    FAILED=1
fi

SID="$(sed -n 's/^Session  *\(agt_[0-9a-f]*\).*/\1/p' "${LAUNCH_OUT}" 2>/dev/null | head -n 1)"
if [ -n "${SID}" ]; then
    note "ok   session id minted and printed: ${SID}"
else
    note "FAIL could not read a session id from ${LAUNCH_OUT}"
    FAILED=1
    SID="agt_000000000000"
fi
SCOPE="punar-agent-${SID}.scope"

# Resolve the scope's cgroup from the KERNEL, via the registered pid — the
# same path M8 group 3 uses, so the migration target is never guessed.
as_punar "${CTL}" --json agents list > "${RUN_DIR}/m9-agents-list.json" 2>/dev/null
AGENT_PID="$(jq -r ".sessions[] | select(.session_id == \"${SID}\") | .process_id" \
    "${RUN_DIR}/m9-agents-list.json" 2>/dev/null)"
CGROUP_PATH=""
if [ -n "${AGENT_PID}" ] && [ -r "/proc/${AGENT_PID}/cgroup" ]; then
    CGROUP_PATH="$(sed -n 's|^0::||p' "/proc/${AGENT_PID}/cgroup" 2>/dev/null | head -n 1)"
fi
if [ -n "${CGROUP_PATH}" ] && [ -d "/sys/fs/cgroup${CGROUP_PATH}" ]; then
    SCOPE_PROCS="/sys/fs/cgroup${CGROUP_PATH}/cgroup.procs"
    note "ok   the agent scope cgroup is readable at /sys/fs/cgroup${CGROUP_PATH}"
else
    note "FAIL could not resolve the scope cgroup for pid '${AGENT_PID:-none}' (cgroup path '${CGROUP_PATH:-none}') — every agent-originated assertion below will fail"
    FAILED=1
    SCOPE_PROCS=/dev/null
fi

as_punar "${CTL}" --json capabilities > "${RUN_DIR}/m9-firewall-before.json" 2>/dev/null
jq_check "firewall is enabled before the agent asks (the pre-state every gate assertion rests on)" \
    "${RUN_DIR}/m9-firewall-before.json" \
    '[.capabilities[] | select(.capability == "security.firewall"
        and .current_state == "enabled")] | length == 1'

in_scope "${CTL}" capabilities set security.firewall disabled \
    > "${RUN_DIR}/m9-set-stdout.txt" 2> "${RUN_DIR}/m9-set-approval.txt"
check_eq "an agent-originated capabilities.set exits 4 (approval_required — reserved since M3, real now)" \
    4 "$?"
grep_row "the refusal names the approval id the human will answer" \
    "${RUN_DIR}/m9-set-approval.txt" "apr_"
grep_row "the refusal says out loud that nothing ran" \
    "${RUN_DIR}/m9-set-approval.txt" "NOTHING HAS BEEN EXECUTED"
grep_row "the refusal says an AI agent may resolve nothing" \
    "${RUN_DIR}/m9-set-approval.txt" "AN AI AGENT MAY RESOLVE NOTHING"
if [ -s "${RUN_DIR}/m9-set-stdout.txt" ]; then
    note "FAIL a gated capabilities.set wrote to stdout — nothing ran, so there is nothing to pipe"
    FAILED=1
else
    note "ok   a gated capabilities.set writes NOTHING to stdout"
fi
APR1="$(first_apr "${RUN_DIR}/m9-set-approval.txt")"
check_eq "an approval id was raised" "yes" "$([ -n "${APR1}" ] && echo yes || echo no)"

as_punar "${CTL}" --json capabilities > "${RUN_DIR}/m9-firewall-gated.json" 2>/dev/null
jq_check "the capability did NOT change: a gate is not a notification (spec 28)" \
    "${RUN_DIR}/m9-firewall-gated.json" \
    '[.capabilities[] | select(.capability == "security.firewall"
        and .current_state == "enabled")] | length == 1'
if nft -j list table inet punar-base > "${RUN_DIR}/m9-nft-gated.json" 2>/dev/null; then
    note "ok   the live nft ruleset is still present (observed, never cached — the M3 rule)"
else
    note "FAIL nft table inet punar-base is gone while the approval is still pending"
    FAILED=1
fi

# --- 3. (b) the pending approval, validated against the shipped schema -------
as_punar "${CTL}" --json approvals list > "${RUN_DIR}/m9-approvals-list.json" 2>/dev/null
check_true "punarctl --json approvals list (any admitted peer may read the queue)" "$?"
jq -r --arg id "${APR1}" '.approvals[] | select(.approval.approval_id == $id) | .approval' \
    "${RUN_DIR}/m9-approvals-list.json" > "${RUN_DIR}/m9-approval-doc.json" 2>/dev/null
# THE schema assertion, jq half. The host half runs the same exported file
# against schemas/audit/approval.json in boot-test phase 11, because the
# image has no JSON-Schema validator and a jq spot-check alone would let
# daemon-vs-schema drift pass.
jq_check "the .approval member has EXACTLY the nine schema keys and no tenth" \
    "${RUN_DIR}/m9-approval-doc.json" \
    '(keys | sort) == ["approval_id","capability","expires_at","reason",
                       "requester","resource","risk","status","user"]'
jq_check "the approval document matches the shipped patterns and enums" \
    "${RUN_DIR}/m9-approval-doc.json" \
    '(.approval_id | test("^apr_[A-Za-z0-9]+$"))
     and (.requester.type == "ai_agent")
     and (.requester.id | test("^agt_[A-Za-z0-9]+$"))
     and (.capability == "security.firewall")
     and (.resource == "disabled")
     and (.risk == "low" or .risk == "medium" or .risk == "high")
     and (.status == "pending")
     and (.user | length) > 0
     and (.reason | length) > 0
     and (.expires_at | length) > 0'
jq_check "the requester is THIS session (attribution came from the cgroup, not a claim)" \
    "${RUN_DIR}/m9-approval-doc.json" \
    "(.requester.id == \"${SID}\")"
# The section 2.1 law, tested: consumption and execution are SIBLINGS of the
# schema document, never fields inside it and never a fifth status.
jq_check "consumed_at and execution are NOT inside .approval (the envelope law)" \
    "${RUN_DIR}/m9-approval-doc.json" \
    '(has("consumed_at") | not) and (has("execution") | not)
     and (has("resolved_at") | not) and (has("kind") | not)'
jq_check "the envelope carries the siblings, the contract line and the policy citation" \
    "${RUN_DIR}/m9-approvals-list.json" \
    "([.approvals[] | select(.approval.approval_id == \"${APR1}\")] | length) == 1
     and ([.approvals[] | select(.approval.approval_id == \"${APR1}\")] | all(
        .kind == \"capability_set\"
        and (.contract | length) > 0
        and (.policy.name | length) > 0
        and (.policy.policy_id | length) > 0
        and .execution == null))"
grep_row "the shell's summary file names the same approval" "${SUMMARY_FILE}" "${APR1}"
check_eq "the summary file is 0640 root:punar in the ROOT-owned runtime dir (anti-spoofing)" \
    "640 root punar" "$(stat -c '%a %U %G' "${SUMMARY_FILE}" 2>/dev/null)"

# --- 4. (c) an AI agent may resolve NOTHING (law 2, spec 60) -----------------
in_scope "${CTL}" approvals resolve "${APR1}" --decision approved \
    > "${RUN_DIR}/m9-self-approve-stdout.txt" 2> "${RUN_DIR}/m9-self-approve.txt"
check_eq "an agent resolving its own request exits 3 (denied)" 3 "$?"
grep_row "the refusal names the actor as an AI agent" \
    "${RUN_DIR}/m9-self-approve.txt" "AI AGENT"
grep_row "the refusal says an agent cannot approve" \
    "${RUN_DIR}/m9-self-approve.txt" "APPROVE"
as_punar "${CTL}" --json approvals get "${APR1}" > "${RUN_DIR}/m9-approval-after-self.json" 2>/dev/null
jq_check "the approval is STILL pending after the agent tried to answer it" \
    "${RUN_DIR}/m9-approval-after-self.json" \
    '.approval.status == "pending" and .execution == null'
jq -c "select(.action == \"approval.resolve\" and .agent_session_id == \"${SID}\")" \
    "${AUDIT_LOG}" > "${RUN_DIR}/m9-audit-bypass.json" 2>/dev/null
jq_slurp_check "the refusal is audited with the approval id, the agent, and the reason" \
    "${RUN_DIR}/m9-audit-bypass.json" \
    "(length >= 1) and all(.[];
       .decision == \"deny\" and .result == \"self_approval_refused\"
       and .source == \"ai_agent\" and .agent_session_id == \"${SID}\"
       and (.resource | test(\"^apr_\")))"

# --- 5. (k) the D-003 money shot, then (d) the human resolve -----------------
as_punar qs -p /usr/share/punar/shell ipc call approval open >/dev/null 2>&1
check_true "qs ipc call approval open (the Plate D-003 overlay)" "$?"
sleep 2
overlay_state="$(as_punar qs -p /usr/share/punar/shell ipc call approval state 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "approval overlay state after open" "open" "${overlay_state}"
overlay_pending="$(as_punar qs -p /usr/share/punar/shell ipc call approval pending 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "the overlay reports exactly one pending approval" "1" "${overlay_pending}"
overlay_selected="$(as_punar qs -p /usr/share/punar/shell ipc call approval selected 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "the card on screen is THIS approval (not merely 'a card is open')" \
    "${APR1}" "${overlay_selected}"
# Bounded settle for the overlay's event-driven FileView pickup and the
# countdown's first tick — not a poll.
sleep 10
if [ -n "${WL_DISPLAY}" ] && as_punar grim "${RUN_DIR}/punar-m9.png" 2>/dev/null \
        && [ -s "${RUN_DIR}/punar-m9.png" ]; then
    note "ok   grim captured punar-m9.png ($(stat -c '%s' "${RUN_DIR}/punar-m9.png") bytes) — human evidence of the D-003 approval gate"
else
    note "FAIL grim capture punar-m9.png (wayland=${WL_DISPLAY:-none})"
    FAILED=1
fi
as_punar qs -p /usr/share/punar/shell ipc call approval close >/dev/null 2>&1
overlay_state="$(as_punar qs -p /usr/share/punar/shell ipc call approval state 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "approval overlay state after Esc/close" "closed" "${overlay_state}"
overlay_pending="$(as_punar qs -p /usr/share/punar/shell ipc call approval pending 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "dismissal is NOT denial: the request is still pending after the overlay closed" \
    "1" "${overlay_pending}"

# The human answers. As punar — the routed console user, NOT root — so the
# routing rule is exercised rather than bypassed by uid 0.
as_punar "${CTL}" approvals resolve "${APR1}" --decision approved \
    > "${RUN_DIR}/m9-resolve.txt" 2>&1
check_true "the routed console user resolves the approval (exit 0)" "$?"
as_punar "${CTL}" --json approvals get "${APR1}" > "${RUN_DIR}/m9-approved.json" 2>/dev/null
jq_check "status approved, executed exactly once, and the execution names its audit event" \
    "${RUN_DIR}/m9-approved.json" \
    '.approval.status == "approved"
     and (.resolved_at | length) > 0
     and (.resolved_by.user | length) > 0
     and .execution.result == "success"
     and .execution.changed == true
     and (.execution.audit_event_id | test("^evt_"))'
EXEC_EVT="$(jq -r '.execution.audit_event_id' "${RUN_DIR}/m9-approved.json" 2>/dev/null)"
as_punar "${CTL}" --json capabilities > "${RUN_DIR}/m9-firewall-after.json" 2>/dev/null
jq_check "the capability changed only after a human said yes" \
    "${RUN_DIR}/m9-firewall-after.json" \
    '[.capabilities[] | select(.capability == "security.firewall"
        and .current_state == "disabled")] | length == 1'
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "FAIL the nft table is still present after the approved disable — the descriptor and the kernel disagree"
    FAILED=1
else
    note "ok   the live nft ruleset is gone: the approved mutation really ran (observed, not cached)"
fi
# Pointer direction 1: the execution event id names a real audit event, and
# that event is attributed to THE AGENT — the agent did it, the human allowed
# it (spec 22, milestone-9.md §5.5).
jq -c "select(.event_id == \"${EXEC_EVT}\")" "${AUDIT_LOG}" \
    > "${RUN_DIR}/m9-audit-exec.json" 2>/dev/null
jq_slurp_check "the executed capability event is attributed to the AGENT, not the resolver" \
    "${RUN_DIR}/m9-audit-exec.json" \
    "(length == 1) and all(.[];
       .action == \"capabilities.set\" and .decision == \"allow\"
       and .source == \"ai_agent\" and .agent_session_id == \"${SID}\"
       and .resource == \"security.firewall\")"
# Pointer direction 2: the approval.resolve event names the approval, and is
# attributed to the HUMAN with no agent session.
jq -c "select(.action == \"approval.resolve\" and .resource == \"${APR1}\"
              and .decision == \"allow\")" "${AUDIT_LOG}" \
    > "${RUN_DIR}/m9-audit-resolve.json" 2>/dev/null
jq_slurp_check "the resolution is audited as a HUMAN decision naming the approval id" \
    "${RUN_DIR}/m9-audit-resolve.json" \
    '(length == 1) and all(.[];
       .source == "human" and .result == "approved"
       and ((.agent_session_id == null) or (.agent_session_id == "agt_none")))'

# Restore the firewall as root, and prove the restore took.
"${CTL}" capabilities set security.firewall enabled >/dev/null 2>&1
if nft -j list table inet punar-base >/dev/null 2>&1; then
    note "ok   the firewall was restored to enabled as root (pre-state returned)"
else
    note "FAIL could not restore security.firewall to enabled"
    FAILED=1
fi

# --- 6a. (e) start the expiry clock EARLY -----------------------------------
# The plan asked for `--ttl 15`; that flag does not exist and must not
# (milestone-9.md §5.1 fixes the capabilities.set request shape). So this
# uses the SHIPPED 300 s TTL and starts the clock here, before the credential
# and privilege groups, which run inside the window. The verdict is read in
# group 6b, near the end.
in_scope "${CTL}" capabilities set security.firewall disabled \
    >/dev/null 2> "${RUN_DIR}/m9-expiring-request.txt"
check_eq "a second agent-originated mutation is gated too (exit 4)" 4 "$?"
APR2="$(first_apr "${RUN_DIR}/m9-expiring-request.txt")"
EXPIRY_START="$(date -u +%s)"
EXPIRES_AT2="$(as_punar "${CTL}" --json approvals get "${APR2}" 2>/dev/null \
    | jq -r '.approval.expires_at')"
check_eq "the second approval is a different request" "different" \
    "$([ -n "${APR2}" ] && [ "${APR2}" != "${APR1}" ] && echo different || echo same)"
note "info approval ${APR2:-none} was raised at $(date -u -d "@${EXPIRY_START}" +%H:%M:%SZ 2>/dev/null) and expires at ${EXPIRES_AT2:-unknown}; nobody will answer it, and group 6b reads the verdict after the other groups have run inside its window"

# --- 7. (f) the credential broker: allow, request, deny ----------------------
as_punar "${CTL}" --json secrets list > "${RUN_DIR}/m9-classes.json" 2>/dev/null
check_true "punarctl --json secrets list (the catalog, never a value)" "$?"
jq_check "the catalog names the mock provider and the three classes with their decisions" \
    "${RUN_DIR}/m9-classes.json" \
    '.provider == "mock" and (.attestation | test("simulated"; "i"))
     and ([.classes[].id] | sort == ["aws-dev","aws-prod","github"])
     and ([.classes[] | select(.id == "github")] | all(.decision == "allow"))
     and ([.classes[] | select(.id == "aws-dev")] | all(.decision == "request"))
     and ([.classes[] | select(.id == "aws-prod")] | all(.decision == "deny"))'
jq_check "the catalog carries no value, no token id and no hash" \
    "${RUN_DIR}/m9-classes.json" \
    '(tostring | test("punar-mock-|token|secret_value|sha256")) | not'

# github: policy allow. The VALUE is captured into a shell variable that is
# never exported and never written to a file; only the card (stderr) is kept.
TOK_GH="$(in_scope "${CTL}" secrets get github --ttl 5 \
    2> "${RUN_DIR}/m9-secret-card-github.txt")"
GH_RC=$?
GH_ISSUED_AT="$(date -u +%s)"
check_eq "an allow-policy credential is issued to the agent (exit 0)" 0 "${GH_RC}"
check_eq "the value arrived on stdout, bare (so TOKEN=\$(punarctl secrets get ...) works)" \
    "yes" "$([ -n "${TOK_GH}" ] && echo yes || echo no)"
grep_row "the card states the never-written promise" \
    "${RUN_DIR}/m9-secret-card-github.txt" "NEVER WRITTEN TO DISK"
grep_row "the card states that the provider is simulated" \
    "${RUN_DIR}/m9-secret-card-github.txt" "SIMULATED"
grep_row "the card names the class" "${RUN_DIR}/m9-secret-card-github.txt" "GITHUB"
if grep -qF -- "${TOK_GH}" "${RUN_DIR}/m9-secret-card-github.txt" 2>/dev/null; then
    note "FAIL the human card on stderr contains the token value — prose and value must never share a stream"
    FAILED=1
else
    note "ok   the human card carries no part of the value: stdout is the value, stderr is the prose"
fi

# aws-dev: policy request -> approval gate -> issue.
in_scope "${CTL}" secrets get aws-dev --ttl 60 \
    > "${RUN_DIR}/m9-awsdev-gated-stdout.txt" 2> "${RUN_DIR}/m9-awsdev-gated.txt"
check_eq "a request-policy credential exits 4 and issues NOTHING" 4 "$?"
if [ -s "${RUN_DIR}/m9-awsdev-gated-stdout.txt" ]; then
    note "FAIL a gated credential wrote to stdout — nothing was issued, so there is nothing to pipe"
    FAILED=1
else
    note "ok   a gated credential writes NOTHING to stdout"
fi
APR3="$(first_apr "${RUN_DIR}/m9-awsdev-gated.txt")"
as_punar "${CTL}" --json approvals get "${APR3}" > "${RUN_DIR}/m9-cred-approval.json" 2>/dev/null
jq_check "the credential approval is a typed method + a class, never a registry entry" \
    "${RUN_DIR}/m9-cred-approval.json" \
    '.kind == "credential_request"
     and .approval.capability == "credential.request"
     and .approval.resource == "aws-dev"
     and .approval.status == "pending"
     and .consumed_at == null'
as_punar "${CTL}" approvals resolve "${APR3}" --decision approved >/dev/null 2>&1
check_true "the human approves the credential request" "$?"
TOK_AWS="$(in_scope "${CTL}" secrets get aws-dev --ttl 60 \
    2> "${RUN_DIR}/m9-secret-card-awsdev.txt")"
AWS_RC=$?
check_eq "the approved credential is then issued (exit 0)" 0 "${AWS_RC}"
check_eq "the aws-dev value arrived on stdout" "yes" \
    "$([ -n "${TOK_AWS}" ] && echo yes || echo no)"
as_punar "${CTL}" --json approvals get "${APR3}" > "${RUN_DIR}/m9-cred-consumed.json" 2>/dev/null
jq_check "consumption is a SIBLING field: consumed_at set while status is still 'approved'" \
    "${RUN_DIR}/m9-cred-consumed.json" \
    '.approval.status == "approved" and (.consumed_at | length) > 0'
# Single use: a yes is not a standing grant.
in_scope "${CTL}" secrets get aws-dev --ttl 60 \
    >/dev/null 2> "${RUN_DIR}/m9-awsdev-second.txt"
check_eq "a SECOND aws-dev request is gated again (an approval is single-use)" 4 "$?"
APR4="$(first_apr "${RUN_DIR}/m9-awsdev-second.txt")"
check_eq "the second request raised a NEW approval id" "new" \
    "$([ -n "${APR4}" ] && [ "${APR4}" != "${APR3}" ] && echo new || echo reused)"

# aws-prod: policy deny, with the section 73 four beats.
in_scope "${CTL}" secrets get aws-prod \
    >/dev/null 2> "${RUN_DIR}/m9-secrets-deny.txt"
check_eq "a deny-policy credential exits 3" 3 "$?"
grep_row "denial beat 1 — what happened" "${RUN_DIR}/m9-secrets-deny.txt" "NOT ISSUED"
grep_row "denial beat 2 — who asked" "${RUN_DIR}/m9-secrets-deny.txt" "${SID}"
grep_row "denial beat 3 — which policy decided" \
    "${RUN_DIR}/m9-secrets-deny.txt" "PERSONAL DEFAULTS"
grep_row "denial beat 4 — what to do next" "${RUN_DIR}/m9-secrets-deny.txt" "CHANGE IT"
grep_row "the denial is honest that approval is NOT available for this class" \
    "${RUN_DIR}/m9-secrets-deny.txt" "APPROVAL IS NOT AVAILABLE FOR THIS CLASS"
if grep -qi 'punar-mock-' "${RUN_DIR}/m9-secrets-deny.txt" 2>/dev/null; then
    note "FAIL the denial message contains a token prefix"
    FAILED=1
else
    note "ok   the denial message carries no value of any kind"
fi

# Every credential audit event carries the CLASS ONLY.
jq -c 'select(.action == "credential.request" or .action == "credential.expire"
              or .action == "credential.revoke")' "${AUDIT_LOG}" \
    > "${RUN_DIR}/m9-audit-credentials.json" 2>/dev/null
jq_slurp_check "every credential audit event names a CLASS and nothing else" \
    "${RUN_DIR}/m9-audit-credentials.json" \
    '(length >= 3) and all(.[];
       .resource == "github" or .resource == "aws-dev" or .resource == "aws-prod")'

# --- 8. (g) a short-lived credential really expires, and revoke is real ------
elapsed=$(( $(date -u +%s) - GH_ISSUED_AT ))
if [ "${elapsed}" -lt 6 ]; then
    sleep $((6 - elapsed))
fi
printf '%s' "${TOK_GH}" | in_scope "${CTL}" secrets validate --class github \
    >/dev/null 2> "${RUN_DIR}/m9-validate-expired.txt"
gh_validate_rc=$?
if [ "${gh_validate_rc}" -ne 0 ]; then
    note "ok   a 5-second credential no longer validates after 6 seconds (exit ${gh_validate_rc})"
else
    note "FAIL an expired credential still validated — 'short-lived' is not enforced"
    FAILED=1
fi
if grep -qiE 'expired|lifetime lapsed|not found' "${RUN_DIR}/m9-validate-expired.txt" 2>/dev/null; then
    note "ok   the validate refusal names a VERDICT (expired / not found), not a malfunction"
else
    note "FAIL the validate refusal does not say why: $(head -c 200 "${RUN_DIR}/m9-validate-expired.txt" 2>/dev/null)"
    FAILED=1
fi
grep_row "the validate card restates that the value came from stdin and never argv" \
    "${RUN_DIR}/m9-validate-expired.txt" "NEVER ON ARGV"
check_eq "the expiry is audited exactly once, naming the class only" 1 \
    "$(audit_count '.action == "credential.expire" and .resource == "github"')"
printf '%s' "${TOK_AWS}" | in_scope "${CTL}" secrets revoke \
    >/dev/null 2> "${RUN_DIR}/m9-revoke.txt"
check_true "punarctl secrets revoke reads the value from STDIN and succeeds" "$?"
printf '%s' "${TOK_AWS}" | in_scope "${CTL}" secrets validate --class aws-dev \
    >/dev/null 2>&1
aws_validate_rc=$?
if [ "${aws_validate_rc}" -ne 0 ]; then
    note "ok   a revoked credential no longer validates (exit ${aws_validate_rc})"
else
    note "FAIL a revoked credential still validated"
    FAILED=1
fi
check_eq "the revocation is audited, naming the class only" 1 \
    "$(audit_count '.action == "credential.revoke" and .resource == "aws-dev"')"

# --- 9. (h) THE REDACTION SWEEP — the headline assertion of this milestone ---
# For EACH issued token, every place Punar writes must contain it zero times.
# The report itself records only counts: a file that printed a match would be
# the leak it is testing for.
REDACTION="${RUN_DIR}/m9-redaction.txt"
{
    echo "# M9 redaction sweep (milestone-9.md §12 group 9; SPEC section 53)."
    echo "# Counts only, never a match: a report that printed a token would BE"
    echo "# the leak it is asserting the absence of."
    echo "# Two tokens were issued in this run (classes github and aws-dev)."
} > "${REDACTION}"

CORPUS_LIST="${RUN_DIR}/m9-redaction-corpus.txt"
: > "${CORPUS_LIST}"
for f in "${AUDIT_LOG}" "${SUMMARY_FILE}" "${RUN_DIR}/agents.json" \
         "${RUN_DIR}/status.json" /run/punar-agentd/ledger.json \
         /var/lib/punar/preferences.json "${LEDGER_DIR}/index.json"; do
    [ -f "${f}" ] && echo "${f}" >> "${CORPUS_LIST}"
done
for d in "${LEDGER_DIR}" "${APPROVALS_DIR}" "${GRANTS_DIR}" \
         /var/lib/punar/policy.d "${RUN_DIR}"; do
    [ -d "${d}" ] && find "${d}" -type f >> "${CORPUS_LIST}" 2>/dev/null
done
# Every punar process's environ and cmdline: an env var cannot expire and
# /proc/<pid>/cmdline is world-readable, which is why M9 refuses both
# delivery channels (milestone-9.md §6.4).
for p in /proc/[0-9]*; do
    comm="$(cat "${p}/comm" 2>/dev/null)"
    case "${comm}" in
        punar*|quickshell|qs) ;;
        *) continue ;;
    esac
    for probe in environ cmdline; do
        [ -r "${p}/${probe}" ] && echo "${p}/${probe}" >> "${CORPUS_LIST}"
    done
done
corpus_files="$(wc -l < "${CORPUS_LIST}" | tr -d ' ')"
echo "corpus-files: ${corpus_files}" >> "${REDACTION}"
echo "journal: journalctl -b --no-pager (searched separately)" >> "${REDACTION}"

# A vacuous corpus would make every absence assertion pass for the wrong
# reason, so the corpus is asserted first — and then the NEGATIVE CONTROL:
# the class NAMES must be present in the audit trail, proving this grep
# would in fact have found a value if one had been written.
if [ "${corpus_files}" -ge 10 ]; then
    note "ok   the redaction corpus is non-empty (${corpus_files} files, plus the journal)"
else
    note "FAIL the redaction corpus has only ${corpus_files} files — the absence assertions below would be near-vacuous"
    FAILED=1
fi
if grep -qF 'aws-dev' "${AUDIT_LOG}" 2>/dev/null \
        && grep -qF 'github' "${AUDIT_LOG}" 2>/dev/null; then
    note "ok   negative control: the class NAMES do appear in the audit trail, so this grep finds what is there"
else
    note "FAIL negative control failed: the class names are not in the audit trail, so the absence sweep proves nothing"
    FAILED=1
fi

sweep_token() {
    label="$1"
    value="$2"
    if [ -z "${value}" ]; then
        note "FAIL redaction sweep for ${label}: no value was captured, so the sweep would be vacuous"
        FAILED=1
        return
    fi
    hits=0
    while IFS= read -r target; do
        if grep -qF -- "${value}" "${target}" 2>/dev/null; then
            hits=$((hits + 1))
            echo "LEAK-IN: ${target}" >> "${REDACTION}"
        fi
    done < "${CORPUS_LIST}"
    if journalctl -b --no-pager 2>/dev/null | grep -qF -- "${value}"; then
        hits=$((hits + 1))
        echo "LEAK-IN: journal" >> "${REDACTION}"
    fi
    echo "${label}: ${hits} occurrences across ${corpus_files} files + the journal" \
        >> "${REDACTION}"
    if [ "${hits}" -eq 0 ]; then
        note "ok   REDACTION: the ${label} credential appears 0 times in everything Punar writes, in the journal, and in every punar process's environ and cmdline"
    else
        note "FAIL REDACTION: the ${label} credential leaked into ${hits} location(s) — see ${REDACTION} for the file names (never the value)"
        FAILED=1
    fi
}
sweep_token "github" "${TOK_GH}"
sweep_token "aws-dev" "${TOK_AWS}"
# A second, broader sweep: the SHAPE of an issued value, so it also catches a
# token this script never held (one a daemon might have logged on a path not
# exercised here, or from a class this run never asked for).
#
# It matches the token GRAMMAR, not the bare `punar-mock-` prefix:
# store.rs mints `punar-mock-<class>-<43 base64url chars>` (TOKEN_PREFIX +
# class id + 32 bytes of entropy). The bare prefix is NOT a secret and is not
# even credential-specific — it is the leading substring of two long-shipped
# COMPONENT names, `punar-mock-smplify` (the M5 mock MDM service, its socket
# dir and its unit) and `punar-mock-agent` (the M7 fixture binary, whose
# 15-char /proc comm is `punar-mock-agen`). Those names legitimately appear
# in earlier milestones' reports, in cgroup comm dumps and in argv, so a
# prefix grep reports leaks that are not leaks and would train the reader to
# ignore this line. Requiring the class segment AND the 43-character random
# tail makes a hit mean "a value that could actually authorize something".
TOKEN_SHAPE='punar-mock-[a-z0-9-]+-[A-Za-z0-9_-]{43}'
# Negative control for THIS sweep: the grammar must match a value that really
# was issued, or its silence would prove nothing. The value goes in on stdin,
# never in argv (the same discipline `secrets validate` enforces).
if printf '%s' "${TOK_GH}" | grep -qE -- "${TOKEN_SHAPE}"; then
    note "ok   negative control: the token-shape pattern does match a really-issued value, so its silence is evidence"
else
    note "FAIL negative control: the token-shape pattern does not match an issued value — the shape sweep below proves nothing"
    FAILED=1
fi
shape_hits=0
while IFS= read -r target; do
    if grep -qE -- "${TOKEN_SHAPE}" "${target}" 2>/dev/null; then
        shape_hits=$((shape_hits + 1))
        echo "SHAPE-IN: ${target}" >> "${REDACTION}"
    fi
done < "${CORPUS_LIST}"
echo "token-shape: ${shape_hits} occurrences" >> "${REDACTION}"
if [ "${shape_hits}" -eq 0 ]; then
    note "ok   REDACTION: nothing shaped like an issued credential appears anywhere Punar writes"
else
    note "FAIL REDACTION: something shaped like an issued credential appears in ${shape_hits} location(s) — see ${REDACTION} for the file names (never the value)"
    FAILED=1
fi

# --- 10. (i) the M8 ledger filled in for real -------------------------------
as_punar "${CTL}" --json agents scan >/dev/null 2>&1
sleep 1
as_punar "${CTL}" --json agents access "${SID}" > "${RUN_DIR}/m9-access.json" 2>/dev/null
check_true "punarctl agents access --json for the session that used credentials" "$?"
jq_check "credential_classes filled with the CLASS NAMES the agent actually used" \
    "${RUN_DIR}/m9-access.json" \
    '(.summary.resources.credential_classes | index("github")) != null
     and (.summary.resources.credential_classes | index("aws-dev")) != null'
jq_check "a refused class is NOT recorded as one the agent used" \
    "${RUN_DIR}/m9-access.json" \
    '(.summary.resources.credential_classes | index("aws-prod")) == null'
jq_check "the Level-3 evidence is the audit event — the variant M8 declared and M9 produces" \
    "${RUN_DIR}/m9-access.json" \
    '[.detail.entries[] | select(.category == "credential_classes")]
     | (length >= 2) and all(.evidence == "audit_event")'
jq_check "credential_classes and credential_request LEFT not_yet_observed (their producer shipped)" \
    "${RUN_DIR}/m9-access.json" \
    '(.not_yet_observed | any(.category == "credential_classes") | not)
     and (.not_yet_observed | any(.category == "credential_request") | not)
     and (.not_yet_observed | any(.category == "policy_bypass_attempt") | not)'
# M9 re-milestoned this row M9+ -> M11+, because M9 shipped a credential
# broker and not a tool gateway. Re-milestoning is the honest move, and a
# check that pins the NUMBER makes the honest move break CI — which is what
# this class of regression is (docs/development/checks-conventions.md). What
# must hold is that the row is still there, still names A milestone, and
# still says why. The number is the daemon's business, not this file's.
# Whether the row belongs there at all is answered by THE DEVICE, not by a
# milestone literal: if a tool/MCP gateway is installed, the row is a stale
# promise and must be gone; if none is, the row must be present and honest.
# Same probe as m8-check; extend the unit list when a gateway is named.
if [ -f /usr/lib/systemd/system/punar-mcpd.service ] ||
        [ -f /usr/lib/systemd/system/punar-toolgw.service ] ||
        [ -f /usr/lib/systemd/system/punar-gateway.service ]; then
    jq_check "a tool/MCP gateway is installed here, so mcp_servers must no longer claim it has no producer" \
        "${RUN_DIR}/m9-access.json" \
        '.not_yet_observed | any(.category == "mcp_servers") | not'
else
    jq_check "mcp_servers is still named, with a milestone and a reason (re-milestoning must not break this)" \
        "${RUN_DIR}/m9-access.json" \
        '.not_yet_observed | any(.category == "mcp_servers"
                                 and (.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                                 and (.reason | length) > 0)'
fi
# And the rule the row above is only an instance of: every honesty row this
# document carries is well-formed. This is the assertion that keeps working
# when the mcp_servers row itself finally leaves the list.
# shellcheck disable=SC2016  # $all/$produced/$pending/$cats/$observed/$root
# and $vocab are JQ variables bound inside the filter; the single shell
# expansion is deliberately spliced out of the quotes.
jq_check "every not-yet-observed row names a real category, a milestone token and a reason" \
    "${RUN_DIR}/m9-access.json" \
    '["credential_classes","directory_zones","mcp_servers","network_destinations",
      "process_classes","repositories","denied_access","sensitive_resource_access",
      "privilege_request","production_access","credential_request",
      "policy_bypass_attempt","unknown_ai_execution"] as $vocab
     | (.not_yet_observed // []) as $rows
     | ([$rows[].category] - $vocab | length == 0)
       and ($rows | all((.level == 3 or .level == 4)
                        and (.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                        and ((.reason | length) > 0)))'
jq_check "the Level-4 events include a credential_request AND the policy_bypass_attempt" \
    "${RUN_DIR}/m9-access.json" \
    '([.summary.security_events[].event_type] | index("credential_request")) != null
     and ([.summary.security_events[].event_type] | index("policy_bypass_attempt")) != null'
jq_check "no credential VALUE, token id or hash reached the ledger — only class names" \
    "${RUN_DIR}/m9-access.json" \
    '(tostring | test("punar-mock-|sha256")) | not'

# --- 11. (j) just-in-time privilege (spec 48, Plate D-012) ------------------
TZ_BEFORE="$(os_timezone)"
as_punar "${CTL}" capabilities set time.timezone Europe/Berlin \
    >/dev/null 2> "${RUN_DIR}/m9-nonroot-denied.txt"
check_eq "a non-root human mutation is refused (exit 3)" 3 "$?"
grep_row "the refusal now names the just-in-time path, not just 'be root'" \
    "${RUN_DIR}/m9-nonroot-denied.txt" "PRIVILEGE REQUEST"
as_punar "${CTL}" privilege request --capability time.timezone \
    --reason "m9 exercise: set the timezone for one minute" --duration 1 \
    >/dev/null 2> "${RUN_DIR}/m9-privilege-request.txt"
check_eq "privilege request returns exit 4 — nothing is elevated until it is answered" \
    4 "$?"
APR_PRIV="$(first_apr "${RUN_DIR}/m9-privilege-request.txt")"
as_punar "${CTL}" --json approvals get "${APR_PRIV}" > "${RUN_DIR}/m9-priv-approval.json" 2>/dev/null
jq_check "the privilege approval carries the reason VERBATIM and the grant window as its resource" \
    "${RUN_DIR}/m9-priv-approval.json" \
    '.kind == "privilege_request"
     and .approval.capability == "time.timezone"
     and (.approval.resource | test("^[0-9]+m$"))
     and (.approval.reason | test("m9 exercise"))
     and .approval.requester.type == "human"'
as_punar "${CTL}" approvals resolve "${APR_PRIV}" --decision approved >/dev/null 2>&1
check_true "the human resolves their own privilege request (D-012 draws exactly this)" "$?"
as_punar "${CTL}" --json privilege status > "${RUN_DIR}/m9-grant.json" 2>/dev/null
jq_check "a grant now exists: one capability, a window, and an id" \
    "${RUN_DIR}/m9-grant.json" \
    '(.grants | length) == 1
     and (.grants[0].grant_id | test("^gnt_"))
     and .grants[0].capability == "time.timezone"
     and (.grants[0].expires_at | length) > 0'
GNT="$(jq -r '.grants[0].grant_id' "${RUN_DIR}/m9-grant.json" 2>/dev/null)"
as_punar "${CTL}" capabilities set time.timezone Europe/Berlin \
    > "${RUN_DIR}/m9-privilege.txt" 2>&1
check_true "the SAME non-root call now succeeds, inside the window" "$?"
check_eq "the timezone really changed (not just the descriptor)" "Europe/Berlin" \
    "$(os_timezone)"
# The grant IS a section 39 Temporary Approved Exception, so it is cited in
# policy_ids. audit-event.json is closed at twelve fields and has no
# `details` object; M9 does not extend the schema to carry a grant id
# (milestone-9.md correction to §7).
jq -c "select(.action == \"capabilities.set\" and .resource == \"time.timezone\"
              and .decision == \"allow\")" "${AUDIT_LOG}" \
    > "${RUN_DIR}/m9-audit-grant.json" 2>/dev/null
jq_slurp_check "the grant-authorized mutation cites the grant id in policy_ids" \
    "${RUN_DIR}/m9-audit-grant.json" \
    "any(.[]; .policy_ids | index(\"${GNT}\"))"
# Privilege is never permanent. One minute, then gone — expiry is lazy and
# needs no timer, so the read below is what observes the lapse.
sleep 65
as_punar "${CTL}" --json privilege status > "${RUN_DIR}/m9-grant-expired.json" 2>/dev/null
jq_check "the grant is gone once its window closed" \
    "${RUN_DIR}/m9-grant-expired.json" '(.grants | length) == 0'
check_eq "the lapse is audited exactly once" 1 \
    "$(audit_count ".action == \"privilege.expire\" and .resource == \"${GNT}\"")"
if [ ! -e "${GRANTS_DIR}/${GNT}.json" ]; then
    note "ok   the expired grant was unlinked from disk, not merely flagged"
else
    note "FAIL ${GRANTS_DIR}/${GNT}.json still exists after the window closed"
    FAILED=1
fi
as_punar "${CTL}" capabilities set time.timezone UTC \
    >/dev/null 2> "${RUN_DIR}/m9-after-expiry.txt"
check_eq "the same non-root call is refused again once the window closed (exit 3)" 3 "$?"
# A reason is required: it travels verbatim into the audit record, and an
# elevation nobody can explain is not one Punar records.
as_punar "${CTL}" privilege request --capability time.timezone --reason "" \
    >/dev/null 2> "${RUN_DIR}/m9-empty-reason.txt"
check_eq "an empty --reason is a usage error before any IPC (exit 2)" 2 "$?"
# An AI agent gets per-request approvals, never a time window (spec 48, 60).
in_scope "${CTL}" privilege request --capability time.timezone \
    --reason "agent asks for a window" --duration 15 \
    >/dev/null 2> "${RUN_DIR}/m9-agent-privilege.txt"
check_eq "an AI agent asking for a privilege WINDOW is denied outright (exit 3)" 3 "$?"
check_eq "the refusal is audited as agent_privilege_refused" 1 \
    "$(audit_count ".action == \"privilege.request\" and .agent_session_id == \"${SID}\"
        and .decision == \"deny\" and .result == \"agent_privilege_refused\"")"
# Restore the timezone as root.
"${CTL}" capabilities set time.timezone "${TZ_BEFORE:-UTC}" >/dev/null 2>&1
check_eq "the timezone was restored as root" "${TZ_BEFORE:-UTC}" \
    "$(os_timezone)"

# --- 12. negative probes (spec 74.4) ----------------------------------------
for method in credential.show credential.export credential.list secrets.dump \
              system.exec shell.run; do
    probe_out="$(as_punar "${CTL}" debug rpc "${method}" --socket secrets 2>&1)"
    rc=$?
    if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi "${method}"; then
        note "ok   debug rpc ${method} rejected on the broker socket (closed method table, exit ${rc})"
    else
        note "FAIL debug rpc ${method} (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
        FAILED=1
    fi
done
for method in approvals.approve approvals.deny approvals.delete privilege.grant \
              privilege.extend; do
    probe_out="$(as_punar "${CTL}" debug rpc "${method}" 2>&1)"
    rc=$?
    if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi "${method}"; then
        note "ok   debug rpc ${method} rejected on punard (there is no path to mint privilege, exit ${rc})"
    else
        note "FAIL debug rpc ${method} (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
        FAILED=1
    fi
done
# approvals.create as an unprivileged peer. `debug rpc` sends NO params, so
# what this probe actually proves is the weaker of the two facts: the call is
# refused, at params parsing, before it could mint anything. It must never
# succeed, and the report says which refusal it saw rather than implying the
# authz rule was reached — the strong fact (root-only, and never from an
# agent-shaped peer) is pinned in crates/punard/tests/approvals.rs.
probe_out="$(as_punar "${CTL}" debug rpc approvals.create 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ]; then
    note "ok   approvals.create from the non-root console user mints nothing (exit ${rc}; a paramless probe is refused at params parsing, before authz)"
else
    note "FAIL approvals.create succeeded for a non-root peer"
    FAILED=1
fi
# The third method that refuses an agent-shaped peer — approvals.create,
# which is refused *as an agent* rather than merely told to become root
# (contract section 14.5, result `agent_create_refused`) — cannot be probed
# from here, and that is stated rather than quietly skipped: `debug rpc` sends
# NO params, so a well-formed approvals.create never gets past params parsing
# to reach the rule, and this image ships no python/socat/nc to hand-craft the
# frame (the same tooling limit the §5.1 deviation note records). It is proven
# over the real wire in crates/punard/tests/approvals.rs
# (`an_ai_agent_cannot_author_an_approval_even_as_root`). What IS proven here,
# on a real kernel cgroup, is the same shared rule through the one method the
# CLI can reach it by: the agent privilege refusal in group 11.
note "info approvals.create's agent refusal is proven in crates/punard/tests/approvals.rs, not here: debug rpc sends no params and this image has no tool to hand-craft the frame. The shared rule is exercised in-VM through privilege.request (group 11)."
if ! runuser -u nobody -- "${CTL}" secrets list >/dev/null 2>&1; then
    note "ok   the broker socket refuses a peer outside group punar (0660 root:punar admission)"
else
    note "FAIL a peer outside group punar reached the broker socket"
    FAILED=1
fi
# The flag that must never exist: /proc/<pid>/cmdline is world-readable, so a
# secret on argv is a secret published to every local user.
as_punar "${CTL}" secrets validate --token x >/dev/null 2>&1
check_eq "there is no --token flag and there never will be (exit 2, usage)" 2 "$?"
as_punar "${CTL}" secrets get github --project atlas >/dev/null 2>&1
check_eq "there is no --project flag on secrets get either (no unforgeable mediation point)" \
    2 "$?"

# --- 6b. (e) the verdict on the approval nobody answered --------------------
elapsed=$(( $(date -u +%s) - EXPIRY_START ))
if [ "${elapsed}" -lt 305 ]; then
    remaining=$((305 - elapsed))
    note "info waiting the remaining ${remaining}s of the shipped 300 s approval TTL (the other groups ran inside the window; a bounded wait for a KNOWN ttl is a wait, not a poll)"
    sleep "${remaining}"
fi
as_punar "${CTL}" --json approvals get "${APR2}" > "${RUN_DIR}/m9-expired.json" 2>/dev/null
jq_check "an unanswered approval expires, and NOTHING was executed" \
    "${RUN_DIR}/m9-expired.json" \
    '.approval.status == "expired" and .execution == null and .resolved_at == null'
as_punar "${CTL}" --json capabilities > "${RUN_DIR}/m9-firewall-expired.json" 2>/dev/null
jq_check "the capability the expired approval asked for is unchanged" \
    "${RUN_DIR}/m9-firewall-expired.json" \
    '[.capabilities[] | select(.capability == "security.firewall"
        and .current_state == "enabled")] | length == 1'
check_eq "the lapse is audited exactly once, however many times the record is read" 1 \
    "$(audit_count ".action == \"approval.expire\" and .resource == \"${APR2}\"")"
as_punar "${CTL}" approvals resolve "${APR2}" --decision approved \
    >/dev/null 2> "${RUN_DIR}/m9-resolve-expired.txt"
resolve_expired_rc=$?
if [ "${resolve_expired_rc}" -ne 0 ] \
        && grep -qi 'expire' "${RUN_DIR}/m9-resolve-expired.txt"; then
    note "ok   answering a lapsed approval says EXPIRED, not 'conflict' (exit ${resolve_expired_rc}): 'you were too late' and 'someone already answered' are different facts"
else
    note "FAIL resolving an expired approval (exit ${resolve_expired_rc}): $(head -c 200 "${RUN_DIR}/m9-resolve-expired.txt" 2>/dev/null)"
    FAILED=1
fi

# --- teardown ----------------------------------------------------------------
as_punar systemctl --user stop "${SCOPE}" > "${RUN_DIR}/m9-stop.txt" 2>&1
waited=0
while [ "${waited}" -lt 60 ] && kill -0 "${LAUNCH_PID}" 2>/dev/null; do
    sleep 2
    waited=$((waited + 2))
done
if kill -0 "${LAUNCH_PID}" 2>/dev/null; then
    note "FAIL punar-env did not return ${waited}s after the scope stopped; killing it"
    kill -TERM "${LAUNCH_PID}" 2>/dev/null
    FAILED=1
else
    wait "${LAUNCH_PID}"
    note "ok   the managed session ended cleanly (exit $?)"
fi
rm -f "${ATLAS}/.punar-agent-fifo"
# Leave the device in its pre-M9 state: the firewall enabled, the timezone
# restored above, and no live grant.
"${CTL}" capabilities set security.firewall enabled >/dev/null 2>&1

# --- 13. stated gaps (spec 1.22) --------------------------------------------
note "info the cgroup is EVIDENCE, not a sandbox. An agent that launches a helper outside its own scope escapes attribution and would present to punard as the console user. M9 does not close that — it records the resolver's uid, pid and cgroup in resolved_by and in the audit trail so an escape is visible after the fact. The real fixes are a per-agent-session uid (a sandbox) and a logind seat presence check, both named as deferred in milestone-9.md §13."
note "info there is NO PAM or polkit re-authentication at resolve time in M9. 'Human-only' here means 'the peer's cgroup shows no agent scope AND the peer is root or the routed user' — kernel-attested, but not proof that a person pressed the key. No surface in this milestone claims otherwise."
note "info the credential provider is a MOCK. There is no upstream credential authority, the CI VM has no network, and every issued value carries an identifiable punar-mock-<class>- prefix precisely so a leak would be greppable. Every surface that prints one says SIMULATED."
note "info cross-user resolve refusal (user B may not answer user A's approval) is NOT proven in-VM: this image has one interactive user and no tool to forge peer credentials, by design. It is proven by punard's host integration tests (crates/punard/tests/approvals.rs), the same honest-gap pattern m7-check and m8-check use."
note "info the expiry group used the SHIPPED 300 s approval TTL rather than the plan's --ttl 15, because capabilities.set carries no ttl parameter by decision (milestone-9.md §5.1 fixes its request shape) and this image has no tool to hand-craft a socket frame. The clock was started before the credential and privilege groups so the wait overlaps real work."
note "info the screenshot proves the D-003 overlay rendered a card, not that every glyph is correct. WHICH card was on screen is asserted separately against the shell's own IPC (approval selected), and the card's content is asserted against the socket and the summary file the overlay reads."

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M9_OK"
else
    note "PUNAR_M9_FAIL"
fi
cat "${REPORT}"
exit 0
