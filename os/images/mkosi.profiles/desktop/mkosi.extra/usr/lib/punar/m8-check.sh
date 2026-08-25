#!/bin/sh
# M8 in-VM AI Access Ledger exercise (milestone-8.md §12; SPEC sections 21,
# 22, 24, 53, and 1.14/1.22). Runs AS ROOT via punar-m8-check.service; every
# unprivileged step runs as punar through the M7 runuser + session-env
# pattern, because the managed launch needs the live user manager: the agent
# runs in a `systemd-run --user --scope` unit and THAT SCOPE CGROUP is the
# ledger's first evidence source. idle-ram.sh starts this synchronously
# AFTER punar-m7-check.service and BEFORE the artifact export, so everything
# written into /run/punar here ships in the same export tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m8-report.txt
# (`PUNAR_M8_OK` / `PUNAR_M8_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh phase 10) parses the exported report and
# hard-fails on PUNAR_M8_FAIL or a truncated report.
#
# WHAT THIS EXERCISE IS ACTUALLY PROVING (spec 1.14 is the whole design):
# the ledger is DERIVED from mediation points Punar already owns. There is
# no eBPF, no fanotify, no ptrace, no LD_PRELOAD, no filesystem or network
# interception anywhere in this milestone, and this script installs none.
# The four sources are:
#   A  the session's punar-agent-<id>.scope cgroup  -> process classes
#   B  the audit stream, filtered by agent_session_id -> Level-4 references
#   C  the punar-env workspace grant                -> zones + repository
#   D  adapter/registry metadata                    -> identity
# Group 3 reads A directly from /sys/fs/cgroup and group 7 joins B by event
# id, so the two are shown to be genuinely independent evidence paths.
#
# HONESTY NOTES (spec 1.22), all of which the assertions enforce rather than
# merely assert around:
#   - network_destinations, mcp_servers and credential_classes are EMPTY and
#     are required to be named in `not_yet_observed[]` with their milestone
#     (M12 / M9+ / M9). An empty category that is not labelled is a FAIL
#     here, because on a surface it would read as "did not happen".
#   - Process counts are SAMPLED at scan points. Short-lived children are
#     missed by construction and every surface must say so. `process_peak`
#     is peak CONCURRENT pids (the kernel's pids.peak), never a spawn total.
#   - Cross-user denial (user B may not read or purge user A's ledger) is
#     NOT proven in-VM: this image has one interactive user and no tool to
#     forge peer credentials. Group 17 prints that as an info line and names
#     where it IS proven. Implying coverage would be the dishonesty spec
#     1.22 forbids.
#
# IMAGE TOOLING TRAPS carried from earlier milestones:
#   - No diffutils: compare with sha256sum, never cmp/diff (M6 lesson).
#   - `qs ipc call` clients MUST pass -p /usr/share/punar/shell (M2 lesson).
#   - fmt::verdict uppercases: every rendered-word grep is case-insensitive
#     (M5 lesson).
#   - No python, socat or nc; jq IS present and does all JSON work here.
#   - node and cargo are NOT installed. The process-class evidence is
#     therefore git + shell + agent + punar, and nothing is faked.

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m8-report.txt"
CTL=/usr/bin/punarctl
ENV_BIN=/usr/bin/punar-env
AGENTD_UNIT=punar-agentd.service
AGENTD_SOCK=/run/punar-agentd/agentd.sock
LEDGER_DIR=/var/lib/punar/agents/ledger
LEDGER_INDEX="${LEDGER_DIR}/index.json"
LEDGER_RUNTIME=/run/punar-agentd/ledger.json
CLASS_TABLE=/usr/share/punar/agents/process-classes.json
AGENTS_JSON="${RUN_DIR}/agents.json"
AUDIT_LOG=/var/log/punar/audit.jsonl
PUNAR_HOME=/home/punar
ATLAS="${PUNAR_HOME}/atlas"
FIXTURE_DIR=/usr/share/punar/fixtures/projects/atlas
LAUNCH_OUT="${RUN_DIR}/m8-launch.txt"
FAILED=0
SID=""
LAUNCH_PID=""

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

# check_ge <name> <minimum> <actual>
check_ge() {
    if [ -n "$3" ] && [ "$3" -ge "$2" ] 2>/dev/null; then
        note "ok   $1 = $3 (>= $2)"
    else
        note "FAIL $1 (wanted >= $2, got '${3:-none}')"
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
# JSONL needs slurping: `jq -e` over a multi-line stream reports only the
# LAST line's truthiness, which would let a bad line hide behind a good one.
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
        note "FAIL $1 (missing: '$3')"
        FAILED=1
    fi
}

# audit_count <jq select body> — number of audit events matching.
audit_count() {
    jq -c "select($1)" "${AUDIT_LOG}" 2>/dev/null | wc -l | tr -d ' '
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

# --- 1. preflight: daemon, ledger store, class table -------------------------
check_eq "punar-agentd.service is active" "active" \
    "$(systemctl is-active "${AGENTD_UNIT}" 2>&1)"
check_eq "ledger store mode/owner (root-only: a rewritable ledger is not evidence)" \
    "700 root root" "$(stat -c '%a %U %G' "${LEDGER_DIR}" 2>/dev/null)"
jq_check "process-class table parses and maps the classes this image can supply" \
    "${CLASS_TABLE}" \
    '.v == 1 and .classes.git == "git" and .classes.sh == "shell"
     and (.classes | to_entries | all(.value | test("^[a-z][a-z0-9_-]*$")))'
# The table must not carry anything that looks like a path or a command
# line: it is the ONLY thing standing between a raw comm and the ledger.
jq_check "the class table's values are classes, never paths or command lines" \
    "${CLASS_TABLE}" \
    '[.classes[]] | all(test("[/: ]") | not)'

# --- 2. managed launch with deterministic children (sources A + B) -----------
# Atlas: normally left by m6/m7-check. Re-created from the staged fixture if
# neither ran, so M8's verdict never depends on an earlier exercise's.
if [ ! -f "${ATLAS}/project-environment.yaml" ]; then
    mkdir -p "${ATLAS}"
    cp "${FIXTURE_DIR}/project-environment.yaml" \
       "${FIXTURE_DIR}/project-network-policy.json" "${ATLAS}/" 2>/dev/null
    chown -R punar:punar "${ATLAS}"
    note "info Atlas project re-created from the staged fixture (m6/m7-check left none)"
fi
rm -f "${ATLAS}/.punar-agent-fifo"

# WHY the systemd-run --user wrapper: punar-env creates the agent scope with
# `systemd-run --user --scope`, which MIGRATES the caller into a cgroup under
# user@<uid>.service. cgroup v2 delegation containment permits that only from
# inside the user manager's own subtree — not from this check's system.slice
# cgroup. Asking the user manager to FORK the launcher puts punar-env exactly
# where a desktop launch would run it (the M7 hard lesson).
as_punar systemd-run --user --pipe --wait --collect --quiet \
    --unit=punar-m8-launch --setenv=PUNAR_AGENT_MOCK=1 \
    --setenv=PUNAR_MOCK_AGENT_CHILDREN=1 \
    -- "${ENV_BIN}" -C "${ATLAS}" agent claude-code \
    > "${LAUNCH_OUT}" 2>&1 &
LAUNCH_PID=$!

# Bounded wait for the mock's own final line, which is printed only after
# every child in the evidence sequence has been started.
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
    note "ok   managed session launched and children spawned within ${waited}s"
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
grep_row "the evidence children were generated (dev/CI stand-in, labelled as one)" \
    "${LAUNCH_OUT}" "PUNAR_MOCK_AGENT_CHILDREN=1"
grep_row "the shell and git children blocked on the fifo (no busy loop, spec 6.3)" \
    "${LAUNCH_OUT}" "blocked on ./.punar-agent-fifo"
grep_row "punard DENIED the agent's capability mutation (the Level-4 producer)" \
    "${LAUNCH_OUT}" "capabilities.set denied by punard"

# --- 3. source A: the scope cgroup, read directly ----------------------------
as_punar "${CTL}" --json agents list > "${RUN_DIR}/m8-agents-list.json" 2>/dev/null
AGENT_PID="$(jq -r ".sessions[] | select(.session_id == \"${SID}\") | .process_id" \
    "${RUN_DIR}/m8-agents-list.json" 2>/dev/null)"
CGROUP_PATH=""
if [ -n "${AGENT_PID}" ] && [ -r "/proc/${AGENT_PID}/cgroup" ]; then
    # v2: "0::/user.slice/.../punar-agent-<id>.scope".
    CGROUP_PATH="$(sed -n 's|^0::||p' "/proc/${AGENT_PID}/cgroup" 2>/dev/null \
        | head -n 1)"
fi
SCOPE_FS=""
if [ -n "${CGROUP_PATH}" ] && [ -d "/sys/fs/cgroup${CGROUP_PATH}" ]; then
    SCOPE_FS="/sys/fs/cgroup${CGROUP_PATH}"
fi
if [ -n "${SCOPE_FS}" ]; then
    note "ok   the agent scope cgroup is readable at ${SCOPE_FS}"
    cp "${SCOPE_FS}/cgroup.procs" "${RUN_DIR}/m8-cgroup-procs.txt" 2>/dev/null
    proc_count="$(wc -l < "${RUN_DIR}/m8-cgroup-procs.txt" 2>/dev/null | tr -d ' ')"
    check_ge "pids in the session's own cgroup (agent + writer + shell + git)" 3 \
        "${proc_count}"
    : > "${RUN_DIR}/m8-cgroup-comms.txt"
    while IFS= read -r scope_pid; do
        cat "/proc/${scope_pid}/comm" >> "${RUN_DIR}/m8-cgroup-comms.txt" 2>/dev/null
    done < "${RUN_DIR}/m8-cgroup-procs.txt"
    # Assert the CLASS the table would produce, never the raw comm: if
    # /bin/sh resolves through a symlink the kernel may report `bash`, and
    # both spell class `shell` (milestone-8.md §3.2).
    if grep -qE '^(sh|bash|dash|zsh)$' "${RUN_DIR}/m8-cgroup-comms.txt" 2>/dev/null; then
        note "ok   a shell-class process is alive in the scope (comm evidence, class asserted)"
    else
        note "FAIL no shell-class comm in the scope: $(tr '\n' ' ' < "${RUN_DIR}/m8-cgroup-comms.txt" 2>/dev/null)"
        FAILED=1
    fi
    if grep -qx 'git' "${RUN_DIR}/m8-cgroup-comms.txt" 2>/dev/null; then
        note "ok   a git-class process is alive in the scope"
    else
        note "FAIL no git comm in the scope: $(tr '\n' ' ' < "${RUN_DIR}/m8-cgroup-comms.txt" 2>/dev/null)"
        FAILED=1
    fi
    peak="$(cat "${SCOPE_FS}/pids.peak" 2>/dev/null)"
    check_ge "the kernel's own pids.peak for the scope (peak CONCURRENT, not a spawn total)" \
        3 "${peak}"
else
    note "FAIL could not resolve the scope cgroup for pid '${AGENT_PID:-none}' (cgroup path '${CGROUP_PATH:-none}')"
    FAILED=1
fi

# --- 4. one sampling pass ----------------------------------------------------
as_punar "${CTL}" --json agents scan > "${RUN_DIR}/m8-scan.json" 2>/dev/null
check_true "punarctl agents scan (the ledger's event-driven update point — no timer)" "$?"

# --- 5. agents.access shape --------------------------------------------------
as_punar "${CTL}" --json agents access "${SID}" > "${RUN_DIR}/m8-access.json" 2>/dev/null
check_true "punarctl agents access --json as the session owner" "$?"
jq_check "result carries summary + detail + not_yet_observed + retention + privacy" \
    "${RUN_DIR}/m8-access.json" \
    '(keys | contains(["summary","detail","not_yet_observed","retention","privacy"]))'
jq_check "summary is schema-exact: four keys, all six resource arrays" \
    "${RUN_DIR}/m8-access.json" \
    '(.summary | keys | contains(["session_id","agent","generated_at","resources"]))
     and (.summary.resources | keys | sort ==
          ["credential_classes","directory_zones","mcp_servers",
           "network_destinations","process_classes","repositories"])
     and (.summary.resources | to_entries | all(.value | type == "array"))'
jq_check "every security-event reference is an id + a contract event_type + a timestamp" \
    "${RUN_DIR}/m8-access.json" \
    '(.summary.security_events | all(keys | sort ==
        ["event_id","event_type","timestamp"]))
     and (.summary.security_events | all(.event_id | test("^evt_")))
     and (.summary.security_events | all(.timestamp | length > 0))
     and ([.summary.security_events[].event_type]
          - ["denied_access","privilege_request","credential_request",
             "policy_bypass_attempt","production_access",
             "sensitive_resource_access","unknown_ai_execution"]
          | length == 0)'

# --- 6. Level-3 content, and the honest empties ------------------------------
jq_check "process classes include git AND shell (source A, sampled at scan points)" \
    "${RUN_DIR}/m8-access.json" \
    '(.summary.resources.process_classes | index("git")) != null
     and (.summary.resources.process_classes | index("shell")) != null'
jq_check "directory zones are the workspace ZONE only — never a path (spec 21.2)" \
    "${RUN_DIR}/m8-access.json" \
    '.summary.resources.directory_zones == ["workspace"]'
jq_check "the repository is the project NAME from the workspace grant (no git remote is read)" \
    "${RUN_DIR}/m8-access.json" \
    '.summary.resources.repositories == ["atlas"]'
jq_check "the three producerless categories are EMPTY and each is named with its milestone" \
    "${RUN_DIR}/m8-access.json" \
    '(.summary.resources.network_destinations == [])
     and (.summary.resources.mcp_servers == [])
     and (.summary.resources.credential_classes == [])
     and (.not_yet_observed | any(.level == 3 and .category == "network_destinations"
            and .milestone == "M12" and (.reason | length) > 0))
     and (.not_yet_observed | any(.level == 3 and .category == "mcp_servers"
            and .milestone == "M9+" and (.reason | length) > 0))
     and (.not_yet_observed | any(.level == 3 and .category == "credential_classes"
            and .milestone == "M9" and (.reason | length) > 0))'
# Two Level-4 categories have producers in M8 (denied_access from any
# attributed deny, privilege_request from an allowed mutation); the other
# FIVE must each be named with a milestone. Seven accounted for, none
# quietly absent (spec 1.22) — unknown_ai_execution included, because a
# detection has no registered session to attach a ledger to until M10.
jq_check "the five Level-4 categories with no producer are named too (all seven accounted for)" \
    "${RUN_DIR}/m8-access.json" \
    '[.not_yet_observed[] | select(.level == 4) | .category] | sort ==
     ["credential_request","policy_bypass_attempt","production_access",
      "sensitive_resource_access","unknown_ai_execution"]'
jq_check "every entry carries a real count, an ordered first/last seen, and a NAMED mediation point" \
    "${RUN_DIR}/m8-access.json" \
    '(.detail.entries | length) >= 1
     and (.detail.entries | all(.count >= 1))
     and (.detail.entries | all(.first_seen <= .last_seen))
     and ([.detail.entries[].evidence]
          - ["cgroup_scope","audit_event","workspace_bind","adapter_metadata"]
          | length == 0)'
jq_check "the retention window is stated, and an ACTIVE session's clock has not started" \
    "${RUN_DIR}/m8-access.json" \
    '.retention.days == 14 and .retention.active == true
     and .detail.status == "active"'
jq_check "the privacy notice carries the SPEC 21.2 never-recorded list and the purge command" \
    "${RUN_DIR}/m8-access.json" \
    '.privacy.local_only == true and .privacy.audit_trail_separate == true
     and (.privacy.purge_command | test("privacy purge"))
     and (.privacy.never_recorded | index("prompts")) != null
     and (.privacy.never_recorded | index("source code")) != null
     and (.privacy.never_recorded | index("secret values")) != null
     and (.privacy.never_recorded | index("file paths inside the workspace")) != null
     and (.privacy.never_recorded | index("individual file reads")) != null'

# --- 7. source B: the Level-4 denial join ------------------------------------
# punard's section-12.5 attribution rule reads /proc/<peer_pid>/cgroup at
# accept(); a call from inside the scope is stamped with the session id and
# source ai_agent WITHOUT the agent declaring anything. The join key below is
# the event id itself, compared across two different files.
jq -c "select(.action == \"capabilities.set\" and .agent_session_id == \"${SID}\")" \
    "${AUDIT_LOG}" > "${RUN_DIR}/m8-audit-denial.json" 2>/dev/null
jq_slurp_check "the audit trail attributes the agent's DENIED call to this session — exactly once" \
    "${RUN_DIR}/m8-audit-denial.json" \
    '(length == 1) and all(.[];
       .decision == "deny" and .result == "denied" and .source == "ai_agent"
       and .resource == "security.firewall"
       and (.event_id | test("^evt_")))'
DENIAL_EVT="$(jq -r '.event_id' "${RUN_DIR}/m8-audit-denial.json" 2>/dev/null | head -n 1)"
if [ -n "${DENIAL_EVT}" ] && [ "${DENIAL_EVT}" != "null" ]; then
    note "ok   the denial's event id was read from the audit trail: ${DENIAL_EVT}"
    jq_check "that exact event id appears in the ledger as a denied_access REFERENCE" \
        "${RUN_DIR}/m8-access.json" \
        ".summary.security_events | any(.event_id == \"${DENIAL_EVT}\"
           and .event_type == \"denied_access\")"
else
    note "FAIL no attributed capabilities.set event for ${SID} — punard's section-12.5 attribution did not fire, so the ledger's Level-4 half has no producer"
    FAILED=1
fi
# The reference carries no payload: the resource name stays in the audit log,
# which is the single source of truth and the one place to redact (spec 53).
jq_check "the ledger stores REFERENCES, never audit payloads" \
    "${RUN_DIR}/m8-access.json" \
    '[.summary.security_events[] | keys[]] | unique |
     . == ["event_id","event_type","timestamp"] or . == []'

# --- 8. privacy regression: what is NOT on disk (the important group) --------
cp "${LEDGER_DIR}/${SID}.json" "${RUN_DIR}/m8-ledger-file.json" 2>/dev/null
cp "${LEDGER_INDEX}" "${RUN_DIR}/m8-index.json" 2>/dev/null
cp "${LEDGER_RUNTIME}" "${RUN_DIR}/m8-ledger-runtime.json" 2>/dev/null
cp "${AGENTS_JSON}" "${RUN_DIR}/m8-agents-file.json" 2>/dev/null
# absent_from <label> <file> <string>... — every string must appear zero
# times. `grep -c` counts LINES, and these documents are single-line JSON,
# so the assertion is deliberately "not once", not "few times".
absent_from() {
    label="$1"
    corpus="$2"
    shift 2
    for forbidden in "$@"; do
        hits="$(grep -c -F -- "${forbidden}" "${corpus}" 2>/dev/null)"
        if [ -z "${hits}" ]; then
            note "FAIL ${label}: could not read ${corpus} to check for '${forbidden}'"
            FAILED=1
        elif [ "${hits}" = "0" ]; then
            note "ok   ${label}: '${forbidden}' appears 0 times"
        else
            note "FAIL ${label}: '${forbidden}' appears in ${corpus} — SPEC 21.2 violation"
            FAILED=1
        fi
    done
}

# Corpus A — the STORED records and the index. Nothing the mock actually did
# may be reconstructable from these bytes: not the workspace path, not the
# argv of any child, not the capability it was denied, and no field name that
# would imply such a thing was ever collected.
STORED="${RUN_DIR}/m8-privacy-stored.txt"
cat "${LEDGER_DIR}"/*.json > "${STORED}" 2>/dev/null
# A vacuous corpus would make every assertion below pass for the wrong
# reason, so the corpus itself is asserted first.
if [ -s "${STORED}" ] && grep -qF "${SID}" "${STORED}" 2>/dev/null; then
    note "ok   the privacy corpus is non-empty and contains this session's record ($(wc -c < "${STORED}" | tr -d ' ') bytes)"
else
    note "FAIL the privacy corpus is empty or does not mention ${SID} — the absence assertions below would be vacuous"
    FAILED=1
fi
absent_from "stored ledger" "${STORED}" \
    "${ATLAS}" "/home/punar" "/usr/bin/git" "/bin/sh" "/usr/lib/punar" \
    ".punar-agent-touch" ".punar-agent-fifo" \
    "hash-object" "stdin-paths" "--version" \
    "security.firewall" "capabilities.set" \
    "cmdline" "argv" "prompt" "cwd" "executable" "process_id"
# `comm` is checked separately: the raw TASK_COMM_LEN name the kernel gave
# each child (`punar-mock-agen`, `git`, `sh`) passes through the class table
# and is thrown away. The truncated agent name is the sharpest probe — it
# exists nowhere but /proc.
absent_from "stored ledger (raw comm)" "${STORED}" "punar-mock-agen"

# Corpus B — the panel's view. Same path/argv rules. The never-recorded LIST
# lives here (it is the promise, printed), so the words "prompts" and
# "source code" legitimately appear and are NOT probed; what must not appear
# is anything the session actually touched.
absent_from "runtime view" "${LEDGER_RUNTIME}" \
    "${ATLAS}" "/home/punar" "/usr/bin/git" "/bin/sh" \
    ".punar-agent-touch" ".punar-agent-fifo" \
    "hash-object" "stdin-paths" "security.firewall" "capabilities.set" \
    "cmdline" "argv" "cwd" "punar-mock-agen"
# Structural, not textual: no resource class anywhere may hold a path, a
# host:port or whitespace. This is the property the ResourceClass newtype
# enforces in types; here it is checked against the bytes on disk.
jq_check "no resource class on disk contains '/', ':' or whitespace" \
    "${RUN_DIR}/m8-ledger-file.json" \
    '([.entries[].resource_class] | all(test("[/:[:space:]\\\\]") | not))'
jq_check "the runtime view's resource arrays are equally clean" \
    "${RUN_DIR}/m8-ledger-runtime.json" \
    '[.sessions[].summary.resources | .[][]] | all(test("[/:[:space:]\\\\]") | not)'
jq_check "the stored record has no field for a path, a pid or a command line" \
    "${RUN_DIR}/m8-ledger-file.json" \
    '(keys | any(. == "cmdline" or . == "argv" or . == "prompt" or . == "comm"
                 or . == "cwd" or . == "path" or . == "executable"
                 or . == "process_id" or . == "pid")) | not'
jq_check "the world-readable summary carries no ledger identifiers at all" \
    "${RUN_DIR}/m8-agents-file.json" \
    '(tostring | test("evt_")) | not'

# --- 9. the privacy surface (spec 24.2 — the user-facing half) ---------------
as_punar "${CTL}" privacy ledger > "${RUN_DIR}/m8-privacy.txt" 2>&1
check_true "punarctl privacy ledger exit code" "$?"
grep_row "privacy ledger: masthead" "${RUN_DIR}/m8-privacy.txt" "PRIVACY"
grep_row "privacy ledger: names the local ledger as the subject" \
    "${RUN_DIR}/m8-privacy.txt" "LOCAL AI LEDGER · WHAT THIS DEVICE RECORDED"
grep_row "privacy ledger: the session has a row" "${RUN_DIR}/m8-privacy.txt" "${SID}"
grep_row "privacy ledger: states the retention window in days" \
    "${RUN_DIR}/m8-privacy.txt" "14 DAYS"
grep_row "privacy ledger: prints the never-recorded list (prompts)" \
    "${RUN_DIR}/m8-privacy.txt" "PROMPTS"
grep_row "privacy ledger: prints the never-recorded list (source code)" \
    "${RUN_DIR}/m8-privacy.txt" "SOURCE CODE"
grep_row "privacy ledger: names where the data lives" \
    "${RUN_DIR}/m8-privacy.txt" "/VAR/LIB/PUNAR/AGENTS/LEDGER"
grep_row "privacy ledger: gives the exact delete command" \
    "${RUN_DIR}/m8-privacy.txt" "PUNARCTL PRIVACY PURGE"
grep_row "privacy ledger: says the audit trail is separate and survives a purge" \
    "${RUN_DIR}/m8-privacy.txt" "AUDIT TRAIL"
grep_row "privacy ledger: states that no remote query path exists yet" \
    "${RUN_DIR}/m8-privacy.txt" "MILESTONE 10"
as_punar "${CTL}" --json privacy ledger > "${RUN_DIR}/m8-privacy.json" 2>/dev/null
jq_check "privacy ledger --json parses and names itself a COMPOSED local document" \
    "${RUN_DIR}/m8-privacy.json" \
    '(.source | test("composed"))
     and .local_only == true
     and .remote_query.available == false
     and .audit_trail_separate == true'
# The M12 verb users will type anyway: reserved honestly, never silently.
probe_out="$(as_punar "${CTL}" privacy connections 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi 'milestone 12'; then
    note "ok   punarctl privacy connections names Milestone 12 and refuses (exit ${rc})"
else
    note "FAIL privacy connections (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi

# --- 10. the counts-only fingerprint on agents.list --------------------------
as_punar "${CTL}" --json agents list > "${RUN_DIR}/m8-agents-list.json" 2>/dev/null
jq_check "agents.list carries a ledger fingerprint for the session" \
    "${RUN_DIR}/m8-agents-list.json" \
    ".sessions | any(.session_id == \"${SID}\" and (.ledger | type) == \"object\")"
jq_check "the fingerprint is COUNTS ONLY: three numbers and one timestamp, nothing else" \
    "${RUN_DIR}/m8-agents-list.json" \
    '[.sessions[] | select(.ledger != null) | .ledger] | all(
       (keys | sort == ["process_classes","resources","security_events","updated_at"])
       and (.resources | type) == "number"
       and (.process_classes | type) == "number"
       and (.security_events | type) == "number"
       and (.updated_at | type) == "string")'
jq_check "no class name and no event id leaks through the fingerprint" \
    "${RUN_DIR}/m8-agents-list.json" \
    '[.sessions[] | select(.ledger != null) | .ledger | tostring]
     | all((test("evt_") or test("shell") or test("workspace")) | not)'
jq_check "detections get NO ledger field (an unmanaged process has no session to attribute)" \
    "${RUN_DIR}/m8-agents-list.json" \
    '.detections | all(has("ledger") | not)'

# --- 11. the AI panel: the D-005 ledger register -----------------------------
check_eq "the panel's ledger view is 0640 root:punar in the ROOT-owned runtime dir" \
    "640 root punar" "$(stat -c '%a %U %G' "${LEDGER_RUNTIME}" 2>/dev/null)"
jq_check "the runtime view names this session and is literally the agents.access rows" \
    "${RUN_DIR}/m8-ledger-runtime.json" \
    ".v == 1 and (.sessions | any(.summary.session_id == \"${SID}\"
       and (.summary.resources.process_classes | index(\"git\")) != null
       and (.not_yet_observed | length) >= 3
       and (.privacy.local_only == true)))"
as_punar qs -p /usr/share/punar/shell ipc call aipanel open >/dev/null 2>&1
check_true "qs ipc call aipanel open (the SUPER+A surface)" "$?"
sleep 2
panel_state="$(as_punar qs -p /usr/share/punar/shell ipc call aipanel state 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "aipanel state after open" "open" "${panel_state}"
# The bounded settle is the panel's event-driven FileView pickup, not a poll.
sleep 10
if [ -n "${WL_DISPLAY}" ] && as_punar grim "${RUN_DIR}/punar-m8.png" 2>/dev/null \
        && [ -s "${RUN_DIR}/punar-m8.png" ]; then
    note "ok   grim captured punar-m8.png ($(stat -c '%s' "${RUN_DIR}/punar-m8.png") bytes) — human evidence of the D-005 ledger register"
else
    note "FAIL grim capture punar-m8.png (wayland=${WL_DISPLAY:-none})"
    FAILED=1
fi
as_punar qs -p /usr/share/punar/shell ipc call aipanel close >/dev/null 2>&1
panel_state="$(as_punar qs -p /usr/share/punar/shell ipc call aipanel state 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "aipanel state after close" "closed" "${panel_state}"
note "info the screenshot proves the pane rendered, not that every row is correct — the row content is asserted against the socket and the runtime view above, which are the same bytes the pane reads"

# --- 12. end of session: the retention clock starts at ended_at --------------
as_punar systemctl --user stop "${SCOPE}" > "${RUN_DIR}/m8-stop.txt" 2>&1
check_true "systemctl --user stop of the agent scope" "$?"
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
    check_eq "punar-env exit code after the session ended (passthrough)" 0 "$?"
fi
rm -f "${ATLAS}/.punar-agent-fifo"
# agents.end -> compaction is synchronous inside the daemon, but punar-env's
# own exit and the daemon's final write are two processes; a short settle
# keeps the copy below from racing the rename.
sleep 2
cp "${LEDGER_DIR}/${SID}.json" "${RUN_DIR}/m8-ledger-file.json" 2>/dev/null
jq_check "the ended record is compacted: status ended, ended_at and a retention deadline" \
    "${RUN_DIR}/m8-ledger-file.json" \
    '.status == "ended" and (.ended_at | length) > 0
     and (.retention_expires_at | length) > 0'
ENDED_AT="$(jq -r '.ended_at' "${RUN_DIR}/m8-ledger-file.json" 2>/dev/null)"
EXPIRES_AT="$(jq -r '.retention_expires_at' "${RUN_DIR}/m8-ledger-file.json" 2>/dev/null)"
if [ -n "${ENDED_AT}" ] && [ "${ENDED_AT}" != "null" ]; then
    want_day="$(date -u -d "${ENDED_AT} + 14 days" +%Y-%m-%d 2>/dev/null)"
    got_day="$(printf '%s' "${EXPIRES_AT}" | cut -c1-10)"
    check_eq "the deletion deadline is exactly 14 days after the session ENDED (not after it started)" \
        "${want_day}" "${got_day}"
else
    note "FAIL no ended_at on the compacted record; retention deadline not checkable"
    FAILED=1
fi
as_punar "${CTL}" --json agents access "${SID}" > "${RUN_DIR}/m8-access-ended.json" 2>/dev/null
jq_check "an ended session reports the concrete date it will be deleted, not a policy sentence" \
    "${RUN_DIR}/m8-access-ended.json" \
    '.retention.days == 14 and .retention.active == false
     and (.retention.expires_at | length) > 0'

# --- 13. purge as the owner (spec 24.2: unconditional, for your own data) ----
as_punar "${CTL}" privacy purge --session "${SID}" --yes \
    > "${RUN_DIR}/m8-purge.txt" 2>&1
check_true "punarctl privacy purge --session as the OWNER (no policy may withhold this in M8)" "$?"
grep_row "the purge render confirms what was deleted" "${RUN_DIR}/m8-purge.txt" "PURGED"
grep_row "the purge render states the audit-trail boundary in one sentence" \
    "${RUN_DIR}/m8-purge.txt" "AUDIT TRAIL"
if [ -e "${LEDGER_DIR}/${SID}.json" ]; then
    note "FAIL ${LEDGER_DIR}/${SID}.json still exists after purge — deletion is not real"
    FAILED=1
else
    note "ok   the session's ledger file is gone from disk"
fi
cp "${LEDGER_INDEX}" "${RUN_DIR}/m8-index.json" 2>/dev/null
jq_check "the index row became a TOMBSTONE: purged_at, zero counts, no agent, no project" \
    "${RUN_DIR}/m8-index.json" \
    ".sessions | any(.session_id == \"${SID}\" and (.purged_at | length) > 0
       and .counts.resources == 0 and .counts.security_events == 0
       and (has(\"agent\") | not) and (has(\"project\") | not))"
check_eq "audit: the purge is recorded, attributed, and allowed" 1 \
    "$(audit_count ".action == \"ledger.purge\" and .agent_session_id == \"${SID}\"
        and .decision == \"allow\" and .result == \"purged\"")"
# The other half of guarantee 4: purge deletes the ledger, NOT the audit
# trail. The denial event that produced the Level-4 reference is still there.
check_eq "the audit trail was NOT touched by the purge (spec 53: it is not the user's to delete)" 1 \
    "$(audit_count ".event_id == \"${DENIAL_EVT}\"")"

# --- 14. no resurrection -----------------------------------------------------
as_punar "${CTL}" --json agents scan >/dev/null 2>&1
sleep 1
if [ -e "${LEDGER_DIR}/${SID}.json" ]; then
    note "FAIL a scan (which drains the audit tail) RECREATED the purged ledger — the tombstone does not floor re-ingestion"
    FAILED=1
else
    note "ok   a full audit drain does not resurrect what the user deleted"
fi
as_punar "${CTL}" agents access "${SID}" > "${RUN_DIR}/m8-access-purged.txt" 2>&1
grep_row "a purged session renders as PURGED — never as 'nothing recorded'" \
    "${RUN_DIR}/m8-access-purged.txt" "PURGED"
as_punar "${CTL}" --json agents access "${SID}" > "${RUN_DIR}/m8-access-purged.json" 2>/dev/null
jq_check "the purged result carries purged_at and empty resources, not an error" \
    "${RUN_DIR}/m8-access-purged.json" \
    '(.purged_at | length) > 0
     and (.summary.resources | to_entries | all(.value == []))
     and (.summary.security_events == [])'

# --- 15. retention prune -----------------------------------------------------
# The index is held in memory by the running daemon, so a synthetic row
# written underneath it would be overwritten on the next flush. The daemon is
# therefore restarted around the injection — stated here rather than hidden,
# because the restart is an artifact of the TEST, not of the design (the real
# trigger is startup / agents.scan / agents.end, all event-driven, no timer).
GHOST=agt_ffffffff0001
systemctl stop "${AGENTD_UNIT}" >/dev/null 2>&1
BACKDATED="$(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null)"
cat > "${LEDGER_DIR}/${GHOST}.json" <<EOF
{"v":1,"session_id":"${GHOST}","agent":"claude-code","user":"punar",
 "project":"atlas","classification":"managed","status":"ended",
 "started_at":"${BACKDATED}","ended_at":"${BACKDATED}",
 "updated_at":"${BACKDATED}","retention_expires_at":"${BACKDATED}",
 "process_peak":1,"truncated":false,
 "entries":[{"category":"directory_zones","resource_class":"workspace",
             "count":1,"first_seen":"${BACKDATED}","last_seen":"${BACKDATED}",
             "evidence":"workspace_bind"}],
 "security_events":[]}
EOF
chmod 0640 "${LEDGER_DIR}/${GHOST}.json"
jq --arg id "${GHOST}" --arg at "${BACKDATED}" \
   '.sessions += [{"session_id":$id,"agent":"claude-code","project":"atlas",
                   "user":"punar","classification":"managed","status":"ended",
                   "first_seen":$at,"last_seen":$at,"updated_at":$at,
                   "retention_expires_at":$at,
                   "counts":{"resources":1,"process_classes":0,
                             "security_events":0}}]' \
   "${LEDGER_INDEX}" > "${LEDGER_INDEX}.new" 2>/dev/null \
   && mv "${LEDGER_INDEX}.new" "${LEDGER_INDEX}"
chmod 0640 "${LEDGER_INDEX}"
prune_before="$(audit_count '.action == "ledger.prune" and .result == "expired"')"
systemctl start "${AGENTD_UNIT}" >/dev/null 2>&1
# Wait on the unit AND the socket: `systemctl stop` can leave a stale
# socket inode behind, so the file existing is not by itself proof the
# daemon is back.
waited=0
while [ "${waited}" -lt 30 ]; do
    if [ "$(systemctl is-active "${AGENTD_UNIT}" 2>&1)" = "active" ] \
            && [ -S "${AGENTD_SOCK}" ] \
            && as_punar "${CTL}" --json agents list >/dev/null 2>&1; then
        break
    fi
    sleep 1
    waited=$((waited + 1))
done
note "info punar-agentd was restarted once, deliberately: the ledger index is held in memory, so a synthetic backdated row written underneath a running daemon would be overwritten on its next flush. The restart is an artifact of the TEST — the real prune triggers are startup, agents.scan and agents.end, all event-driven, no timer (milestone-8.md §6.3)."
check_eq "punar-agentd is back after the injection restart" "active" \
    "$(systemctl is-active "${AGENTD_UNIT}" 2>&1)"
as_punar "${CTL}" --json agents scan >/dev/null 2>&1
sleep 1
if [ -e "${LEDGER_DIR}/${GHOST}.json" ]; then
    note "FAIL the 30-day-old ledger survived a prune pass — retention is not enforced"
    FAILED=1
else
    note "ok   a ledger past its 14-day deadline is deleted without anyone asking"
fi
cp "${LEDGER_INDEX}" "${RUN_DIR}/m8-index-pruned.json" 2>/dev/null
jq_check "the expired session's index row is gone too (no dangling rollup)" \
    "${RUN_DIR}/m8-index-pruned.json" \
    ".sessions | all(.session_id != \"${GHOST}\")"
jq_check "the user's tombstone SURVIVED the prune pass (a deletion the user made is remembered)" \
    "${RUN_DIR}/m8-index-pruned.json" \
    ".sessions | any(.session_id == \"${SID}\" and (.purged_at | length) > 0)"
prune_after="$(audit_count '.action == "ledger.prune" and .result == "expired"')"
if [ "${prune_after}" -gt "${prune_before}" ]; then
    note "ok   audit: the prune batch was recorded once, naming the count (${prune_before} -> ${prune_after})"
else
    note "FAIL audit: no ledger.prune expired event after the injection (${prune_before} -> ${prune_after})"
    FAILED=1
fi
jq -c 'select(.action == "ledger.prune")' "${AUDIT_LOG}" \
    > "${RUN_DIR}/m8-audit-prune.json" 2>/dev/null
jq_slurp_check "every prune event names a batch COUNT, never one event per deleted file (spec 6.4)" \
    "${RUN_DIR}/m8-audit-prune.json" \
    '(length >= 1)
     and all(.[]; .resource | test("^ledger:[0-9]+$"))
     and all(.[]; .source == "service" and .user_id == "punar-agentd")
     and ([.[].result] - ["expired","index_cap","orphan"] | length == 0)'

# --- 16. negative probes -----------------------------------------------------
probe_out="$(as_punar "${CTL}" agents access agt_000000000000 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi 'agt_000000000000'; then
    note "ok   agents access on an unknown id refused (exit ${rc}) without inventing a ledger"
else
    note "FAIL agents access on an unknown id (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi
# `debug rpc` sends no params at all, so this probes the outer half of the
# same guarantee: a purge request that does not NAME what to delete is
# refused. The inner half — params present but naming neither or both
# scopes — is unreachable from this CLI (clap's required group) and is
# covered by punar-common's own unit test on LedgerPurgeParams::scope.
probe_out="$(as_punar "${CTL}" debug rpc ledger.purge --socket agentd 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qiE 'invalid|scope|session_id|params'; then
    note "ok   ledger.purge that names no scope is refused (exit ${rc}) — deletion is never inferred"
else
    note "FAIL ledger.purge with no scope (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi
# There is NO export path in M8, and the refusal says so rather than just
# 'unknown method' (spec 24: the ledger stays on this device).
for method in ledger.bogus ledger.export ledger.query; do
    probe_out="$(as_punar "${CTL}" debug rpc "${method}" --socket agentd 2>&1)"
    rc=$?
    if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi "${method}"; then
        note "ok   debug rpc ${method} rejected (closed method table, exit ${rc})"
    else
        note "FAIL debug rpc ${method} (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
        FAILED=1
    fi
done
probe_out="$(as_punar "${CTL}" debug rpc ledger.export --socket agentd 2>&1)"
if printf '%s' "${probe_out}" | grep -qiE 'no export|stays on this device|upload'; then
    note "ok   the ledger.export refusal says WHY there is no such method, not just that there isn't one"
else
    note "FAIL ledger.export refusal is not honest about the absent upload path: $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi
if ! runuser -u nobody -- "${CTL}" agents access "${SID}" >/dev/null 2>&1; then
    note "ok   agents access as nobody rejected (0660 root:punar socket admission)"
else
    note "FAIL agents access as nobody succeeded — socket admission broken"
    FAILED=1
fi

# --- 17. stated gaps (spec 1.22) ---------------------------------------------
note "info cross-user denial (user B may neither read nor purge user A's ledger) is NOT proven in-VM: this image has one interactive user and no tool to forge peer credentials, by design. It is proven by punar-agentd's host integration tests with the fixed-Peer harness (tests/ledger.rs), the same honest-gap pattern m7-check used for the peer-credential denial path."
note "info network destinations, MCP servers and credential classes are absent because no mediation point observes them yet — punar-netd is M12 and punar-secrets is M9. Group 6 requires each absence to be LABELLED, which is the assertion that keeps an empty array from reading as 'did not happen'."
note "info process classes are sampled at scan points. A child that lives and dies between two passes is missed, and process_peak is peak CONCURRENT pids, never a spawn total. Spawn-accurate history would need exactly the broad tracing SPEC 1.14 forbids."

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M8_OK"
else
    note "PUNAR_M8_FAIL"
fi
cat "${REPORT}"
exit 0
