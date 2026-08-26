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
#   - network_destinations and mcp_servers are EMPTY and are required to be
#     named in `not_yet_observed[]` with their milestone (M12 / M11+). An
#     empty category that is not labelled is a FAIL here, because on a
#     surface it would read as "did not happen".
#   - M9 AMENDMENT: credential_classes, credential_request and
#     policy_bypass_attempt gained producers in Milestone 9 and LEFT that
#     list. credential_classes is still empty in this exercise — because
#     this session requested no credential, which is a fact rather than a
#     gap — and group 6 now asserts the ROW IS ABSENT. The honesty idiom
#     has to work in both directions, or a category with a working producer
#     would go on claiming it has none.
#   - M9 AMENDMENT: an agent's capability mutation is GATED now, not denied
#     (`firewall: approval_required` in the shipped AI authority document).
#     Nothing is applied either way — the invariant this exercise cares
#     about — but the Level-4 denied_access producer moved to the
#     privilege-window refusal, which policy can never turn into a yes.
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

# grep_re <name> <file> <ERE> — the same, for a SHAPE rather than a literal.
# Case-insensitive because fmt::verdict uppercases rendered words (M5 lesson).
grep_re() {
    if grep -qiE "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (no line matching: '$3')"
        FAILED=1
    fi
}

# audit_count <jq select body> — number of audit events matching.
audit_count() {
    jq -c "select($1)" "${AUDIT_LOG}" 2>/dev/null | wc -l | tr -d ' '
}

# --- the producer probe (docs/development/checks-conventions.md) -------------
# "Does a mediation point for this category exist?" is answered by looking at
# THIS DEVICE, never by a milestone literal in a check script. A check that
# pins `.milestone == "M12"` dies the day M12 ships — that is five of the six
# recorded regressions of this class. A check that looks for punar-netd keeps
# telling the truth in both worlds, and flips, on its own, to demanding the
# honesty row be REMOVED the moment the producer appears.
#
# Extend the case below when a producer ships under a name this list does not
# know. The residual risk is stated honestly: a producer that ships under an
# unknown name reads here as absent, and the stale honesty row would then
# still pass. Nothing in a shell check can close that; the punar-common unit
# tests that own `not_yet_observed()` are what do.
unit_installed() { [ -f "/usr/lib/systemd/system/$1" ]; }

producer_present() {
    case "$1" in
        # Sampled from the session scope cgroup by punar-agentd (source A).
        process_classes) unit_installed "${AGENTD_UNIT}" ;;
        # Derived from the punar-env workspace grant (source C).
        directory_zones|repositories) [ -x "${ENV_BIN}" ] ;;
        # M9: punar-secrets is the credential mediation point.
        credential_classes|credential_request) unit_installed punar-secrets.service ;;
        # M12: punar-netd is the network mediation point. Absent today.
        # `sensitive_resource_access` rides the same probe because M12 owns
        # the mediation that would observe a sensitive zone too. That is a
        # PROXY, and a coarse one: if M12 lands punar-netd without zone
        # mediation, this flips early and the group below fails loudly with
        # the category named, which is a one-line fix here — the opposite of
        # a stale row passing in silence.
        network_destinations|production_access|sensitive_resource_access)
            unit_installed punar-netd.service ;;
        # M11+: no tool/MCP gateway is named yet; these are the candidate
        # unit names, so the probe answers correctly the day one lands.
        mcp_servers)
            unit_installed punar-mcpd.service ||
                unit_installed punar-toolgw.service ||
                unit_installed punar-gateway.service ;;
        # punard is the authorization and approval mediation point: an
        # attributed deny, an allowed privilege window and a refused bypass
        # all come out of it. Present since M3/M9, which is why none of the
        # three may ever re-enter the pending list.
        denied_access|privilege_request|policy_bypass_attempt)
            unit_installed punard.service ;;
        # M10 is what gave this category a producer: a detection now gets its
        # own bounded ledger, and the periodic pass that finds one is this
        # timer. Before M10 the timer did not exist and the honesty row was
        # required; the day it appeared the row had to go. That flip is the
        # entire argument for probing the device instead of pinning
        # "MILESTONE 10" — this probe would have demanded the M10 edit by
        # itself, in the run that shipped it.
        unknown_ai_execution) unit_installed punar-agentd-scan.timer ;;
        *) return 1 ;;
    esac
}

# produced_json <category>... — JSON array of those with a live producer.
produced_json() {
    present=""
    for category in "$@"; do
        if producer_present "${category}"; then
            present="${present}${category}
"
        fi
    done
    printf '%s' "${present}" |
        jq -R -s -c 'split("\n") | map(select(length > 0))'
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
# M9 amendment, stated rather than quietly re-worded: an agent's capability
# mutation is no longer DENIED, it is GATED (the personal AI authority
# document says `firewall: approval_required`). Nothing is applied either
# way, which is the invariant M8 cared about; the Level-4 denied_access
# producer is now the privilege-window refusal below, which policy can never
# turn into a yes (SPEC sections 48, 60).
grep_row "punard GATED the agent's capability mutation behind an approval (M9)" \
    "${LAUNCH_OUT}" "capabilities.set gated by punard"
grep_row "punard REFUSED the agent a privilege window (the Level-4 producer)" \
    "${LAUNCH_OUT}" "privilege.request refused for an AI agent"

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
# THE LEVEL-3 HONESTY BICONDITIONAL (spec 1.22).
#
# This replaces three generations of pinned text. M8 asserted the exact
# milestone string per category; M9 had to re-milestone `mcp_servers`
# M9+ -> M11+ and delete the `credential_classes` row; M10 gave
# `unknown_ai_execution` a producer. Each time, a check that had pinned the
# placeholder failed for a change that was CORRECT. So this asserts the rule
# instead, against a producer set read off the device by `producer_present`:
#
#   labelled  <=>  no producer exists on this device       (both directions)
#   labelled   =>  the resource array is empty             (no contradiction)
#   labelled   =>  a milestone token, and a reason         (no bare deferral)
#   labelled   =>  the category is one of the shipped six  (closed vocabulary)
#
# The forward direction is the M8 rule: an empty category with no mediation
# point must SAY so, because on a surface an unlabelled empty array reads as
# "did not happen". The reverse direction is the M9 amendment, and it is what
# makes this survive fulfilment: the day punar-netd is installed, this
# assertion stops accepting the `network_destinations` row and demands it be
# deleted — which is exactly the change M10 had to make by hand for
# `unknown_ai_execution`, and exactly the change no check caught.
#
# `milestone` is a token — `M12`, `M11+` — or the sentinel `none`, which
# M10's unmanaged ledgers use for a limitation that is permanent rather than
# pending. Prose ("arrives in a later milestone") is a bare deferral and
# fails here.
PRODUCED_L3="$(produced_json credential_classes directory_zones mcp_servers \
    network_destinations process_classes repositories)"
note "info level-3 producers installed on this device: ${PRODUCED_L3}"
# shellcheck disable=SC2016  # $all/$produced/$pending/$cats/$observed/$root
# and $vocab are JQ variables bound inside the filter; the single shell
# expansion is deliberately spliced out of the quotes.
jq_check "every Level-3 category is accounted for: labelled if and only if this device has no producer for it" \
    "${RUN_DIR}/m8-access.json" \
    '["credential_classes","directory_zones","mcp_servers",
      "network_destinations","process_classes","repositories"] as $all
     | '"${PRODUCED_L3}"' as $produced
     | . as $root
     | [($root.not_yet_observed // [])[] | select(.level == 3)] as $pending
     | [$pending[].category] as $cats
     | (($cats | unique | length) == ($cats | length))
       and (($cats - $all) | length == 0)
       and ($pending | all((.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                           and ((.reason | length) > 0)))
       and ($all | all(. as $c
             | (($root.summary.resources[$c] | length) == 0) as $empty
             | (($cats | index($c)) != null) as $labelled
             | (($produced | index($c)) != null) as $has
             | ($labelled == ($has | not))
               and (($labelled | not) or $empty)))'
# The same rule again, one category at a time, so a failure names WHICH
# category and WHICH direction broke rather than just "the rule". The branch
# is chosen by the device probe, never by a milestone literal — the day a
# producer is installed, this loop starts demanding the honesty row be gone,
# which is the M9 credential_classes amendment and the M10
# unknown_ai_execution amendment made automatic instead of manual.
for category in credential_classes mcp_servers network_destinations; do
    if producer_present "${category}"; then
        jq_check "${category}: its mediation point is installed here, so an empty array is a FACT and the honesty row must be gone" \
            "${RUN_DIR}/m8-access.json" \
            '.not_yet_observed | any(.category == "'"${category}"'") | not'
    else
        jq_check "${category}: no mediation point on this device, so it is EMPTY and names an owning milestone" \
            "${RUN_DIR}/m8-access.json" \
            '((.summary.resources["'"${category}"'"] // []) | length) == 0
             and (.not_yet_observed | any(.level == 3
                    and .category == "'"${category}"'"
                    and (.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                    and (.reason | length) > 0))'
    fi
done
# Independent of any milestone: THIS session requests no credential, so its
# credential_classes array is empty as a matter of fact. Kept separate from
# the row rule above, because "empty because nothing happened" and "empty
# because nothing can observe it" are the two things spec 1.22 forbids
# rendering alike.
jq_check "credential_classes is empty because this session asked for none" \
    "${RUN_DIR}/m8-access.json" \
    '(.summary.resources.credential_classes // []) == []'
# THE LEVEL-4 REGISTER — the same biconditional, over the same device probe.
#
# The failing assertion was
#   [.not_yet_observed[] | select(.level == 4) | .category] | sort ==
#     ["production_access","sensitive_resource_access","unknown_ai_execution"]
# and it was a photograph of M8's pending set, not a rule. M10 gave
# `unknown_ai_execution` a real producer — a detection now carries its own
# bounded ledger — so the row correctly left the list and the photograph
# stopped matching. The pinned set could only ever be right for one
# milestone.
#
# What is asserted instead:
#
#   closed vocabulary   nothing outside the shipped seven, on either side
#   no duplicates       one row per category
#   disjointness        a category with an event in THIS ledger may not also
#                       claim it has no producer
#   no bare deferral    every pending row carries a milestone token + reason
#   biconditional       pending IF AND ONLY IF this device has no producer
#   monotone floor      denied_access, privilege_request and the two M9
#                       categories may never re-enter the pending set — M8
#                       and M9 produced them, and a producer that regressed
#                       is not an honesty row, it is a bug
#   non-vacuous         at least one category is actually observed here
#
# The biconditional is the half that survives fulfilment AND keeps the old
# assertion's strength. Forward: an unproduced category may not go missing —
# deleting the `production_access` row while punar-netd is still absent fails
# here, exactly as it failed under the pinned set. Reverse: a produced
# category may not go on claiming it has none — which is the M10 edit,
# demanded automatically instead of discovered by a red CI run.
PRODUCED_L4="$(produced_json denied_access sensitive_resource_access \
    privilege_request production_access credential_request \
    policy_bypass_attempt unknown_ai_execution)"
note "info level-4 producers installed on this device: ${PRODUCED_L4}"
# shellcheck disable=SC2016  # $all/$produced/$pending/$cats/$observed/$root
# and $vocab are JQ variables bound inside the filter; the single shell
# expansion is deliberately spliced out of the quotes.
jq_check "every Level-4 category is accounted for: pending if and only if this device has no producer, never both, never bare" \
    "${RUN_DIR}/m8-access.json" \
    '["denied_access","sensitive_resource_access","privilege_request",
      "production_access","credential_request","policy_bypass_attempt",
      "unknown_ai_execution"] as $all
     | '"${PRODUCED_L4}"' as $produced
     | . as $root
     | [($root.not_yet_observed // [])[] | select(.level == 4)] as $pending
     | [$pending[].category] as $cats
     | ([($root.summary.security_events // [])[].event_type] | unique) as $observed
     | (($cats | unique | length) == ($cats | length))
       and (($cats - $all) | length == 0)
       and (($observed - $all) | length == 0)
       and (($observed | length) >= 1)
       and (($cats - $observed) == $cats)
       and ($pending | all((.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                           and ((.reason | length) > 0)))
       and ($all | all(. as $c
             | (($cats | index($c)) != null) == (($produced | index($c)) == null)))
       and (($cats - ["production_access","sensitive_resource_access",
                      "unknown_ai_execution","credential_request",
                      "policy_bypass_attempt"]) | length == 0)'
# The same rule again, one category at a time, so a failure names WHICH
# category and WHICH direction broke. Only the categories whose producer
# status can move are looped; denied_access and privilege_request are
# produced by this very exercise and are covered by the monotone floor above.
for category in credential_request policy_bypass_attempt production_access \
        sensitive_resource_access unknown_ai_execution; do
    if producer_present "${category}"; then
        jq_check "${category}: its producer is installed here, so the honesty row must be gone" \
            "${RUN_DIR}/m8-access.json" \
            '[.not_yet_observed[] | select(.level == 4 and .category == "'"${category}"'")] | length == 0'
    else
        jq_check "${category}: no producer on this device, so it is NAMED with an owning milestone and a reason" \
            "${RUN_DIR}/m8-access.json" \
            '.not_yet_observed | any(.level == 4
                    and .category == "'"${category}"'"
                    and (.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                    and (.reason | length) > 0)'
    fi
done
note "info the seven Level-4 categories are accounted for by a rule, not by a snapshot of the pending set. denied_access and privilege_request are produced HERE (groups 7 and 8). credential_request and policy_bypass_attempt are produced by punar-secrets and the approval refusal, and m9-check exercises both. unknown_ai_execution is produced by a detection's own bounded ledger, and m10-check exercises it. The branch above is chosen by which mediation unit is installed on this device, never by a milestone literal, so it flips on its own the day a producer lands. Residual risk, stated plainly: a producer that ships under a unit name producer_present does not know reads here as absent, and a stale honesty row would then still pass. No shell check can close that; the punar-common unit tests that own not_yet_observed() are what do."
# The same rule, one layer up: the RENDERED surface. The jq assertions above
# prove the document is honest; this proves the honesty survives rendering.
# A row that reaches a human as a bare "Not yet observed" with no milestone
# beside it is the failure mode spec 1.22 is about, and it is a rendering bug
# the document-level checks cannot see.
as_punar "${CTL}" agents access "${SID}" > "${RUN_DIR}/m8-access.txt" 2>&1
check_true "punarctl agents access (human) as the session owner" "$?"
grep_row "the rendered ledger names the Level-3 register" \
    "${RUN_DIR}/m8-access.txt" "LEDGER · WHAT IT ACCESSED"
grep_re "the rendered ledger names at least one not-yet-observed category WITH its milestone" \
    "${RUN_DIR}/m8-access.txt" 'NOT YET OBSERVED.*M[0-9]+'
# The milestone has to sit BESIDE the words, in the value the eye lands on —
# not merely somewhere later in the reason prose, which is why this looks at
# the 60 characters that follow the phrase rather than at the whole line.
# `tr` first, so there is no case-sensitivity trap (M5 lesson) and no reliance
# on GNU sed's `I` flag.
# shellcheck disable=SC2018,SC2019  # the ASCII fold is deliberate: these lines
# carry UTF-8 separators, and `a-z`/`A-Z` folds only single-byte ASCII. The
# `[:lower:]`/`[:upper:]` classes shellcheck suggests are locale-dependent,
# and in a single-byte non-C locale they would map bytes >= 0x80 and corrupt
# the very separators the greps below step over.
nyo_tails="$(tr 'a-z' 'A-Z' < "${RUN_DIR}/m8-access.txt" 2>/dev/null |
    grep -F 'NOT YET OBSERVED' |
    sed 's/^.*NOT YET OBSERVED//' |
    cut -c1-60)"
# `printf '%s'` and not '%s\n': with no not-yet-observed rows at all — the
# world where every producer has shipped — the variable is empty and this
# must count ZERO bare rows, not one empty one.
bare_rows="$(printf '%s' "${nyo_tails}" | grep -cv 'M[0-9]')"
if [ "${bare_rows}" = "0" ]; then
    note "ok   no not-yet-observed row renders bare — every one carries its milestone beside the words"
else
    note "FAIL ${bare_rows} not-yet-observed row(s) render BARE (no milestone beside the words): $(printf '%s' "${nyo_tails}" | grep -v 'M[0-9]' | head -c 200)"
    FAILED=1
fi
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
# M9 amendment: the DENIED call is now the privilege-window refusal. The
# gated capabilities.set is asserted separately just below, because "nothing
# was applied" is still the invariant and it is now reached by a different
# route.
jq -c "select(.action == \"privilege.request\" and .agent_session_id == \"${SID}\")" \
    "${AUDIT_LOG}" > "${RUN_DIR}/m8-audit-denial.json" 2>/dev/null
jq_slurp_check "the audit trail attributes the agent's DENIED call to this session — exactly once" \
    "${RUN_DIR}/m8-audit-denial.json" \
    '(length == 1) and all(.[];
       .decision == "deny" and .result == "agent_privilege_refused"
       and .source == "ai_agent"
       and .resource == "security.firewall"
       and (.event_id | test("^evt_")))'
jq -c "select(.action == \"capabilities.set\" and .agent_session_id == \"${SID}\")" \
    "${AUDIT_LOG}" > "${RUN_DIR}/m8-audit-gated.json" 2>/dev/null
jq_slurp_check "the agent's capability mutation was GATED, not applied (M9: decision approval_required)" \
    "${RUN_DIR}/m8-audit-gated.json" \
    '(length == 1) and all(.[];
       .decision == "approval_required" and .result == "pending"
       and .source == "ai_agent" and .resource == "security.firewall")'
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
# THE REMOTE-QUERY ROW. M8 pinned the literal "MILESTONE 10" here, because
# in M8 no remote-query path existed and the surface said so with the
# milestone that would build it. M10 built it, the placeholder was correctly
# replaced by the live line, and this assertion failed for a change that was
# right. The invariant M8 was actually protecting is section 24.2's: the
# privacy surface must always state WHAT CAN LEAVE THE DEVICE, whatever the
# current truth is. So assert the row exists, is not blank, and says one of
# the three honest things — the path does not exist yet and here is the
# milestone that owns it; no organization is enrolled so there is no path at
# all; or the path exists and here is the command that shows you every use of
# it. A blank row, a missing row, or an unexplained value fails.
grep_re "privacy ledger: the REMOTE QUERY row exists and is not blank" \
    "${RUN_DIR}/m8-privacy.txt" '^REMOTE QUERY +[^[:space:]]'
grep_re "privacy ledger: the REMOTE QUERY row states what can leave the device (a milestone, or no path, or the command that reads the record)" \
    "${RUN_DIR}/m8-privacy.txt" \
    '^REMOTE QUERY +.*(MILESTONE [0-9]+|NO REMOTE-QUERY PATH|PUNARCTL PRIVACY QUERIES)'
as_punar "${CTL}" --json privacy ledger > "${RUN_DIR}/m8-privacy.json" 2>/dev/null
# Same conversion in the machine surface. `available == false` was a pin on
# M8's own answer; the durable property is that the block SELF-DESCRIBES:
# when there is no path it says WHY — the milestone that will build one, or
# the reason it could not be read — and when there is a path it names the
# command that reads its log. Either way a consumer can tell "nothing can
# leave" from "something can, here is how you audit it", which is the whole
# point of the field. The unavailable branch accepts `milestone` OR `reason`
# because both are shapes this codebase actually produces (main.rs
# privacy_ledger_json fails closed to a `reason` when the daemon does not
# answer); what it refuses is a bare `{"available": false}` — an unexplained
# false is the silent middle spec 1.22 forbids.
#
# The available branch refuses the SAME silent middle wearing the opposite
# mask: `available: true` with a null log and no reason would claim a path
# exists while showing nothing and explaining nothing. The shipped code never
# emits that — its no-answer branch always carries `read: false` and a
# `reason` — so requiring a non-null log OR a reason costs nothing today and
# closes the hole for good.
jq_check "privacy ledger --json parses, names itself a COMPOSED local document, and self-describes the remote-query path" \
    "${RUN_DIR}/m8-privacy.json" \
    '((.source // "") | test("composed"))
     and .local_only == true
     and .audit_trail_separate == true
     and (((.storage_path // "") | length) > 0)
     and ((.remote_query | type) == "object")
     and ((.remote_query.available | type) == "boolean")
     and (if .remote_query.available
          then (.remote_query | has("log"))
               and ((.remote_query.command // "") | test("privacy queries"))
               and ((.remote_query.log != null)
                    or (((.remote_query.reason // "") | length) > 0))
          else ((.remote_query.milestone // "")
                 | test("^M[0-9]+[+]?(/M[0-9]+[+]?)*$"))
               or (((.remote_query.reason // "") | length) > 0)
          end)'
# The M12 verb users will type anyway: reserved honestly, never silently.
# The milestone number is not pinned — re-milestoning is the honest move and
# must not break this — and the shipped branch is accepted too, so the day
# the verb becomes real this still passes for the right reason: it renders a
# real view instead of refusing. What stays forbidden in both worlds is the
# silent middle: exiting 0 with nothing, or refusing without naming when.
probe_out="$(as_punar "${CTL}" privacy connections 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qiE 'milestone [0-9]+'; then
    note "ok   punarctl privacy connections is reserved honestly: it refuses (exit ${rc}) and names the milestone that owns it"
elif [ "${rc}" -eq 0 ] && printf '%s' "${probe_out}" | grep -qF 'P U N A R'; then
    note "ok   punarctl privacy connections has shipped and renders a real view (exit 0, masthead present)"
else
    note "FAIL privacy connections neither refuses with a milestone nor renders a view (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
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
# The wire contract (docs/api/ipc.md section 12.2) is a two-shape field:
# {"days":14,"active":true} while the session runs, {"days":14,"expires_at":"…"}
# once it has ended. `active` is ABSENT on an ended session, not `false` —
# omitting it is how the document says "the retention clock has started".
# This row used to assert `.retention.active == false`, which the contract
# never promised and which `null == false` fails. What it MEANT to test is
# asserted instead, and more strictly than before: the window, a concrete
# date, that date being the same deadline the stored record carries, and no
# claim that an ended session is still running.
jq_check "an ended session reports the concrete date it will be deleted, not a policy sentence" \
    "${RUN_DIR}/m8-access-ended.json" \
    ".retention.days == 14 and (.retention.active // false) == false
     and (.retention.expires_at | length) > 0
     and .retention.expires_at == \"${EXPIRES_AT}\""

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
note "info group 6 does not assert WHICH categories are unobservable — it asserts the RULE, in both directions, against the mediation units actually installed on this device (the produced sets are printed above as info lines, so the report says which world it ran in). An empty array with no producer must be LABELLED, which is what keeps it from reading as 'did not happen'; an empty array WITH a producer must NOT be labelled, which is what stops a shipped milestone being quietly denied. Credential classes are the second case since M9: punar-secrets exists and this session simply asked for no credential, so its honesty row must be gone — m9-check asserts the row's contents fill in for a session that does use one. The milestone numbers themselves live in punar_common::ledger::not_yet_observed and in its unit tests; this file deliberately contains none."
note "info process classes are sampled at scan points. A child that lives and dies between two passes is missed, and process_peak is peak CONCURRENT pids, never a spawn total. Spawn-accurate history would need exactly the broad tracing SPEC 1.14 forbids."

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M8_OK"
else
    note "PUNAR_M8_FAIL"
fi
cat "${REPORT}"
exit 0
