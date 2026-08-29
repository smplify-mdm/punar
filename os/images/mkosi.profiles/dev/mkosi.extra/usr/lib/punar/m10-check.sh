#!/bin/sh
# M10 in-VM exercise: periodic shadow-AI detection, the local alert, the
# unknown-agent ledger, and the pull-based administrator query
# (milestone-10.md §16; SPEC sections 23, 12.1, 21, 24, 24.1, 24.2, 51,
# 51.1, 59.4, 72, 73, 6.3, 6.4, 1.22). Runs AS ROOT via
# punar-m10-check.service; every unprivileged step runs as punar through
# the M7/M8/M9 runuser + session-env pattern. idle-ram.sh starts this
# synchronously AFTER punar-m9-check.service and BEFORE the artifact
# export, so everything written into /run/punar here ships in the same tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m10-report.txt
# (`PUNAR_M10_OK` / `PUNAR_M10_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh phase 12) parses the exported report and
# hard-fails on PUNAR_M10_FAIL or a truncated report.
#
# WHAT THIS EXERCISE IS ACTUALLY PROVING — the four laws of the milestone:
#   1. **Punar is not a server.** Group 10 shows an enqueued administrator
#      query sitting pending forever against an unenrolled device across
#      three reconcile passes, and group 13 shows the agentd socket
#      refusing the same question from a local peer. Nothing listens.
#   2. **The transport is not the authority.** Group 8 shows a query whose
#      ROLE permits it refused by the DEVICE, because the organization
#      never asked for that scope at enrollment; group 10 forces
#      `query.answer` directly and gets the same refusal with no
#      enrollment file at all (gate B, independent of gate A).
#   3. **The user learns first and can always read the record.** Group 5
#      captures the card; group 9 prints the whole query log as the
#      UNPRIVILEGED user; group 11 shows a purge that leaves that log and
#      the audit trail intact.
#   4. **Suspected, never certain, and never armed.** Group 3 proves the
#      timer fired with no manual scan; groups 4-5 prove one alert per
#      signature and the words on the card, including `nothing was
#      blocked` and the absence of the plate's `api.foo.ai`, which no code
#      produces.
#
# IMAGE TOOLING TRAPS carried from earlier milestones:
#   - No diffutils: compare with sha256sum, never cmp/diff (M6 lesson).
#   - `qs ipc call` clients MUST pass -p /usr/share/punar/shell (M2 lesson).
#   - fmt::verdict uppercases: every rendered-word grep is case-insensitive
#     (M5 lesson).
#   - No python, socat or nc; jq IS present and does all JSON work here.
#     Every jq filter below was replayed against a real document before it
#     shipped (the M9 lesson: three filters shipped broken, exiting 5
#     instead of evaluating).
#   - There is no JSON-Schema validator in the image, so the detection
#     ledger summary is checked twice: by jq here, and against
#     schemas/ai-agent/ledger-summary.json on the HOST by boot-test.
#   - A bounded `sleep` waiting for a KNOWN timer period is a wait, not a
#     poll (SPEC 6.3) — the same shape m4-check uses for the reconcile
#     timer.
#
# THE ONE ORDERING RULE THAT MATTERS: between group 2 (fixture start) and
# the end of group 3, this script issues NO `punarctl agents scan` and NO
# `punarctl agents list`. `agents.list` runs a staleness-gated pass and
# labels it `manual`, which would destroy exactly the property group 3
# exists to prove. Group 3 reads the FILE and waits.

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m10-report.txt"
CTL=/usr/bin/punarctl
AGENTS_JSON="${RUN_DIR}/agents.json"
ALERTS_FILE=/run/punar-agentd/alerts.json
AGENTD_RUN_DIR=/run/punar-agentd
DETECTIONS=/var/lib/punar/agents/detections.jsonl
DETECTIONS_INDEX=/var/lib/punar/agents/detections-index.json
QUERIES=/var/lib/punar/agents/queries.jsonl
LEDGER_DIR=/var/lib/punar/agents/ledger
AUDIT_LOG=/var/log/punar/audit.jsonl
ENROLLMENT=/var/lib/punar/enrollment.json
SUSPECTED=/usr/share/punar/agents/signatures/suspected.json
SCAN_TIMER=punar-agentd-scan.timer
SCAN_UNIT=punar-agentd-scan.service
SCAN_WANTS=/usr/lib/systemd/system/timers.target.wants/punar-agentd-scan.timer
RECONCILE_TIMER=punard-reconcile.timer
MOCK=punar-mock-smplify.service
MOCK_SOCK=/run/punar-mock-smplify/api.sock
MOCK_STATE=/var/lib/punar-mock-smplify
FIXTURE_SRC=/usr/lib/punar/foo-agent-fixture.sh
PUNAR_HOME=/home/punar
FOO="${PUNAR_HOME}/Downloads/foo-agent"
BAR="${PUNAR_HOME}/Downloads/bar-agent"
FAILED=0
FOO_PID=""
BAR_PID=""

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

# check_true <name> <status>
check_true() {
    if [ "$2" -eq 0 ]; then
        note "ok   $1"
    else
        note "FAIL $1 (status $2)"
        FAILED=1
    fi
}

# jq_check <name> <json-file> <filter that must be truthy>
jq_check() {
    if jq -e "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq filter: $3; input head: $(head -c 240 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# jq_slurp_check <name> <jsonl-file> <filter over the slurped array>
jq_slurp_check() {
    if jq -e -s "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq -s filter: $3; input head: $(head -c 240 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# grep_row <name> <file> <fixed string, case-insensitive>
grep_row() {
    if grep -qiF "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (missing: '$3'; head: $(head -c 200 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

# grep_absent <name> <file> <fixed string that must NOT appear>
grep_absent() {
    if grep -qiF "$3" "$2" 2>/dev/null; then
        note "FAIL $1 ('$3' is present and must not be)"
        FAILED=1
    else
        note "ok   $1 ('$3' absent)"
    fi
}

# audit_count <jq select body> — number of audit events matching.
audit_count() {
    jq -c "select($1)" "${AUDIT_LOG}" 2>/dev/null | wc -l | tr -d ' '
}

# --- the producer probe (docs/development/checks-conventions.md) -------------
# "Does a mediation point for this category exist?" is answered by looking at
# THIS DEVICE, never by a milestone literal in a check script. The same probe
# m8-check uses, cut down to the two categories whose producer status can
# still move for an unmanaged ledger. `repositories` and `credential_classes`
# are deliberately NOT here: for a detection they are permanent limitations
# (milestone `none`), not pending producers, so no unit will ever satisfy
# them and a probe would be the wrong question.
unit_installed() { [ -f "/usr/lib/systemd/system/$1" ]; }

ledger_producer_present() {
    [ -f "/usr/share/punar/ledger-producers/$1" ]
}

producer_present() {
    case "$1" in
        # punar-netd's privacy connection view is not itself an AI-ledger
        # producer. The row leaves only when the explicit agentd bridge ships.
        network_destinations) ledger_producer_present "$1" ;;
        # M11+: no tool/MCP gateway is named yet; these are the candidate
        # unit names, so the probe answers correctly the day one lands.
        mcp_servers)
            unit_installed punar-mcpd.service ||
                unit_installed punar-toolgw.service ||
                unit_installed punar-gateway.service ;;
        *) return 1 ;;
    esac
}

# audit_count_from <first-line> <jq select body> — matches in the audit
# trail from line N onward, so a window can be asserted rather than the
# whole boot.
audit_count_from() {
    tail -n "+$1" "${AUDIT_LOG}" 2>/dev/null | jq -c "select($2)" 2>/dev/null | wc -l | tr -d ' '
}

audit_lines() { wc -l < "${AUDIT_LOG}" 2>/dev/null | tr -d ' ' || echo 0; }

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

# shell_ipc <args...> — one call into the running shell. `-p` is the M2
# lesson: without it the client cannot find the config and answers nothing.
shell_ipc() {
    as_punar qs -p /usr/share/punar/shell ipc call "$@" 2>/dev/null
}

# mock_rpc <method> <params-json> — one raw call to the dev/CI control
# plane over its own socket. `punarctl debug rpc --params` is the client:
# the image ships no second one, and a hand-rolled here-doc would be a
# third framing implementation to get wrong.
mock_rpc() {
    "${CTL}" --socket "${MOCK_SOCK}" debug rpc "$1" --params "$2" 2>&1
}

# agentd_rpc <method> <params-json>
agentd_rpc() {
    "${CTL}" --socket agentd debug rpc "$1" --params "$2" 2>&1
}

note "M10 shadow-AI detection, alert and remote-query exercise"
note "started $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 1. preflight -----------------------------------------------------------
check_eq "punar-agentd.service is active (the data owner)" \
    "active" "$(systemctl is-active punar-agentd.service 2>&1)"
check_eq "punard.service is active (the only control-plane client)" \
    "active" "$(systemctl is-active punard.service 2>&1)"

# Vendor enablement: the SYMLINK plus `Wants=`, never is-enabled — a
# /usr/lib .wants unit reports `disabled` and always will (the M4 lesson,
# which cost a whole milestone once).
if [ -L "${SCAN_WANTS}" ]; then
    note "ok   scan timer vendor-wants symlink present ($(readlink "${SCAN_WANTS}"))"
else
    note "FAIL ${SCAN_WANTS} is not a symlink (the timer would never arm)"
    FAILED=1
fi
if systemctl show timers.target -p Wants 2>/dev/null | grep -q "${SCAN_TIMER}"; then
    note "ok   timers.target Wants=${SCAN_TIMER}"
else
    note "FAIL timers.target does not Want ${SCAN_TIMER}"
    FAILED=1
fi
check_eq "scan timer is active" \
    "active" "$(systemctl is-active "${SCAN_TIMER}" 2>&1)"
# The cadence. `systemctl show` has NO `OnUnitActiveSecUSec` property —
# systemd exposes a timer's monotonic schedule as the composite
# `TimersMonotonic` triples, and unknown property names are silently
# omitted rather than reported. Grepping for one was therefore an
# assertion that could never pass and never constrained anything: the
# 240 s claim in milestone-10.md §3.2 went unverified for a whole
# milestone while the line sat red.
#
# What §3.2 actually argues is a NUMBER and a RELATION: the pass runs
# every 240 s, and 240 s is an exact multiple of the shipping reconcile
# period, so `AccuracySec=30` lets systemd coalesce the two into one
# wakeup and M10 adds no new wakeup INSTANT at all. Assert those — the
# period in seconds from the unit systemd loaded, and the divisibility
# relation against the reconcile period READ from its own unit rather
# than assumed — so that re-tuning the reconcile period is caught (the
# coalescing claim would stop being true and somebody must say so out
# loud), and so that no assertion here depends on how systemctl chooses
# to spell a duration.
timer_show="$(systemctl show "${SCAN_TIMER}" -p TimersMonotonic -p AccuracyUSec -p NextElapseUSecMonotonic 2>/dev/null)"
printf '%s\n' "${timer_show}" > "${RUN_DIR}/m10-timer.txt"

# timer_period <unit> — the effective `OnUnitActiveSec=` of a timer unit
# in whole seconds, as systemd loaded it (drop-ins included; the last
# assignment wins). Empty when it cannot be read or is not a plain
# duration, which fails the caller loudly rather than quietly.
timer_period() {
    tp_raw="$(systemctl cat "$1" 2>/dev/null | sed -n 's/^OnUnitActiveSec=//p' | tail -n 1)"
    case "${tp_raw}" in
        *h)   tp_n="${tp_raw%h}";   tp_mul=3600 ;;
        *min) tp_n="${tp_raw%min}"; tp_mul=60 ;;
        *s)   tp_n="${tp_raw%s}";   tp_mul=1 ;;
        *)    tp_n="${tp_raw}";     tp_mul=1 ;;
    esac
    case "${tp_n}" in
        ''|*[!0-9]*) return 0 ;;
        *) printf '%s\n' "$(( tp_n * tp_mul ))" ;;
    esac
}

scan_period="$(timer_period "${SCAN_TIMER}")"
reconcile_period="$(timer_period "${RECONCILE_TIMER}")"
check_eq "scan cadence is 240 s (milestone-10.md section 3.2)" \
    "240" "${scan_period:-unreadable}"
if [ -n "${scan_period}" ] && [ -n "${reconcile_period}" ] && [ "${reconcile_period}" -gt 0 ] \
    && [ "$(( scan_period % reconcile_period ))" -eq 0 ]; then
    note "ok   ${scan_period}s is an exact multiple of the ${reconcile_period}s reconcile period, so systemd coalesces the two wakeups"
else
    note "FAIL scan cadence ${scan_period:-unreadable}s is not an exact multiple of the reconcile period ${reconcile_period:-unreadable}s — section 3.2's coalescing claim no longer holds and the unit or the claim must change"
    FAILED=1
fi
grep_row "scan accuracy is 30 s (the coalescing window), as systemd parsed it" \
    "${RUN_DIR}/m10-timer.txt" "AccuracyUSec=30s"
next_elapse="$(printf '%s\n' "${timer_show}" | sed -n 's/^NextElapseUSecMonotonic=//p')"
if [ -n "${next_elapse}" ] && [ "${next_elapse}" != "0" ] && [ "${next_elapse}" != "infinity" ]; then
    note "ok   scan timer has a next elapse in the future (${next_elapse})"
else
    note "FAIL scan timer has no scheduled next elapse (${next_elapse:-absent})"
    FAILED=1
fi

check_eq "agentd runtime dir mode/owner (root-owned: a forged alert card is a phishing primitive)" \
    "750 root punar" "$(stat -c '%a %U %G' "${AGENTD_RUN_DIR}" 2>/dev/null)"

if jq -e '.provenance[] | select(.id == "unmanaged-path-agentlike") | .require == "both"' \
    "${SUSPECTED}" >/dev/null 2>&1; then
    note "ok   M10 provenance rule present and requires BOTH halves (path AND name)"
else
    note "FAIL ${SUSPECTED} has no unmanaged-path-agentlike rule with require:\"both\""
    FAILED=1
fi

# Timer determinism, the m5 precedent: every sync below must be exactly one
# reconcile pass. The SCAN timer is deliberately NOT stopped — group 3
# exists to watch it fire, and a check that armed the thing it asserts
# proves nothing.
reconcile_was="$(systemctl is-active "${RECONCILE_TIMER}" 2>/dev/null || true)"
systemctl stop "${RECONCILE_TIMER}" >/dev/null 2>&1
note "info reconcile timer stopped for determinism (was ${reconcile_was}); the SCAN timer runs on"

# --- 2. the fixture unknown agent -------------------------------------------
# A heuristic asserted against a process that does not exist proves
# nothing, so detection gets something real and verifiably innocuous to
# find (the M7 fixture, reused verbatim).
#
# Start from a known floor: earlier exercises in this same boot install and
# start the SAME fixture, and the scan timer has been running since
# OnBootSec=240, so a foo-agent detection may already be in the registry.
# Group 3 must not be satisfiable by somebody else's row, so the leftovers
# are killed here and the ids that exist right now are recorded — the wait
# below then requires a detection id that is NOT one of them.
pkill -u punar -f "${PUNAR_HOME}/Downloads/" 2>/dev/null
sleep 1
install -d -o punar -g punar -m 0755 "${PUNAR_HOME}/Downloads" 2>/dev/null
install -o punar -g punar -m 0755 "${FIXTURE_SRC}" "${FOO}" 2>/dev/null
install -o punar -g punar -m 0755 "${FIXTURE_SRC}" "${BAR}" 2>/dev/null
if [ -x "${FOO}" ] && [ -x "${BAR}" ]; then
    note "ok   fixtures installed at ${FOO} and ${BAR} (0755, punar-owned)"
else
    note "FAIL the detection fixtures were not installed"
    FAILED=1
fi

PRE_IDS="$(jq -r '.detections[]? | select(.agent == "foo-agent") | .session_id' \
    "${AGENTS_JSON}" 2>/dev/null | tr '\n' ' ')"
note "info foo-agent detection ids already present before this exercise: ${PRE_IDS:-none}"

setsid runuser -u punar -- "${FOO}" >/dev/null 2>&1 &
FOO_PID=$!
sleep 2
if kill -0 "${FOO_PID}" 2>/dev/null; then
    note "ok   fixture running as punar (pid ${FOO_PID})"
else
    note "FAIL fixture did not stay running"
    FAILED=1
fi

agents_before="$(sha256sum "${AGENTS_JSON}" 2>/dev/null | cut -d' ' -f1)"
audit_before="$(audit_lines)"
audit_window_start=$((audit_before + 1))
note "info audit line count before the wait: ${audit_before}"

# --- 3. periodic detection fires with NO manual scan -------------------------
# Bounded wait: 240 s period + 30 s AccuracySec + 30 s slack. Reading a
# file every 10 s while waiting for a KNOWN timer is a wait, not a product
# polling loop (SPEC 6.3; the m4-check drift-demo shape).
waited=0
detected=0
DETECTION_ID=""
while [ "${waited}" -lt 300 ]; do
    for candidate in $(jq -r '.detections[]? | select(.agent == "foo-agent") | .session_id' \
        "${AGENTS_JSON}" 2>/dev/null); do
        case " ${PRE_IDS} " in
            *" ${candidate} "*) ;;   # a row from an earlier window
            *)
                DETECTION_ID="${candidate}"
                detected=1
                ;;
        esac
    done
    [ "${detected}" -eq 1 ] && break
    sleep 10
    waited=$((waited + 10))
done
if [ "${detected}" -eq 1 ]; then
    note "ok   periodic detection produced a foo-agent row after ${waited}s (no manual scan issued)"
else
    note "FAIL no foo-agent detection within 300s of the scan timer's period"
    FAILED=1
fi
cp "${AGENTS_JSON}" "${RUN_DIR}/m10-agents-file.json" 2>/dev/null

jq_check "the detection is classified unknown" "${RUN_DIR}/m10-agents-file.json" \
    '.detections[] | select(.agent == "foo-agent") | .classification == "unknown"'
jq_check "the detection carries suspected:true in the DATA (spec 23)" \
    "${RUN_DIR}/m10-agents-file.json" \
    '.detections[] | select(.agent == "foo-agent") | .suspected == true'

# The trigger travels in the audit event's `resource` as <agent>:<trigger>.
# This is the assertion the whole group exists for: a detection produced by
# the TIMER, and nothing a check script typed.
timer_detections="$(audit_count_from "${audit_window_start}" '.action == "agents.scan" and .result == "detected" and (.resource | test(":timer$"))')"
manual_scans="$(audit_count_from "${audit_window_start}" '.action == "agents.scan" and (.resource | test(":manual$"))')"
if [ "${timer_detections}" -ge 1 ]; then
    note "ok   audit has ${timer_detections} agents.scan/detected event(s) with trigger timer"
else
    note "FAIL no agents.scan detected event carrying the timer trigger"
    FAILED=1
fi
check_eq "no manual-triggered scan in the detection window (the property this group proves)" \
    "0" "${manual_scans}"

agents_after="$(sha256sum "${AGENTS_JSON}" 2>/dev/null | cut -d' ' -f1)"
if [ "${agents_before}" != "${agents_after}" ]; then
    note "ok   agents.json changed only because the detection SET changed (sha256 differs)"
else
    note "FAIL agents.json is byte-identical after a detection appeared"
    FAILED=1
fi
note "info time-to-first-sighting: ${waited}s (period 240s + accuracy 30s is the stated worst case)"

note "info detection id (new in this window): ${DETECTION_ID:-none}"

# --- 4. exactly one alert per signature --------------------------------------
# THE ANTI-NAG KEY IS THE SIGNATURE, NEVER THE DISPLAY NAME. This group
# used to count rows whose `.agent` read `foo-agent` and demand exactly
# one. That is a different assertion from the rule, and it is wrong:
# `signature_id` is `sha256(exe_realpath ‖ owner_uid)` (milestone-10.md
# section 4.2), so ONE fixture legitimately produces TWO signatures —
# the punar process that runs the script, and the ROOT `runuser` parent
# whose argv carries the same absolute path and which the M7 suspected
# glob therefore also matches. m7-check section 7 records the same fact
# in the same words ("both rows are legitimate detections"), and picks
# the punar-owned one for exactly this reason. Two owners running what
# looks like the same binary is two things seen, and one card each is
# the rule WORKING — on a multi-user machine that distinction is the
# whole point of putting the uid in the key.
#
# So assert the rule itself, in three parts, and never the row count of a
# display name:
#   1. every signature in the register has AT MOST ONE card (the anti-nag
#      law, over the whole file rather than over one agent name);
#   2. the signature this exercise deliberately created — the punar-owned
#      one — has exactly one card, so the group cannot go vacuous;
#   3. no card ever reads `cleared` beside a non-zero `live` count.
# Part 3 is the structural sweep: a card that says the process went away
# while it is running is the failure a reader of the shell would actually
# suffer, and no count of rows can see it.
ANTINAG_FOO='([.alerts[] | select(.agent == "foo-agent")] | length) >= 1
   and ([.alerts[] | select(.agent == "foo-agent" and .owner == "punar")] | length) == 1
   and ((.alerts | group_by(.signature_id) | map(length) | max) == 1)'
NO_CONTRADICTION='[.alerts[] | select(.state == "cleared" and .live > 0)] | length == 0'

if [ -f "${ALERTS_FILE}" ]; then
    note "ok   ${ALERTS_FILE} exists"
else
    note "FAIL ${ALERTS_FILE} was never written"
    FAILED=1
fi
check_eq "alerts.json mode/owner (0640 root:punar — the M9 root-owned-summary lesson)" \
    "640 root punar" "$(stat -c '%a %U %G' "${ALERTS_FILE}" 2>/dev/null)"
cp "${ALERTS_FILE}" "${RUN_DIR}/m10-alerts.json" 2>/dev/null
jq_check "alerts.json parses and carries the section 5.3 field list" \
    "${RUN_DIR}/m10-alerts.json" \
    '.v == 1 and (.alerts | type == "array") and (.alerts[0] | has("alert_id") and has("signature_id") and has("agent") and has("executable") and has("owner") and has("first_seen") and has("last_seen") and has("live") and has("detection_id") and has("signature") and has("policy_citation") and has("state"))'
jq_check "at most one alert per signature, and the fixture's own signature has exactly one card" \
    "${RUN_DIR}/m10-alerts.json" "${ANTINAG_FOO}"
jq_check "no card reads 'cleared' beside a live process count" \
    "${RUN_DIR}/m10-alerts.json" "${NO_CONTRADICTION}"
jq_check "no pid, cmdline or cgroup path anywhere in the card data" \
    "${RUN_DIR}/m10-alerts.json" \
    '(tostring | test("process_id|cmdline|argv|cgroup")) | not'

# Two more passes, now permitted — the diff is the event, so an unchanged
# pass must produce no second card and no second raise.
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
cp "${ALERTS_FILE}" "${RUN_DIR}/m10-alerts-after-scans.json" 2>/dev/null
jq_check "still at most one card per signature after two more passes (anti-nag)" \
    "${RUN_DIR}/m10-alerts-after-scans.json" "${ANTINAG_FOO}"

"${CTL}" --json debug rpc alerts.list --params '{"include_dismissed":true}' \
    > "${RUN_DIR}/m10-alerts-list.json" 2>/dev/null
jq_check "alerts.list liveness: last_seen is at or after first_seen" \
    "${RUN_DIR}/m10-alerts-list.json" \
    '[.alerts[] | select(.agent == "foo-agent")][0] | .last_seen >= .first_seen'
# The card the exercise created is LIVE, because its process is. A record
# that keeps `cleared_at` and a quiet window while `live >= 1` is the
# contradiction group 4's sweep exists for, seen from the socket.
jq_check "the card is live while the process is, with no clear and no window still standing" \
    "${RUN_DIR}/m10-alerts-list.json" \
    '[.alerts[] | select(.agent == "foo-agent" and .owner == "punar")]
     | length == 1
       and (.[0] | .state == "live" and .live >= 1
                   and (.cleared_at == null) and (.quiet_until == null))'

# ONE RAISE PER SIGNATURE — the audit half of the rule. The expected count
# is not a literal: it is READ from the register as the number of distinct
# foo-agent signatures it holds. A signature that raised twice pushes the
# raise count above the signature count and fails here, and would also
# fail the `group_by` sweep above; a fixture that stops producing the root
# `runuser` signature moves both numbers together and stays green, which
# is the difference between asserting the relation and asserting a
# snapshot (checks-conventions.md occurrence 3b).
foo_signatures="$(jq -r '[.alerts[] | select(.agent == "foo-agent") | .signature_id] | unique | length' \
    "${RUN_DIR}/m10-alerts-list.json" 2>/dev/null)"
raises="$(audit_count '.action == "agents.alert_raise" and (.resource | test("^foo-agent(:|$)"))')"
check_eq "exactly one alert_raise audit event per foo-agent signature" \
    "${foo_signatures:-unreadable}" "${raises}"
FOO_ALERT="$(jq -r '[.alerts[] | select(.agent == "foo-agent" and .owner == "punar")][0].alert_id // empty' \
    "${RUN_DIR}/m10-alerts-list.json" 2>/dev/null)"
note "info the fixture's own card: ${FOO_ALERT:-none} (${foo_signatures:-?} distinct foo-agent signatures in the register)"

# Clear it, then bring it back inside the 24 h quiet window: a
# crash-looping agent must not produce one card per restart.
kill "${FOO_PID}" 2>/dev/null
pkill -u punar -f "${FOO}" 2>/dev/null
sleep 2
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
cp "${ALERTS_FILE}" "${RUN_DIR}/m10-alerts-cleared.json" 2>/dev/null
jq_check "the card clears when the process goes, and the file says so" \
    "${RUN_DIR}/m10-alerts-cleared.json" \
    '[.alerts[] | select(.agent == "foo-agent" and .owner == "punar")][0]
     | .state == "cleared" and .live == 0'
setsid runuser -u punar -- "${FOO}" >/dev/null 2>&1 &
FOO_PID=$!
sleep 2
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
cp "${ALERTS_FILE}" "${RUN_DIR}/m10-alerts-after-restart.json" 2>/dev/null
jq_check "still at most one card per signature after clear + restart (the 24 h quiet window)" \
    "${RUN_DIR}/m10-alerts-after-restart.json" "${ANTINAG_FOO}"
# The file the SHELL reads must come back with it. A record that stays
# `cleared` while the process runs freezes alerts.json at the clear, and
# the alert region then renders a card claiming the process went away for
# the rest of the boot.
jq_check "the card the shell reads came back to live — the file is not frozen at the clear" \
    "${RUN_DIR}/m10-alerts-after-restart.json" \
    '[.alerts[] | select(.agent == "foo-agent" and .owner == "punar")][0]
     | .state == "live" and .live >= 1'
jq_check "no card reads 'cleared' beside a live process count after the restart" \
    "${RUN_DIR}/m10-alerts-after-restart.json" "${NO_CONTRADICTION}"
cleared="$(audit_count '.action == "agents.scan" and .result == "cleared" and (.resource | test("^foo-agent(:|$)"))')"
redetected="$(audit_count '.action == "agents.scan" and .result == "detected" and (.resource | test("^foo-agent(:|$)"))')"
if [ "${cleared}" -ge 1 ] && [ "${redetected}" -ge 2 ]; then
    note "ok   audit shows detected/cleared/detected transitions (${redetected} detected, ${cleared} cleared)"
else
    note "FAIL expected at least 2 detected and 1 cleared transitions (got ${redetected}/${cleared})"
    FAILED=1
fi
"${CTL}" --json debug rpc alerts.list --params '{"include_dismissed":true}' \
    > "${RUN_DIR}/m10-alerts-list-after-restart.json" 2>/dev/null
signatures_after="$(jq -r '[.alerts[] | select(.agent == "foo-agent") | .signature_id] | unique | length' \
    "${RUN_DIR}/m10-alerts-list-after-restart.json" 2>/dev/null)"
raises_after="$(audit_count '.action == "agents.alert_raise" and (.resource | test("^foo-agent(:|$)"))')"
check_eq "still one alert_raise per signature after the restart (no second card, no second toast)" \
    "${signatures_after:-unreadable}" "${raises_after}"
check_eq "the restart introduced no new signature into the register" \
    "${foo_signatures:-unreadable}" "${signatures_after:-unreadable}"
# THE ANTI-NAG PROMISE IS THE ID. A record whose state walks
# live -> cleared -> live under a NEW alert_id is a second card wearing
# the first one's clothes: the shell would animate it in as new, and the
# user would have been told twice about one thing. Assert the id itself.
FOO_ALERT_AFTER="$(jq -r '[.alerts[] | select(.agent == "foo-agent" and .owner == "punar")][0].alert_id // empty' \
    "${RUN_DIR}/m10-alerts-list-after-restart.json" 2>/dev/null)"
check_eq "the card kept its alert_id across live -> cleared -> live" \
    "${FOO_ALERT:-none}" "${FOO_ALERT_AFTER:-none}"

# --- 5. the alert renders (the money shot) -----------------------------------
"${CTL}" agents alerts --all > "${RUN_DIR}/m10-alerts-cli.txt" 2>&1
grep_row "the register says SUSPECTED" "${RUN_DIR}/m10-alerts-cli.txt" "suspected"
grep_row "the register names the executable" "${RUN_DIR}/m10-alerts-cli.txt" "${FOO}"
grep_row "the register names the matched signature" "${RUN_DIR}/m10-alerts-cli.txt" "downloads-foo-agent"
grep_row "the register cites a policy" "${RUN_DIR}/m10-alerts-cli.txt" "policy"
grep_row "the register says nothing was blocked (law 4: M10 is not armed)" \
    "${RUN_DIR}/m10-alerts-cli.txt" "nothing was blocked"
# The plate's subline reads `~/Downloads/foo-agent → api.foo.ai`. No code
# produces a network destination before M12, so the shipped surfaces drop
# it (milestone-10.md section 5.1). This assertion is the deviation's
# guard rail.
grep_absent "no invented network destination in the CLI register" \
    "${RUN_DIR}/m10-alerts-cli.txt" "api.foo.ai"
if grep -qiF "api.foo.ai" "${RUN_DIR}/m10-alerts.json" 2>/dev/null; then
    note "FAIL alerts.json carries api.foo.ai — a datum no code produces"
    FAILED=1
else
    note "ok   alerts.json carries no invented network destination"
fi

shell_ipc alerts open >/dev/null 2>&1
sleep 3
alert_state="$(shell_ipc alerts state | tr -d '\r\n' || true)"
alert_cards="$(shell_ipc alerts cards | tr -d '\r\n' || true)"
note "info shell alert region: state='${alert_state:-unknown}' cards='${alert_cards:-none}'"
if [ -n "${alert_cards}" ]; then
    note "ok   the shell drew a card for the suspected process"
else
    note "FAIL the shell drew no alert card (state ${alert_state:-unknown})"
    FAILED=1
fi
if [ -n "${WL_DISPLAY}" ] && as_punar grim "${RUN_DIR}/punar-m10.png" 2>/dev/null \
    && [ -s "${RUN_DIR}/punar-m10.png" ]; then
    note "ok   grim captured punar-m10.png ($(stat -c '%s' "${RUN_DIR}/punar-m10.png") bytes) — human evidence of the D-009 card"
else
    note "FAIL grim capture punar-m10.png (wayland=${WL_DISPLAY:-none})"
    FAILED=1
fi

# The do-not-disturb rule: the FIRST sighting of a signature breaks
# through, and nothing else does (milestone-10.md section 5.5 — the
# argument is spec 24.2, not taste: an administrator can query this exact
# fact, so quiet mode must never leave the user knowing less).
shell_ipc alerts dnd on >/dev/null 2>&1
setsid runuser -u punar -- "${BAR}" >/dev/null 2>&1 &
BAR_PID=$!
sleep 2
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
sleep 2
cp "${ALERTS_FILE}" "${RUN_DIR}/m10-alerts-dnd.json" 2>/dev/null
# Scoped to the SIGNATURE for the reason group 4 states: the fixture is
# started through `runuser`, so bar-agent is two signatures (punar and the
# root parent), and one card each is the rule working. The breakthrough
# being asserted is that a NEW signature raises at all while quiet is on.
jq_check "the second signature raised a card even under do-not-disturb (the breakthrough)" \
    "${RUN_DIR}/m10-alerts-dnd.json" \
    '([.alerts[] | select(.agent == "bar-agent" and .owner == "punar")] | length) == 1
     and ((.alerts | group_by(.signature_id) | map(length) | max) == 1)'
quiet_ids="$(shell_ipc alerts quiet | tr -d '\r\n' || true)"
cards_dnd="$(shell_ipc alerts cards | tr -d '\r\n' || true)"
note "info under DND: cards='${cards_dnd:-none}' quiet='${quiet_ids:-none}'"
# alerts.json carries no `quiet` field and must not: DND is shell-local
# state (section 5.6) and agentd cannot know it. Having the root-owned
# file trust the shell about the shell's own mode would invert the M9
# lesson. The SHELL answers instead, which is where the state lives.
if [ -n "${quiet_ids}" ]; then
    note "ok   the shell reports the breakthrough card as raised-while-quiet ('${quiet_ids}')"
else
    note "FAIL the shell reports no quiet-mode breakthrough card"
    FAILED=1
fi
if jq -e '.alerts[0] | has("quiet")' "${RUN_DIR}/m10-alerts-dnd.json" >/dev/null 2>&1; then
    note "FAIL alerts.json invented a quiet field the daemon cannot know (section 5.6)"
    FAILED=1
else
    note "ok   alerts.json carries no quiet field — DND is shell-local and the file says so by omission"
fi
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
sleep 2
cards_again="$(shell_ipc alerts cards | tr -d '\r\n' || true)"
check_eq "no second card for the same signature on the next pass" "${cards_dnd}" "${cards_again}"
shell_ipc alerts dnd off >/dev/null 2>&1
shell_ipc alerts close >/dev/null 2>&1

# Dismissal files a card; it never destroys it, and it never moves
# suppression (there is none to move).
BAR_ALERT="$(jq -r '[.alerts[] | select(.agent == "bar-agent" and .owner == "punar")][0].alert_id // empty' \
    "${RUN_DIR}/m10-alerts-dnd.json" 2>/dev/null)"
if [ -n "${BAR_ALERT}" ] && [ "${BAR_ALERT}" != "null" ]; then
    "${CTL}" agents alerts dismiss "${BAR_ALERT}" > "${RUN_DIR}/m10-dismiss.txt" 2>&1
    grep_row "dismissal says FILED TO THE RECORD, not deleted" \
        "${RUN_DIR}/m10-dismiss.txt" "not deleted"
    "${CTL}" agents alerts --all > "${RUN_DIR}/m10-alerts-cli-all.txt" 2>&1
    grep_row "the filed card is still listed by agents alerts --all" \
        "${RUN_DIR}/m10-alerts-cli-all.txt" "${BAR_ALERT}"
else
    note "FAIL no bar-agent alert id to dismiss"
    FAILED=1
fi

# The second fixture has done its job — it existed to prove that a NEW
# signature breaks through do-not-disturb — so it is retired here, before
# the query groups. That is deliberate and worth stating: group 12 asserts
# the fleet aggregate counts ONE distinct unmanaged thing, and that number
# must come from the device's own answer about a set this exercise
# controls, not from whatever happens to be running. The card it raised
# stays in the register (dismissal files, it never destroys).
kill "${BAR_PID}" 2>/dev/null
pkill -u punar -f "${BAR}" 2>/dev/null
sleep 2
"${CTL}" agents scan --trigger manual >/dev/null 2>&1

# --- 6. the unknown-agent ledger (M8's open question, closed) ----------------
if [ -n "${DETECTION_ID}" ] && [ "${DETECTION_ID}" != "null" ]; then
    "${CTL}" --json agents access "${DETECTION_ID}" > "${RUN_DIR}/m10-access.json" 2>&1
    jq -e '.summary' "${RUN_DIR}/m10-access.json" > "${RUN_DIR}/m10-detection-summary.json" 2>/dev/null
    jq_check "the detection's ledger summary is a schema-shaped document" \
        "${RUN_DIR}/m10-detection-summary.json" \
        '(.session_id | test("^agt_")) and .agent == "foo-agent" and (.generated_at | length > 0) and (.resources | type == "object") and (.security_events | type == "array")'
    jq_check "the executable's own process class is recorded" \
        "${RUN_DIR}/m10-detection-summary.json" \
        '(.resources.process_classes | length) >= 1'
    jq_check "the Level-4 unknown_ai_execution reference is attached, with an evt_ id" \
        "${RUN_DIR}/m10-detection-summary.json" \
        '[.security_events[] | select(.event_type == "unknown_ai_execution" and (.event_id | test("^evt_")))] | length >= 1'
    # The two PERMANENT limitations of an unmanaged ledger (section 6.3):
    # nothing granted this process a workspace and /proc/<pid>/cwd is never
    # read, and punar-secrets mediates managed sessions only. No milestone
    # ships these, so they are pinned deliberately — including the `none`
    # sentinel, because "permanently unobservable" and "arriving later" are
    # exactly the two things a surface must not render alike.
    jq_check "repositories and credential classes are EMPTY and named as PERMANENT limitations (milestone \"none\"), not as pending producers" \
        "${RUN_DIR}/m10-access.json" \
        '((.summary.resources.repositories | length) == 0)
         and ((.summary.resources.credential_classes | length) == 0)
         and ([.not_yet_observed[]
               | select(.level == 3 and (.category == "repositories"
                                         or .category == "credential_classes"))]
              | (length == 2)
                and all(.milestone == "none" and ((.reason | length) > 0)))'
    # The two whose producer status can still move. The branch is chosen by
    # the device, never by a milestone literal: today neither ledger producer
    # is installed, so each must be EMPTY and NAMED; the day one lands, this
    # flips on its own to demanding the stale honesty row be deleted. That
    # flip is precisely the edit M10 had to make by hand for
    # `unknown_ai_execution`, and that no check caught.
    for category in network_destinations mcp_servers; do
        if producer_present "${category}"; then
            jq_check "${category}: its ledger producer is installed here, so the honesty row must be gone" \
                "${RUN_DIR}/m10-access.json" \
                '.not_yet_observed | any(.category == "'"${category}"'") | not'
        else
            jq_check "${category}: no ledger producer on this device, so the detection ledger shows NOTHING and names an owning milestone" \
                "${RUN_DIR}/m10-access.json" \
                '((.summary.resources["'"${category}"'"] // []) | length) == 0
                 and (.not_yet_observed | any(.level == 3
                        and .category == "'"${category}"'"
                        and (.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                        and (.reason | length) > 0))'
        fi
    done
    # And the rule the rows above are instances of, over the whole Level-3
    # register: a category is named IF AND ONLY IF it is genuinely empty.
    # Forward, this is spec 1.22 — an unlabelled empty array reads on a
    # surface as "did not happen". Backward, it is the amendment that makes
    # the rule survive fulfilment — a category that HAS data may not go on
    # claiming nothing observes it. Neither direction mentions a milestone
    # number, so no producer shipping can break it.
    # shellcheck disable=SC2016  # $all/$root/$pending/$cats are JQ variables
    # bound inside the filter, not shell expansions.
    jq_check "the detection's Level-3 register: a category is named as not-yet-observed if and only if it is empty, and no row is bare" \
        "${RUN_DIR}/m10-access.json" \
        '["credential_classes","directory_zones","mcp_servers",
          "network_destinations","process_classes","repositories"] as $all
         | . as $root
         | [($root.not_yet_observed // [])[] | select(.level == 3)] as $pending
         | [$pending[].category] as $cats
         | (($cats | unique | length) == ($cats | length))
           and (($cats - $all) | length == 0)
           and ($pending | all((.milestone | test("^(none|M[0-9]+[+]?(/M[0-9]+[+]?)*)$"))
                               and ((.reason | length) > 0)))
           and ($all | all(. as $c
                 | ((($root.summary.resources[$c] // []) | length) == 0)
                   == (($cats | index($c)) != null)))'
    jq_check "retention is the detection window (7 days), not the managed 14" \
        "${RUN_DIR}/m10-access.json" '.retention.days == 7'
    jq_check "the ledger holds no cwd, no cmdline and no path under /home" \
        "${RUN_DIR}/m10-detection-summary.json" \
        '(tostring | test("cwd|cmdline|argv|/home/")) | not'
else
    note "FAIL no detection id — the ledger group could not run"
    FAILED=1
fi

if [ -f "${DETECTIONS}" ]; then
    cp "${DETECTIONS}" "${RUN_DIR}/m10-detections.jsonl" 2>/dev/null
    jq_slurp_check "detections.jsonl holds schema-exact registry records with all ten fields" \
        "${RUN_DIR}/m10-detections.jsonl" \
        '[.[] | select(.agent == "foo-agent")] | length >= 1 and all(.[] | select(.agent == "foo-agent"); has("session_id") and has("agent") and has("version") and has("process_id") and has("user") and has("project") and has("environment") and has("status") and has("classification") and has("started_at"))'
    jq_slurp_check "project is unknown — never inferred from cwd (section 6.3)" \
        "${RUN_DIR}/m10-detections.jsonl" \
        'all(.[] | select(.agent == "foo-agent"); .project == "unknown" and .classification == "unknown" and .version == "unknown")'
    check_eq "detections.jsonl mode (0600 root — a record a peer can rewrite is not evidence)" \
        "600 root root" "$(stat -c '%a %U %G' "${DETECTIONS}" 2>/dev/null)"
    cp "${DETECTIONS_INDEX}" "${RUN_DIR}/m10-detections-index.json" 2>/dev/null
    jq_check "the sibling index carries what the schema cannot hold (zone class, signature, cleared_at)" \
        "${RUN_DIR}/m10-detections-index.json" \
        '[.rows[] | select(.executable | test("foo-agent"))][0] | .zone == "downloads" and (.signature_id | test("^sig_")) and has("signature")'
else
    note "FAIL ${DETECTIONS} was never written"
    FAILED=1
fi

# --- 7. an enrolled device answers an authorized query -----------------------
mock_enabled="$(systemctl is-enabled "${MOCK}" 2>/dev/null || true)"
if [ "${mock_enabled}" = "enabled" ]; then
    note "FAIL ${MOCK} is enabled (the dev/CI mock must never be enabled)"
    FAILED=1
else
    note "ok   ${MOCK} not enabled (is-enabled: ${mock_enabled:-nonexistent})"
fi
systemctl start "${MOCK}" >/dev/null 2>&1
i=0
while [ "${i}" -lt 15 ] && [ ! -S "${MOCK_SOCK}" ]; do i=$((i + 1)); sleep 1; done
if [ -S "${MOCK_SOCK}" ]; then
    note "ok   mock control plane listening after ${i}s"
else
    note "FAIL mock socket ${MOCK_SOCK} absent after ${i}s"
    FAILED=1
fi

"${CTL}" --json enroll start acme.com > "${RUN_DIR}/m10-enroll.json" 2>&1
check_true "enroll start acme.com" "$?"
"${CTL}" --json enroll status > "${RUN_DIR}/m10-enroll-status.json" 2>&1
jq_check "enroll status reports the org's granted remote-query scopes" \
    "${RUN_DIR}/m10-enroll-status.json" \
    '(.remote_query_scopes | index("inventory")) != null and (.remote_query_scopes | index("authority")) != null'
jq_check "resource_summary was NOT granted (the scope group 8 turns on)" \
    "${RUN_DIR}/m10-enroll-status.json" \
    '(.remote_query_scopes | index("resource_summary")) == null'

DEVICE_ID="$(jq -r '.device_id // empty' "${RUN_DIR}/m10-enroll-status.json" 2>/dev/null)"
if [ -z "${DEVICE_ID}" ]; then
    DEVICE_ID="$(cat /var/lib/punar/device-id 2>/dev/null || true)"
fi
note "info device id: ${DEVICE_ID:-none}"

mock_rpc admin.ai_query \
    "{\"admin\":\"cio@acme.com\",\"device_id\":\"${DEVICE_ID}\",\"scope\":\"inventory\"}" \
    > "${RUN_DIR}/m10-query-enqueued.json" 2>&1
jq_check "the mock accepted the inventory query and holds it PENDING (nothing is pushed)" \
    "${RUN_DIR}/m10-query-enqueued.json" \
    '.status == "pending" and (.query_id | test("^qry_"))'
QUERY_OK="$(jq -r '.query_id // empty' "${RUN_DIR}/m10-query-enqueued.json" 2>/dev/null)"

# ONE reconcile pass. The device FETCHES the question on the sync hook it
# already owned; no listener, no push, no new timer.
"${CTL}" --json reconcile > "${RUN_DIR}/m10-reconcile-1.json" 2>&1
sleep 2
mock_rpc admin.query_result "{\"admin\":\"cio@acme.com\",\"query_id\":\"${QUERY_OK}\"}" \
    > "${RUN_DIR}/m10-query-answered.json" 2>&1
jq_check "the enrolled device answered within one reconcile pass" \
    "${RUN_DIR}/m10-query-answered.json" '.status == "answered"'
jq_check "the answer is an inventory projection with the managed and unknown rows" \
    "${RUN_DIR}/m10-query-answered.json" \
    '.answer.payload.counts.unknown >= 1 and (.answer.payload.detections | length) >= 1'
jq_check "the exported detection carries a zone CLASS and a sig_ identity, not a path" \
    "${RUN_DIR}/m10-query-answered.json" \
    '[.answer.payload.detections[] | select(.agent == "foo-agent")][0] | .zone == "downloads" and (.signature_id | test("^sig_")) and .suspected == true and (has("executable") | not)'
jq_check "the answer carries no executable path, pid, cmdline, username or project" \
    "${RUN_DIR}/m10-query-answered.json" \
    '(.answer.payload | tostring | test("/home/|process_id|cmdline|argv|\"user\"|\"project\"")) | not'
jq_check "the administrator's identity is labelled unverified on the way out" \
    "${RUN_DIR}/m10-query-answered.json" '.identity_verified == false'

# --- 8. an out-of-scope query is refused BY THE DEVICE and audited -----------
mock_rpc admin.ai_query \
    "{\"admin\":\"secops@acme.com\",\"device_id\":\"${DEVICE_ID}\",\"scope\":\"resource_summary\"}" \
    > "${RUN_DIR}/m10-query-oos-enqueued.json" 2>&1
QUERY_OOS="$(jq -r '.query_id // empty' "${RUN_DIR}/m10-query-oos-enqueued.json" 2>/dev/null)"
jq_check "the ROLE permits resource_summary, so the mock enqueued it" \
    "${RUN_DIR}/m10-query-oos-enqueued.json" '.status == "pending"'
"${CTL}" --json reconcile > "${RUN_DIR}/m10-reconcile-2.json" 2>&1
sleep 2
mock_rpc admin.query_result "{\"admin\":\"secops@acme.com\",\"query_id\":\"${QUERY_OOS}\"}" \
    > "${RUN_DIR}/m10-query-refused.json" 2>&1
jq_check "the DEVICE refused it: the grant, not the role, is what decides" \
    "${RUN_DIR}/m10-query-refused.json" \
    '.status == "refused" and .answer.authorization_decision == "deny" and .answer.refusal_reason == "out_of_scope"'
jq_check "the refusal names what was asked, what is permitted and who can change it (spec 73)" \
    "${RUN_DIR}/m10-query-refused.json" \
    '(.answer.refusal_message | test("resource_summary")) and (.answer.refusal_message | test("inventory")) and (.answer.refusal_message | test("Next step"))'
jq_check "a refusal carries no payload at all" "${RUN_DIR}/m10-query-refused.json" \
    '(.answer | has("payload")) | not'

cp "${QUERIES}" "${RUN_DIR}/m10-queries.jsonl" 2>/dev/null
check_eq "queries.jsonl mode (0600 root — the daemon is the only writer; the socket is the read path)" \
    "600 root root" "$(stat -c '%a %U %G' "${QUERIES}" 2>/dev/null)"
jq_slurp_check "the query log holds both decided queries with all six spec-51.1 fields" \
    "${RUN_DIR}/m10-queries.jsonl" \
    'length >= 2 and all(.[]; has("query_id") and has("answered_at") and has("requesting_admin") and has("device_id") and has("requested_scope") and has("authorization_decision") and has("result_category"))'
jq_slurp_check "the refusal is recorded as a denial with its reason" \
    "${RUN_DIR}/m10-queries.jsonl" \
    '[.[] | select(.requested_scope == "resource_summary")] | length == 1 and .[0].authorization_decision == "deny" and .[0].refusal_reason == "out_of_scope"'
jq_slurp_check "the answered payload is NOT stored — only its shape" \
    "${RUN_DIR}/m10-queries.jsonl" \
    'all(.[]; (has("payload") | not) and has("record_counts")) and ([.[] | select(.requested_scope == "inventory")][0].record_counts.detections >= 1)'
jq_slurp_check "every recorded identity is flagged unverified (there is no IdP)" \
    "${RUN_DIR}/m10-queries.jsonl" 'all(.[]; .admin_identity_verified == false)'

oos_events="$(audit_count '.action == "admin.ai_query" and .decision == "deny" and .result == "refused" and .source == "organization" and .user_id == "secops@acme.com"')"
check_eq "the refusal is in the audit trail, naming the administrator" "1" "${oos_events}"
ok_events="$(audit_count '.action == "admin.ai_query" and .decision == "allow" and .result == "answered" and .user_id == "cio@acme.com"')"
check_eq "the answer is in the audit trail too" "1" "${ok_events}"

# The role gate is INDEPENDENT of the device's: a query the role forbids
# is never enqueued, so it leaves no row on the device at all.
queries_before_role="$(wc -l < "${QUERIES}" 2>/dev/null | tr -d ' ')"
mock_rpc admin.ai_query \
    "{\"admin\":\"helpdesk@acme.com\",\"device_id\":\"${DEVICE_ID}\",\"scope\":\"security_events\"}" \
    > "${RUN_DIR}/m10-query-role-denied.txt" 2>&1
# The mock's refusal says WHY and says what did not happen. `punarctl`
# prints the daemon's message and nothing else, so the assertion is on the
# words the mock chose, not on an error code the CLI does not render.
grep_row "the mock denied the helpdesk role before enqueuing anything" \
    "${RUN_DIR}/m10-query-role-denied.txt" "was not enqueued"
"${CTL}" --json reconcile > "${RUN_DIR}/m10-reconcile-3.json" 2>&1
sleep 2
queries_after_role="$(wc -l < "${QUERIES}" 2>/dev/null | tr -d ' ')"
check_eq "a role-denied query left NO row on the device (two independent checks)" \
    "${queries_before_role}" "${queries_after_role}"

# --- 9. the user can see the query log (spec 24.2) --------------------------
runuser -u punar -- "${CTL}" privacy queries > "${RUN_DIR}/m10-privacy-queries.txt" 2>&1
check_true "privacy queries runs UNPRIVILEGED and exits 0" "$?"
grep_row "the log names the administrator who asked" \
    "${RUN_DIR}/m10-privacy-queries.txt" "cio@acme.com"
grep_row "the log names the refused query's requester too" \
    "${RUN_DIR}/m10-privacy-queries.txt" "secops@acme.com"
grep_row "the log says the identity is not verified by this device" \
    "${RUN_DIR}/m10-privacy-queries.txt" "not verified by this device"
grep_row "the log prints the never-answered list" \
    "${RUN_DIR}/m10-privacy-queries.txt" "prompts"
grep_row "the log prints the granted scopes, so the user can check answers against them" \
    "${RUN_DIR}/m10-privacy-queries.txt" "inventory"
grep_row "the log says purge does not delete it" \
    "${RUN_DIR}/m10-privacy-queries.txt" "purge"
runuser -u punar -- "${CTL}" --json privacy queries > "${RUN_DIR}/m10-privacy-queries.json" 2>&1
jq_check "--json parses and carries the same rows" "${RUN_DIR}/m10-privacy-queries.json" \
    '(.queries | length) >= 2 and .admin_identity_verified == false'

runuser -u punar -- "${CTL}" privacy ledger > "${RUN_DIR}/m10-privacy-ledger.txt" 2>&1
grep_row "the privacy ledger's REMOTE QUERY line is live" \
    "${RUN_DIR}/m10-privacy-ledger.txt" "remote query"
grep_absent "the M8 placeholder is gone, not merely hidden" \
    "${RUN_DIR}/m10-privacy-ledger.txt" "no upload path exists"

"${CTL}" agents list > "${RUN_DIR}/m10-agents-list.txt" 2>&1
grep_row "agents list states the cadence" "${RUN_DIR}/m10-agents-list.txt" "every 4 min"
grep_row "agents list states the hole sampling detection has by construction" \
    "${RUN_DIR}/m10-agents-list.txt" "inside one interval is not seen"

# --- 10. personal device: the path is inert ---------------------------------
"${CTL}" enroll stop --yes > "${RUN_DIR}/m10-unenroll.txt" 2>&1
check_true "enroll stop --yes" "$?"
if [ -f "${ENROLLMENT}" ]; then
    note "FAIL ${ENROLLMENT} still exists after unenrollment"
    FAILED=1
else
    note "ok   ${ENROLLMENT} is absent (gate B's input is gone)"
fi

mock_rpc admin.ai_query \
    "{\"admin\":\"cio@acme.com\",\"device_id\":\"${DEVICE_ID}\",\"scope\":\"inventory\"}" \
    > "${RUN_DIR}/m10-query-personal.json" 2>&1
QUERY_PERSONAL="$(jq -r '.query_id // empty' "${RUN_DIR}/m10-query-personal.json" 2>/dev/null)"
queries_before_personal="$(wc -l < "${QUERIES}" 2>/dev/null | tr -d ' ')"
"${CTL}" --json reconcile > "${RUN_DIR}/m10-reconcile-p1.json" 2>&1
"${CTL}" --json reconcile > "${RUN_DIR}/m10-reconcile-p2.json" 2>&1
"${CTL}" --json reconcile > "${RUN_DIR}/m10-reconcile-p3.json" 2>&1
sleep 2
mock_rpc admin.query_result "{\"admin\":\"cio@acme.com\",\"query_id\":\"${QUERY_PERSONAL}\"}" \
    > "${RUN_DIR}/m10-query-personal-result.json" 2>&1
jq_check "gate A: after three reconcile passes the query is STILL pending" \
    "${RUN_DIR}/m10-query-personal-result.json" '.status == "pending" and (.answer == null)'
queries_after_personal="$(wc -l < "${QUERIES}" 2>/dev/null | tr -d ' ')"
check_eq "an unenrolled device recorded nothing, because it fetched nothing" \
    "${queries_before_personal}" "${queries_after_personal}"

# Gate B, forced directly at the data owner — proving the two gates are
# independent rather than one gate mentioned twice.
agentd_rpc query.answer \
    '{"query_id":"qry_forced","requesting_admin":"secops@acme.com","organization":"acme.com","requested_scope":"inventory","received_at":"2026-08-25T14:00:00Z"}' \
    > "${RUN_DIR}/m10-gate-b.json" 2>&1
jq_check "gate B: with no enrollment file the data owner refuses a perfectly formed question" \
    "${RUN_DIR}/m10-gate-b.json" \
    '.authorization_decision == "deny" and .refusal_reason == "out_of_scope" and ((has("payload")) | not)'

runuser -u punar -- "${CTL}" privacy queries > "${RUN_DIR}/m10-privacy-personal.txt" 2>&1
personal_exit=$?
check_eq "privacy queries exits 0 on a personal device (a calm line, never an error)" \
    "0" "${personal_exit}"
grep_row "the personal-mode sentence explains the absence" \
    "${RUN_DIR}/m10-privacy-personal.txt" "personal device"

# --- 11. the purge boundary --------------------------------------------------
# Ownership is read BEFORE the purge, because the purge is precisely what removes
# the punar-owned rows. Reading the index afterwards found only root-owned
# detections and the vacuity guard below correctly refused to pass — the guard
# working, and the ordering wrong.
punar_det="$(jq -r 'first(.rows | to_entries[] | select(.value.user == "punar") | .key) // ""' \
    "${DETECTIONS_INDEX}" 2>/dev/null)"
root_det="$(jq -r 'first(.rows | to_entries[] | select(.value.user == "root") | .key) // ""' \
    "${DETECTIONS_INDEX}" 2>/dev/null)"
note "info purge scope probes (taken BEFORE the purge): punar-owned='${punar_det:-none}' root-owned='${root_det:-none}'"

# Both rows must still be READABLE before the purge, or the assertions below
# would be testing an already-empty store.
if [ -n "${punar_det}" ]; then
    "${CTL}" agents access "${punar_det}" > "${RUN_DIR}/m10-access-prepurge.txt" 2>&1
    if grep -qi 'purged' "${RUN_DIR}/m10-access-prepurge.txt" 2>/dev/null; then
        note "FAIL the punar-owned ledger already read as purged BEFORE the purge — the assertion below would be vacuous"
        FAILED=1
    else
        note "ok   the punar-owned detection ledger is present before the purge"
    fi
fi

queries_sha_before="$(sha256sum "${QUERIES}" 2>/dev/null | cut -d' ' -f1)"
ledgers_before="$(find "${LEDGER_DIR}" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
runuser -u punar -- "${CTL}" privacy purge --all --yes > "${RUN_DIR}/m10-purge.txt" 2>&1
check_true "privacy purge --all --yes runs unprivileged" "$?"
grep_row "purge states the audit boundary" "${RUN_DIR}/m10-purge.txt" "audit trail"
grep_row "purge states the query-log boundary" "${RUN_DIR}/m10-purge.txt" "remote-query log"
queries_sha_after="$(sha256sum "${QUERIES}" 2>/dev/null | cut -d' ' -f1)"
check_eq "the query log is byte-identical after a purge (sha256 — the image has no diff)" \
    "${queries_sha_before}" "${queries_sha_after}"
ledgers_after="$(find "${LEDGER_DIR}" -maxdepth 1 -type f 2>/dev/null | wc -l | tr -d ' ')"
note "info ledger records on disk: ${ledgers_before} before the purge, ${ledgers_after} after"
# The assertion is about THIS detection, not about a file count: the store
# also holds the index, and a device that had already purged would make a
# count comparison vacuous. A purged ledger must render as *purged*, never
# as "nothing recorded" (the M8 rule, which M10 inherits for detections).
#
# WHOSE ledger, and why that turned out to be the whole question. The purge
# above ran as PUNAR, and its own scope line says "every session you own
# (root: every session on this device)". The fixture is launched through
# runuser, which leaves a root-owned parent that is detected as its own
# agent — so roughly half the foo-agent detections on this device belong to
# ROOT, and DETECTION_ID above is whichever one the timer happened to produce
# first. When it landed on a root-owned row this assertion failed, and it was
# right to: a user may not purge another principal's records. That is a
# security boundary, not a defect, and it had never been asserted.
#
# So both halves are asserted now, each against a row of KNOWN ownership read
# from the index (this script runs as root and can read it):
#   1. a PUNAR-owned detection's ledger is gone after the user's own purge
#   2. a ROOT-owned detection's ledger SURVIVES that same purge
#   3. and a root purge then removes it, so completeness is not just claimed
ledger_gone() {
    "${CTL}" agents access "$1" > "$2" 2>&1
    lg_exit=$?
    [ "${lg_exit}" -ne 0 ] || grep -qi 'purged' "$2" 2>/dev/null
}

if [ -n "${punar_det}" ]; then
    if ledger_gone "${punar_det}" "${RUN_DIR}/m10-access-purged.txt"; then
        note "ok   the user's own purge removed a punar-owned detection ledger: the surface says purged, never 'nothing recorded'"
    else
        note "FAIL a punar-owned detection ledger survived the user's purge: $(head -c 200 "${RUN_DIR}/m10-access-purged.txt")"
        FAILED=1
    fi
else
    note "FAIL no punar-owned detection in the index — the purge assertion would be vacuous"
    FAILED=1
fi

if [ -n "${root_det}" ]; then
    if ledger_gone "${root_det}" "${RUN_DIR}/m10-access-root-kept.txt"; then
        note "FAIL a ROOT-owned detection ledger was removed by a purge run as punar — the scope boundary leaks"
        FAILED=1
    else
        note "ok   a root-owned detection ledger survived the user's purge (a user may not purge another principal's records)"
    fi

    # 3. and root's own purge is complete.
    "${CTL}" privacy purge --all --yes > "${RUN_DIR}/m10-purge-root.txt" 2>&1
    check_true "privacy purge --all --yes runs as root" "$?"
    if ledger_gone "${root_det}" "${RUN_DIR}/m10-access-root-purged.txt"; then
        note "ok   root's purge removed the root-owned detection ledger"
    else
        note "FAIL the root-owned ledger survived root's own purge: $(head -c 200 "${RUN_DIR}/m10-access-root-purged.txt")"
        FAILED=1
    fi
else
    note "info no root-owned detection in the index — the scope-boundary half is not applicable this run"
fi
surviving_exec="$(audit_count '.action == "agents.scan" and .result == "detected"')"
if [ "${surviving_exec}" -ge 1 ]; then
    note "ok   the audit trail still records that an unknown agent ran (purge removes the summary, never the decision record)"
else
    note "FAIL the detection events did not survive the purge"
    FAILED=1
fi
surviving_query="$(audit_count '.action == "admin.ai_query"')"
if [ "${surviving_query}" -ge 2 ]; then
    note "ok   the admin.ai_query audit events survived the purge (${surviving_query})"
else
    note "FAIL admin.ai_query events did not survive the purge (${surviving_query})"
    FAILED=1
fi

# --- 12. fleet aggregation and its boundary ---------------------------------
punar-mock-smplify --fleet > "${RUN_DIR}/m10-fleet.txt" 2>&1
#
# THIS USED TO ASSERT THE LITERAL NUMBER 1, and the number is not 1. The
# reasoning behind it was that bar-agent is killed before the query groups, so
# only foo-agent remains and the fleet counts one unmanaged thing. That is
# false, and the falsehood is the interesting part: a detection is a RECORD
# THAT AN UNKNOWN AGENT RAN, not a live process list. Killing the process does
# not — and must not — retire the evidence that it executed, any more than
# closing a door un-rings a doorbell. The device honestly reports both, plus
# the extra root-owned rows the runuser fixture creates, so the true count is
# a function of the harness rather than of the product.
#
# What is asserted instead is the property the number was standing in for, and
# it is strictly stronger than a constant:
#   - a device ANSWERED at inventory scope, so the cell is a number and not
#     the em dash (that distinction is the whole point of FleetValue)
#   - the count is at least the one unknown agent this exercise guarantees
#   - and the aggregate is INTERNALLY CONSISTENT: the "N unmanaged agent" line
#     and the Unknown row are two renders of the same aggregation and must
#     agree, which no single hard-coded number could ever check
fleet_unknown="$(grep -E '^Unknown +' "${RUN_DIR}/m10-fleet.txt" | awk '{print $2}')"
fleet_unmanaged="$(grep -Eo '^[0-9]+ unmanaged agent' "${RUN_DIR}/m10-fleet.txt" | awk '{print $1}')"
fleet_sigs="$(grep -Eo '[0-9]+ distinct signature' "${RUN_DIR}/m10-fleet.txt" | awk '{print $1}')"
note "info fleet aggregate: unknown='${fleet_unknown:-}' unmanaged='${fleet_unmanaged:-}' signatures='${fleet_sigs:-}'"

case "${fleet_unknown}" in
    ''|*[!0-9]*)
        note "FAIL the fleet Unknown cell is '${fleet_unknown}', not a number — no device answered at inventory scope, so nothing was aggregated"
        FAILED=1
        ;;
    *)
        if [ "${fleet_unknown}" -ge 1 ]; then
            note "ok   the fleet counts ${fleet_unknown} unknown agent(s), from a device that actually answered"
        else
            note "FAIL the fleet counted 0 unknown agents while this exercise ran at least one"
            FAILED=1
        fi
        ;;
esac

if [ -n "${fleet_unmanaged}" ] && [ "${fleet_unmanaged}" = "${fleet_unknown}" ]; then
    note "ok   the shadow-AI panel and the Unknown row agree (${fleet_unmanaged})"
else
    note "FAIL the shadow-AI panel says '${fleet_unmanaged}' unmanaged while the Unknown row says '${fleet_unknown}' — two renders of one aggregation disagree"
    FAILED=1
fi

case "${fleet_sigs}" in
    ''|*[!0-9]*)
        note "FAIL distinct-signature count is '${fleet_sigs}', not a number"
        FAILED=1
        ;;
    *)
        if [ "${fleet_sigs}" -ge 1 ] && [ "${fleet_sigs}" -le "${fleet_unknown}" ]; then
            note "ok   distinct signatures (${fleet_sigs}) is between 1 and the agent count (${fleet_unknown})"
        else
            note "FAIL distinct signatures ${fleet_sigs} is outside 1..${fleet_unknown} — signatures cannot outnumber the agents that carry them"
            FAILED=1
        fi
        ;;
esac
if grep -q '—' "${RUN_DIR}/m10-fleet.txt"; then
    note "ok   unanswered rows render an em dash"
else
    note "FAIL no em dash in the fleet view — an unanswered row was printed as a number"
    FAILED=1
fi
if grep -Eq 'accessing source repositories +—' "${RUN_DIR}/m10-fleet.txt"; then
    note "ok   'accessing source repositories' is —, not 0 (nobody answered at resource_summary)"
else
    note "FAIL 'accessing source repositories' is not an em dash"
    FAILED=1
fi
if grep -Eq 'production credentials +—' "${RUN_DIR}/m10-fleet.txt"; then
    note "ok   'production credentials' is —, not 0"
else
    note "FAIL 'production credentials' is not an em dash"
    FAILED=1
fi
# Section 72's "0 production credentials" is a FINDING; printing it from an
# absence of data would be the single most dangerous dishonesty available
# to this feature, because it is the line an administrator would most like
# to believe.
grep_absent "the mock never prints '0 production credentials' from an absence of data" \
    "${RUN_DIR}/m10-fleet.txt" "0 production credentials"

# --- 13. negative probes (spec 74.4, 60, 61) --------------------------------
bogus="$("${CTL}" --socket agentd debug rpc alerts.bogus 2>&1 | head -c 400)"
printf '%s\n' "${bogus}" > "${RUN_DIR}/m10-negative-unknown.txt"
grep_row "an unknown alerts.* method answers unknown_method" \
    "${RUN_DIR}/m10-negative-unknown.txt" "does not exist"
agentd_rpc alerts.dismiss '{"alert_id":"alr_nosuchcard"}' \
    > "${RUN_DIR}/m10-negative-notfound.txt" 2>&1
grep_row "dismissing an unknown alert answers not_found" \
    "${RUN_DIR}/m10-negative-notfound.txt" "no alert with id"
runuser -u punar -- "${CTL}" --socket agentd debug rpc query.answer \
    --params '{"query_id":"qry_x","requesting_admin":"x@acme.com","organization":"acme.com","requested_scope":"inventory","received_at":"2026-08-25T14:00:00Z"}' \
    > "${RUN_DIR}/m10-negative-nonroot.txt" 2>&1
grep_row "a local user cannot make this device answer a question (root peer only)" \
    "${RUN_DIR}/m10-negative-nonroot.txt" "denied"
runuser -u nobody -- "${CTL}" --socket agentd debug rpc queries.list \
    > "${RUN_DIR}/m10-negative-nobody.txt" 2>&1
if grep -qiE 'permission denied|could not connect|denied' "${RUN_DIR}/m10-negative-nobody.txt"; then
    note "ok   a peer outside group punar is refused by the filesystem before any method runs"
else
    note "FAIL nobody was not refused at the socket: $(head -c 200 "${RUN_DIR}/m10-negative-nobody.txt")"
    FAILED=1
fi
mock_rpc admin.ai_query \
    "{\"admin\":\"secops@acme.com\",\"device_id\":\"${DEVICE_ID}\",\"scope\":\"everything\"}" \
    > "${RUN_DIR}/m10-negative-vocabulary.txt" 2>&1
grep_row "the mock refuses an invented scope rather than answering best-effort" \
    "${RUN_DIR}/m10-negative-vocabulary.txt" "not a query scope"
agentd_rpc query.answer \
    '{"query_id":"qry_junk","requesting_admin":"secops@acme.com","organization":"acme.com","requested_scope":"everything","received_at":"2026-08-25T14:00:00Z"}' \
    > "${RUN_DIR}/m10-negative-scope.json" 2>&1
jq_check "the device refuses an invented scope too, and returns no partial answer" \
    "${RUN_DIR}/m10-negative-scope.json" \
    '.authorization_decision == "deny" and .refusal_reason == "out_of_scope" and ((has("payload")) | not)'

# --- cleanup: leave the device as this exercise found it ---------------------
kill "${FOO_PID}" 2>/dev/null
kill "${BAR_PID}" 2>/dev/null
pkill -u punar -f "${PUNAR_HOME}/Downloads/" 2>/dev/null
rm -f "${FOO}" "${BAR}"
sleep 1
"${CTL}" agents scan --trigger manual >/dev/null 2>&1
systemctl stop "${MOCK}" >/dev/null 2>&1
mock_active="$(systemctl is-active "${MOCK}" 2>/dev/null)"
check_eq "${MOCK} stopped at exit (the mock runs only inside this window)" \
    "inactive" "${mock_active}"
if [ "${reconcile_was}" = "active" ]; then
    systemctl start "${RECONCILE_TIMER}" >/dev/null 2>&1
    check_eq "reconcile timer restored" "active" "$(systemctl is-active "${RECONCILE_TIMER}" 2>&1)"
fi
check_eq "the scan timer was never stopped by this check (it is what group 3 asserts)" \
    "active" "$(systemctl is-active "${SCAN_TIMER}" 2>&1)"
scan_unit_result="$(systemctl show "${SCAN_UNIT}" -p Result --value 2>/dev/null)"
note "info ${SCAN_UNIT} last result: ${scan_unit_result:-unknown}"

cp "${MOCK_STATE}/received-answers.jsonl" "${RUN_DIR}/m10-received-answers.jsonl" 2>/dev/null
cp "${QUERIES}" "${RUN_DIR}/m10-queries.jsonl" 2>/dev/null

note "finished $(date -u +%Y-%m-%dT%H:%M:%SZ)"
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M10_OK"
else
    note "PUNAR_M10_FAIL"
fi
cat "${REPORT}"
exit 0
