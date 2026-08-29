#!/bin/sh
# M7 in-VM AI agent registry exercise (milestone-7.md §12; SPEC sections 18,
# 19, 20, 22, 23, 25, 26, 27). Runs AS ROOT via punar-m7-check.service; every
# unprivileged step runs as punar through the established runuser + session
# env pattern (the managed launch NEEDS the live user manager: the agent runs
# in a `systemd-run --user --scope` unit, and that scope cgroup IS the
# attribution evidence). idle-ram.sh starts this synchronously AFTER
# punar-m6-check.service and BEFORE the artifact export, so everything
# written into /run/punar here (m7-report.txt, m7-launch.txt, m7-inspect.txt,
# m7-agents-list.json, m7-agents-file.json, m7-registry.jsonl, punar-m7.png,
# per-step diagnostics) ships in the same export tar.
#
# The script ALWAYS exits 0: the verdict lives in /run/punar/m7-report.txt
# (`PUNAR_M7_OK` / `PUNAR_M7_FAIL` final line, per-assertion `ok`/`FAIL`
# lines above it) and is echoed to the console for the serial log. The host
# gate (tools/boot-test.sh phase 9) parses the exported report and hard-fails
# on PUNAR_M7_FAIL or a truncated report.
#
# The journey (11 assertion groups): daemon/socket/tmpfiles preflight →
# staged adapter + signature data → a MOCK managed session launched through
# `punar-env agent claude-code` (there is no real Claude Code in an offline
# VM; PUNAR_AGENT_MOCK=1 substitutes /usr/lib/punar/punar-mock-agent, which
# says so on its first line) → registry truth (list, schema-exact
# registry.jsonl, workspace touch) → scope attribution (spec 22: the cgroup
# and the record agree) → `punarctl agents inspect` detail → a REAL innocuous
# sleeping process at ~punar/Downloads/foo-agent detected as UNKNOWN ·
# SUSPECTED (spec 23) → /run/punar/agents.json → the AI panel screenshot with
# a managed row and an unknown row on one screen (Plate D-005) → end of life
# (scope stopped → `ended` record; fixture killed → detection cleared) →
# audit lifecycle lines carrying the real agt_ id → negative probes on the
# NEW socket.
#
# Honesty notes (spec 1.22):
#   - Every authority row carries its current enforcement state. Network
#     rows are enforced for managed agent scopes by punar-netd; this check
#     verifies the label while M12 proves the actual packet decision.
#   - Detection is a heuristic. The fixture is a real process installed by
#     this script for the detector to find; a match proves the pattern
#     mechanism works, not that detection is complete. Every rendered word
#     says "suspected".
#   - The peer-credential DENIAL path (a register call claiming another
#     user's pid) is NOT exercised here: no tool in the image can send
#     arbitrary typed params to the socket (no socat/nc/python, by design),
#     and inventing one would be a bigger dev surface than the assertion is
#     worth. It is covered by punar-agentd's integration tests on the host.
#     What IS proven in-VM is the socket's filesystem admission and the
#     closed method table.
#
# IMAGE TOOLING TRAPS carried from earlier milestones:
#   - No diffutils: compare with sha256sum, never cmp/diff (M6 lesson).
#   - `qs ipc call` clients MUST pass -p /usr/share/punar/shell (M2 lesson).
#   - fmt::verdict uppercases: every rendered-word grep is case-insensitive
#     (M5 lesson).
#   - vendor-level .wants units report `disabled` from is-enabled: assert the
#     symlink plus Wants= (M4 lesson).
#   - Since M10 the `agents.scan` audit event's `resource` is the composite
#     `<agent>:<trigger>` (audit-event.json has no trigger field, and the M8
#     Decision-0 law says a shipped schema does not grow one), and a 240 s
#     timer runs passes of its own. Every scan-audit assertion here matches
#     the agent name as a PREFIX and stays trigger-agnostic, so the timer
#     owning a transition this script expected cannot fake a failure.

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m7-report.txt"
CTL=/usr/bin/punarctl
ENV_BIN=/usr/bin/punar-env
AGENTD_UNIT=punar-agentd.service
AGENTD_SOCK=/run/punar-agentd/agentd.sock
AGENTD_RUN_DIR=/run/punar-agentd
WANTS_LINK=/usr/lib/systemd/system/multi-user.target.wants/punar-agentd.service
REGISTRY=/var/lib/punar/agents/registry.jsonl
REGISTRY_DIR=/var/lib/punar/agents
AGENTS_JSON="${RUN_DIR}/agents.json"
AUDIT_LOG=/var/log/punar/audit.jsonl
ADAPTERS_DIR=/usr/share/punar/agents/adapters
SUSPECTED=/usr/share/punar/agents/signatures/suspected.json
MOCK_AGENT=/usr/lib/punar/punar-mock-agent
FIXTURE_SRC=/usr/lib/punar/foo-agent-fixture.sh
PUNAR_HOME=/home/punar
ATLAS="${PUNAR_HOME}/atlas"
DOWNLOADS="${PUNAR_HOME}/Downloads"
FOO_AGENT="${DOWNLOADS}/foo-agent"
FIXTURE_DIR=/usr/share/punar/fixtures/projects/atlas
TOUCH_FILE="${ATLAS}/.punar-agent-touch"
LAUNCH_OUT="${RUN_DIR}/m7-launch.txt"
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
        note "FAIL $1 (missing: '$3')"
        FAILED=1
    fi
}

# grep_re <name> <file> <ERE, matched case-insensitively>
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

PUNAR_UID="$(id -u punar 2>/dev/null || echo 1000)"
PUNAR_RUN="/run/user/${PUNAR_UID}"

# Session Wayland display, discovered once from the runtime dir (the
# m2-check pattern — exactly one compositor runs in this VM).
WL_DISPLAY=""
for wl_sock in "${PUNAR_RUN}"/wayland-*; do
    case "${wl_sock}" in
        *.lock) ;;
        *) [ -e "${wl_sock}" ] && WL_DISPLAY="$(basename "${wl_sock}")" && break ;;
    esac
done

# Every unprivileged step: fixed argv, no shell string across the runuser
# boundary. XDG_RUNTIME_DIR + DBUS_SESSION_BUS_ADDRESS are what make
# `systemctl --user` and `systemd-run --user` reach the live user manager
# greetd's autologin session started; WAYLAND_DISPLAY is for `qs ipc call`
# and grim.
as_punar() {
    runuser -u punar -- env "XDG_RUNTIME_DIR=${PUNAR_RUN}" \
        "DBUS_SESSION_BUS_ADDRESS=unix:path=${PUNAR_RUN}/bus" \
        "WAYLAND_DISPLAY=${WL_DISPLAY}" \
        "HOME=${PUNAR_HOME}" "$@"
}

# capture_shot <output-basename> — grim under the session user (this script
# is root; the compositor is punar's). The preceding sleep is the bounded
# FileView pickup wait: the panel's agents.json read is event-driven but not
# synchronous with agentd's write. The screenshot is human evidence; every
# machine assertion reads the file or the socket directly.
capture_shot() {
    sleep 10
    if [ -n "${WL_DISPLAY}" ] && as_punar grim "${RUN_DIR}/$1" 2>/dev/null; then
        note "ok   grim captured $1 (session-user capture)"
    else
        note "FAIL grim capture $1 (wayland=${WL_DISPLAY:-none})"
        FAILED=1
    fi
}

# --- 1. daemon, socket and tmpfiles preflight --------------------------------
check_eq "punar-agentd.service is active" "active" \
    "$(systemctl is-active "${AGENTD_UNIT}" 2>&1)"
# Vendor-level enablement: the SYMLINK plus the resolved Wants= — never
# is-enabled, which reports `disabled` for /usr/lib .wants (M4 lesson).
if [ -L "${WANTS_LINK}" ]; then
    note "ok   vendor wants symlink present: ${WANTS_LINK} -> $(readlink "${WANTS_LINK}")"
else
    note "FAIL vendor wants symlink missing at ${WANTS_LINK}"
    FAILED=1
fi
systemctl show multi-user.target -p Wants > "${RUN_DIR}/m7-wants.txt" 2>&1
grep_row "multi-user.target Wants punar-agentd.service" "${RUN_DIR}/m7-wants.txt" \
    "punar-agentd.service"
check_eq "agentd socket mode/owner (0660 root:punar — filesystem admission)" \
    "660 root punar" "$(stat -c '%a %U %G' "${AGENTD_SOCK}" 2>/dev/null)"
check_eq "agentd socket directory (root-owned, not the peer-writable /run/punar)" \
    "750 root punar" "$(stat -c '%a %U %G' "${AGENTD_RUN_DIR}" 2>/dev/null)"
check_eq "registry state directory mode/owner" "700 root root" \
    "$(stat -c '%a %U %G' "${REGISTRY_DIR}" 2>/dev/null)"
# Nobody must not reach the new socket either (same mechanism m3-check
# proved for punard, asserted here for the second daemon).
if ! runuser -u nobody -- "${CTL}" agents list >/dev/null 2>&1; then
    note "ok   punarctl agents list as nobody rejected (0660 root:punar admission)"
else
    note "FAIL punarctl agents list as nobody succeeded — socket admission broken"
    FAILED=1
fi

# --- 2. adapters and signatures ship as DATA (spec 26 modularity) ------------
for adapter in claude-code generic; do
    if [ -f "${ADAPTERS_DIR}/${adapter}.json" ]; then
        note "ok   adapter definition staged: ${ADAPTERS_DIR}/${adapter}.json"
    else
        note "FAIL adapter definition missing: ${ADAPTERS_DIR}/${adapter}.json"
        FAILED=1
    fi
done
jq_check "generic adapter is a second, independent adapter (the modularity proof)" \
    "${ADAPTERS_DIR}/generic.json" \
    '.name == "generic-shell" and .adapter == "generic"
     and (.adapter_config.signature.comm | length) == 0'
jq_check "suspected-signature data loads and carries the Downloads pattern" \
    "${SUSPECTED}" \
    '.v == 1 and (.patterns | any(.id == "downloads-foo-agent"))'
if [ -x "${MOCK_AGENT}" ]; then
    note "ok   mock agent staged executable at ${MOCK_AGENT}"
else
    note "FAIL mock agent missing or not executable at ${MOCK_AGENT}"
    FAILED=1
fi

# --- 3. managed launch (MOCK) ------------------------------------------------
# The Atlas project: normally left by m6-check. Re-created from the staged
# fixture if that exercise did not run, so M7's verdict never depends on M6's.
if [ ! -f "${ATLAS}/project-environment.yaml" ]; then
    mkdir -p "${ATLAS}"
    cp "${FIXTURE_DIR}/project-environment.yaml" \
       "${FIXTURE_DIR}/project-network-policy.json" "${ATLAS}/" 2>/dev/null
    chown -R punar:punar "${ATLAS}"
    note "info Atlas project re-created from the staged fixture (m6-check did not leave one)"
fi
rm -f "${TOUCH_FILE}"

# PUNAR_AGENT_MOCK=1 is the ONLY thing that substitutes the mock command;
# nothing in the image sets it. The session blocks (the mock waits for a
# signal), so the launcher runs in the background and the scope stop in
# group 10 is what ends it.
#
# WHY the extra `systemd-run --user --pipe --wait` wrapper instead of running
# punar-env directly under runuser: punar-env creates the agent's transient
# scope with `systemd-run --user --scope`, which MIGRATES the calling process
# into a cgroup under user@<uid>.service. cgroup v2's delegation containment
# lets an unprivileged mover do that only when the source and destination
# share an ancestor the mover can write — true inside the user manager's own
# subtree, false for a process sitting in this check's system.slice cgroup.
# Asking the user manager to FORK the launcher (a transient service, no
# migration involved) puts punar-env where a real desktop launch would run
# it, and the scope migration then succeeds for the same reason it does from
# a terminal. `--pipe` hands our redirect to the unit, `--wait` propagates
# punar-env's exit code, `--collect` reaps the unit afterwards.
as_punar systemd-run --user --pipe --wait --collect --quiet \
    --unit=punar-m7-launch --setenv=PUNAR_AGENT_MOCK=1 \
    -- "${ENV_BIN}" -C "${ATLAS}" agent claude-code \
    > "${LAUNCH_OUT}" 2>&1 &
LAUNCH_PID=$!

# Bounded wait for the registry line the launcher prints once punar-agentd
# has accepted the session (fail-closed: if registration fails, punar-env
# stops the scope and exits nonzero, and this wait times out).
waited=0
while [ "${waited}" -lt 120 ]; do
    if grep -qi 'REGISTRY · ' "${LAUNCH_OUT}" 2>/dev/null; then
        break
    fi
    if ! kill -0 "${LAUNCH_PID}" 2>/dev/null; then
        break
    fi
    sleep 2
    waited=$((waited + 2))
done
if grep -qi 'REGISTRY · ' "${LAUNCH_OUT}" 2>/dev/null; then
    note "ok   managed session registered within ${waited}s"
else
    note "FAIL no REGISTRY line after ${waited}s; launch output: $(head -c 400 "${LAUNCH_OUT}" 2>/dev/null)"
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

# The launch block: the mock label, the attribution facts, and the authority
# summary with its per-row enforcement milestones (spec 20 — DECLARED).
grep_row "launch says MOCK in the first lines (no fake agent is passed off as real)" \
    "${LAUNCH_OUT}" "MOCK AGENT · dev/CI stand-in"
grep_row "launch masthead names the session" "${LAUNCH_OUT}" \
    "PUNAR-ENV · AGENT SESSION · ${SID}"
grep_row "launch cites the scope as the attribution mechanism" "${LAUNCH_OUT}" \
    "${SCOPE} · attribution via cgroup"
grep_row "authority block cites the personal policy (unmanaged-first)" \
    "${LAUNCH_OUT}" "AUTHORITY · WHAT IT MAY ACCESS · POLICY · PERSONAL DEFAULTS"
# The enforcement column's whole vocabulary, in one place — the same
# conversion as m6-check (docs/development/checks-conventions.md). What each
# row must do is state WHERE its declaration stands: applied, enforced, or a
# declaration that names the milestone still owed. Pinning M9/M12 here was a
# future-milestone placeholder in a check script, and three of the six
# recorded regressions of this class had exactly that shape.
ENFORCE_RE='(applied( \(bind mount\))?|enforced( \(agent scope\))?|declared · (M[0-9]+[+]?|enforced( M[0-9]+)?|applied))'
grep_re "filesystem row states where its declaration stands" \
    "${LAUNCH_OUT}" "^ +filesystem +project +read_write +${ENFORCE_RE}$"
grep_re "network row states where its declaration stands" \
    "${LAUNCH_OUT}" "^ +network +[a-z_]+ +(allow|deny) +${ENFORCE_RE}$"
grep_re "credentials row states where its declaration stands" \
    "${LAUNCH_OUT}" "^ +credentials +[a-z_]+ +[a-z]+ +${ENFORCE_RE}$"
# The three closing lines of the section-27 flow. Each must still name the
# state of the step — declared with the milestone that owes it, or the fact
# that the step is now real. The milestone NUMBER is not pinned: M9's
# re-milestoning of the tool gateway (M9+ -> M11+ in the ledger) is precisely
# the kind of honest correction that used to break a check.
grep_re "network step names its state, and a milestone if enforcement is still owed" \
    "${LAUNCH_OUT}" '^NETWORK · (DECLARED · enforcement M[0-9]+[+]?|ENFORCED)'
grep_re "credentials step names its state, and a milestone if brokering is still owed" \
    "${LAUNCH_OUT}" '^CREDENTIALS · (DECLARED · M[0-9]+[+]? secret broker|BROKERED)'
grep_re "tool gateway names the milestone that owns it, or says it mediates now" \
    "${LAUNCH_OUT}" '^TOOLS · (M[0-9]+[+]?|MEDIATED)'
# The rule those rows are instances of: no authority row may render as a bare
# `declared`. That reads as a granted permission on a surface (spec 1.22),
# and it keeps holding when every label above is relabelled.
bare_declared="$(grep -cE '^ +(filesystem|network|credentials) .*declared[[:space:]]*$' \
    "${LAUNCH_OUT}" 2>/dev/null)"
if [ "${bare_declared}" = "0" ]; then
    note "ok   no authority row renders as a bare 'declared' — every declaration states where its enforcement stands"
else
    note "FAIL ${bare_declared} authority row(s) render as a bare 'declared': $(grep -E '^ +(filesystem|network|credentials) .*declared[[:space:]]*$' "${LAUNCH_OUT}" | head -c 200)"
    FAILED=1
fi
if grep -qi 'organization' "${LAUNCH_OUT}" 2>/dev/null; then
    note "FAIL launch renders organization chrome on an unenrolled device (unmanaged-first: never)"
    FAILED=1
else
    note "ok   no organization chrome in the launch block (unmanaged-first)"
fi

# --- 4. registry truth -------------------------------------------------------
as_punar "${CTL}" --json agents list > "${RUN_DIR}/m7-agents-list.json" 2>/dev/null
check_true "punarctl agents list --json (as punar, over the agentd socket)" "$?"
jq_check "list carries the managed session with the fixture's own project" \
    "${RUN_DIR}/m7-agents-list.json" \
    ".sessions | any(.session_id == \"${SID}\" and .agent == \"claude-code\"
       and .project == \"atlas\" and .classification == \"managed\"
       and .status == \"active\" and .version == \"mock\"
       and .user == \"punar\" and .environment == \"host\")"
jq_check "every list row carries the ten registry-record fields" \
    "${RUN_DIR}/m7-agents-list.json" \
    '.sessions | all(keys | contains(["session_id","agent","version","process_id",
       "user","project","environment","status","classification","started_at"]))'

# The persisted transition log, validated field by field against
# schemas/ai-agent/registry-record.json (the shipped contract).
grep -F "\"${SID}\"" "${REGISTRY}" > "${RUN_DIR}/m7-registry.jsonl" 2>/dev/null
jq_slurp_check "registry.jsonl has exactly one active record for this session, schema-exact" \
    "${RUN_DIR}/m7-registry.jsonl" \
    '(length == 1) and all(.[];
       (keys | contains(["session_id","agent","version","process_id","user",
                         "project","environment","status","classification",
                         "started_at"]))
       and (.session_id | test("^agt_[0-9a-f]{12}$"))
       and (.status == "active")
       and (.classification == "managed")
       and (.process_id | type == "number")
       and (.started_at | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]+)?([Zz]|[+-][0-9]{2}:[0-9]{2})$")))'
check_eq "registry.jsonl mode (root-only: a writable registry IS attribution authority)" \
    "640 root root" "$(stat -c '%a %U %G' "${REGISTRY}" 2>/dev/null)"

# The mock proves it really ran in the project directory.
if [ -f "${TOUCH_FILE}" ]; then
    note "ok   the agent ran in the project workspace (${TOUCH_FILE} written)"
else
    note "FAIL ${TOUCH_FILE} missing — the agent did not run in the project directory"
    FAILED=1
fi
check_eq "workspace touch file owner (the session runs as the human, not root)" \
    "punar" "$(stat -c '%U' "${TOUCH_FILE}" 2>/dev/null)"

# --- 5. scope attribution (spec 22) ------------------------------------------
as_punar systemctl --user show "${SCOPE}" -p ActiveState -p Description \
    > "${RUN_DIR}/m7-scope.txt" 2>&1
grep_row "the agent's transient scope is active under the user manager" \
    "${RUN_DIR}/m7-scope.txt" "ActiveState=active"
AGENT_PID="$(jq -r ".sessions[] | select(.session_id == \"${SID}\") | .process_id" \
    "${RUN_DIR}/m7-agents-list.json" 2>/dev/null)"
if [ -n "${AGENT_PID}" ] && [ -r "/proc/${AGENT_PID}/cgroup" ]; then
    cp "/proc/${AGENT_PID}/cgroup" "${RUN_DIR}/m7-agent-cgroup.txt" 2>/dev/null
    grep_row "the registered pid's cgroup names the scope (record and kernel agree)" \
        "${RUN_DIR}/m7-agent-cgroup.txt" "${SCOPE}"
else
    note "FAIL registered pid '${AGENT_PID:-none}' has no readable /proc cgroup"
    FAILED=1
fi

# --- 6. punarctl agents inspect (the D-005 detail in terminal grammar) -------
as_punar "${CTL}" agents inspect "${SID}" > "${RUN_DIR}/m7-inspect.txt" 2>&1
check_true "punarctl agents inspect exit code" "$?"
grep_row "inspect: attribution masthead carries the session id" \
    "${RUN_DIR}/m7-inspect.txt" "${SID}"
grep_row "inspect: authority section" "${RUN_DIR}/m7-inspect.txt" \
    "AUTHORITY · WHAT IT MAY ACCESS"
grep_row "inspect: policy citation is the personal default" \
    "${RUN_DIR}/m7-inspect.txt" "POLICY · PERSONAL DEFAULTS"
grep_row "inspect: ledger section is present and honest" \
    "${RUN_DIR}/m7-inspect.txt" "LEDGER · WHAT IT ACCESSED"
# M8 replaced the dashed "MILESTONE 8" placeholder with the real ledger.
# What stays true across both is the honesty rule: categories with no
# producer yet must name the milestone that will fill them, never render
# as an empty success (spec 1.22, 21.2). Assert THAT, not the placeholder.
grep_row "inspect: unproduced ledger categories name their milestone (nothing is faked)" \
    "${RUN_DIR}/m7-inspect.txt" "NOT YET OBSERVED"
# Strengthened, and still placeholder-free: the milestone has to sit BESIDE
# the words, in the value a reader's eye lands on — not merely somewhere
# later in the reason prose. `tr` first, so there is no case trap (M5 lesson)
# and no reliance on GNU sed's `I` flag.
# shellcheck disable=SC2018,SC2019  # the ASCII fold is deliberate: these lines
# carry UTF-8 separators, and `a-z`/`A-Z` folds only single-byte ASCII. The
# `[:lower:]`/`[:upper:]` classes shellcheck suggests are locale-dependent,
# and in a single-byte non-C locale they would map bytes >= 0x80 and corrupt
# the very separators the greps below step over.
bare_rows="$(tr 'a-z' 'A-Z' < "${RUN_DIR}/m7-inspect.txt" 2>/dev/null |
    grep -F 'NOT YET OBSERVED' |
    sed 's/^.*NOT YET OBSERVED//' |
    cut -c1-60 |
    grep -cv 'M[0-9]')"
if [ "${bare_rows}" = "0" ]; then
    note "ok   inspect: no not-yet-observed row renders bare — every one carries its milestone beside the words"
else
    note "FAIL inspect: ${bare_rows} not-yet-observed row(s) render BARE (no milestone beside the words)"
    FAILED=1
fi
as_punar "${CTL}" --json agents inspect "${SID}" \
    > "${RUN_DIR}/m7-inspect.json" 2>/dev/null
jq_check "inspect --json returns the session row verbatim" \
    "${RUN_DIR}/m7-inspect.json" \
    ".session.session_id == \"${SID}\" and .session.classification == \"managed\""

# --- 7. shadow AI: a real process for the heuristic to find (spec 23) --------
mkdir -p "${DOWNLOADS}"
chown punar:punar "${DOWNLOADS}"
install -m 0755 -o punar -g punar "${FIXTURE_SRC}" "${FOO_AGENT}"
# Started with the ABSOLUTE script path as argv[1]: punar-agentd retains only
# absolute path arguments (an agent's argv can carry a prompt, and spec 53
# forbids logging prompt contents), so a relative `sh ./foo-agent` would
# present nothing to match.
as_punar sh "${FOO_AGENT}" > "${RUN_DIR}/m7-foo-agent.txt" 2>&1 &
sleep 3
if pgrep -u punar -f "${FOO_AGENT}" >/dev/null 2>&1; then
    note "ok   detection fixture running at ${FOO_AGENT}"
else
    note "FAIL detection fixture did not start: $(head -c 200 "${RUN_DIR}/m7-foo-agent.txt" 2>/dev/null)"
    FAILED=1
fi
as_punar "${CTL}" --json agents scan > "${RUN_DIR}/m7-scan.json" 2>/dev/null
check_true "punarctl agents scan exit code (an on-demand pass; since M10 a timer runs one too)" "$?"
jq_check "the scan reports the fixture as UNKNOWN and SUSPECTED, never certain" \
    "${RUN_DIR}/m7-scan.json" \
    ".detections | any(.classification == \"unknown\" and .suspected == true
       and .executable == \"${FOO_AGENT}\"
       and .signature_id == \"downloads-foo-agent\"
       and .agent == \"foo-agent\" and .project == \"unknown\"
       and .environment == \"host\")"
jq_check "the managed session is NOT re-reported as a detection (scope is attribution)" \
    "${RUN_DIR}/m7-scan.json" \
    ".detections | all(.session_id != \"${SID}\")"
# The detection identity this pass reported IS the join key into the audit
# trail: agentd puts it in the transition event's `agent_session_id`.
# Group 11 asserts the transition for THIS detection, not merely that some
# foo-agent line exists somewhere in the boot. The id is stable across
# passes for the life of the process (milestone-10.md section 4.1), so it
# still matches when the M10 scan TIMER — not this script — is the pass
# that observes the transition.
#
# The fixture is started through runuser, whose ROOT parent also carries
# the absolute fixture path in its argv and is therefore detected too. Both
# rows are legitimate detections, but the one this exercise deliberately
# created is the process running as punar, so prefer it and fall back to
# any row rather than depending on the daemon's ordering.
DETECTION_ID="$(jq -r "[.detections[] | select(.executable == \"${FOO_AGENT}\")]
    | (map(select(.user == \"punar\")) + .)[0] | .session_id // empty" \
    "${RUN_DIR}/m7-scan.json" 2>/dev/null)"
if [ -n "${DETECTION_ID}" ]; then
    note "ok   the scan minted a detection id for the fixture: ${DETECTION_ID}"
else
    note "FAIL the scan reported no detection id for ${FOO_AGENT}"
    FAILED=1
    # A sentinel that cannot match, so group 11 fails loudly rather than
    # silently counting somebody else's rows.
    DETECTION_ID="agt_none"
fi
as_punar "${CTL}" agents list > "${RUN_DIR}/m7-agents-list.txt" 2>&1
grep_row "the list render says UNKNOWN · SUSPECTED" "${RUN_DIR}/m7-agents-list.txt" \
    "UNKNOWN · SUSPECTED"
grep_row "the list render states the heuristic limit in words" \
    "${RUN_DIR}/m7-agents-list.txt" "SUSPECTED, NOT CERTAIN"
# M7 shipped detection with no trigger of its own and deferred continuous
# detection to M10 by name, so this check pinned the words "MILESTONE 10".
# M10 SHIPPED it (punar-agentd-scan.timer, 240 s), and the footer now
# states the real cadence and the sampling hole instead of a deferral.
# The INVARIANT M7 was protecting is not the deferral sentence: it is that
# the render tells the user how detection actually happens, so nobody
# assumes continuous coverage the product does not have (spec 1.22, 23 —
# "do not claim perfect detection"). Assert THAT, in two halves.
grep_re "the list render states how detection actually happens (a real periodic cadence)" \
    "${RUN_DIR}/m7-agents-list.txt" 'continuous · every [0-9]+ min'
grep_row "the list render still owns the sampling hole (short-lived processes are not seen)" \
    "${RUN_DIR}/m7-agents-list.txt" "starts and exits inside one interval is not seen"

# --- 8. /run/punar/agents.json (the shell's event-driven source) -------------
cp "${AGENTS_JSON}" "${RUN_DIR}/m7-agents-file.json" 2>/dev/null
check_eq "agents.json mode (world-readable summary, atomically replaced)" "644" \
    "$(stat -c '%a' "${AGENTS_JSON}" 2>/dev/null)"
jq_check "agents.json carries both rows and the personal policy citation" \
    "${RUN_DIR}/m7-agents-file.json" \
    ".v == 1 and .policy_citation == \"personal-defaults\"
     and .counts.managed >= 1 and .counts.unknown >= 1
     and (.sessions | any(.session_id == \"${SID}\" and .classification == \"managed\"))
     and (.detections | any(.suspected == true and .executable == \"${FOO_AGENT}\"))"
jq_check "agents.json is summary-only: no pids, no command lines" \
    "${RUN_DIR}/m7-agents-file.json" \
    '[.sessions[], .detections[]] | all(has("process_id") == false
       and has("cmdline") == false)'

# --- 9. the AI panel with both rows on one screen (Plate D-005) --------------
as_punar qs -p /usr/share/punar/shell ipc call aipanel open >/dev/null 2>&1
check_true "qs ipc call aipanel open (the PUNAR+A surface, opened over IPC)" "$?"
sleep 2
panel_state="$(as_punar qs -p /usr/share/punar/shell ipc call aipanel state 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "aipanel state after open" "open" "${panel_state}"
capture_shot punar-m7.png
as_punar qs -p /usr/share/punar/shell ipc call aipanel close >/dev/null 2>&1
panel_state="$(as_punar qs -p /usr/share/punar/shell ipc call aipanel state 2>/dev/null \
    | tr -d '[:space:]"')"
check_eq "aipanel state after close" "closed" "${panel_state}"

# --- 10. end of life ---------------------------------------------------------
as_punar systemctl --user stop "${SCOPE}" > "${RUN_DIR}/m7-stop.txt" 2>&1
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
grep_row "launcher printed the session-ended line" "${LAUNCH_OUT}" \
    "SESSION ENDED · ${SID}"
as_punar "${CTL}" --json agents list > "${RUN_DIR}/m7-agents-list-ended.json" 2>/dev/null
jq_check "the session is listed as ended (this boot's history, not deleted)" \
    "${RUN_DIR}/m7-agents-list-ended.json" \
    ".sessions | any(.session_id == \"${SID}\" and .status == \"ended\")"
grep -F "\"${SID}\"" "${REGISTRY}" > "${RUN_DIR}/m7-registry.jsonl" 2>/dev/null
jq_slurp_check "registry.jsonl now holds both transitions, active then ended" \
    "${RUN_DIR}/m7-registry.jsonl" \
    '(length == 2) and ([.[].status] == ["active","ended"])
     and all(.[]; keys | contains(["session_id","agent","version","process_id",
        "user","project","environment","status","classification","started_at"]))'

pkill -u punar -f "${FOO_AGENT}" >/dev/null 2>&1
# The fixture's `sleep infinity` is orphaned when its shell exits (the shell
# is what the pattern matches). Reap it so the VM is left tidy; nothing else
# in the exercise runs a bare sleep as punar at this point.
pkill -u punar -x sleep >/dev/null 2>&1
sleep 2
as_punar "${CTL}" --json agents scan > "${RUN_DIR}/m7-scan-cleared.json" 2>/dev/null
jq_check "the detection clears once the process is gone" \
    "${RUN_DIR}/m7-scan-cleared.json" \
    ".detections | all(.executable != \"${FOO_AGENT}\")"
cp "${AGENTS_JSON}" "${RUN_DIR}/m7-agents-file-cleared.json" 2>/dev/null
jq_check "agents.json drops the cleared detection too" \
    "${RUN_DIR}/m7-agents-file-cleared.json" \
    '.detections | length == 0'

# --- 11. audit (spec 22: the trail carries the REAL agent session id) --------
check_eq "audit: exactly one agents.register allow for this session" 1 \
    "$(audit_count ".action == \"agents.register\" and .agent_session_id == \"${SID}\"
        and .decision == \"allow\" and .result == \"success\"")"
check_eq "audit: the register event is attributed to the human and the project" 1 \
    "$(audit_count ".action == \"agents.register\" and .agent_session_id == \"${SID}\"
        and .source == \"human\" and .project_id == \"atlas\"
        and .resource == \"claude-code\"")"
check_eq "audit: exactly one agents.end for this session" 1 \
    "$(audit_count ".action == \"agents.end\" and .agent_session_id == \"${SID}\"
        and .result == \"success\"")"
# M7 matched `.resource == "foo-agent"` exactly. M10 made the scan audit
# event's `resource` the composite `<agent>:<trigger>` — audit-event.json
# has no field for a trigger and the M8 Decision-0 law forbids growing one,
# so the trigger travels in `resource` (crates/punar-agentd/src/server.rs,
# `audit_scan_transition`; milestone-10.md section 3.4). The bare equality
# can therefore never match again. What M7 owns is unchanged: the detection
# transition of THIS fixture was audited, in both directions. So match the
# agent name as a PREFIX and bind the event to the detection id the scan
# reported — deliberately WITHOUT pinning the trigger, because since M10
# either this script's pass or the 240 s timer's pass may legitimately be
# the one that observes the transition and emits it (m10-check group 3 is
# where the trigger vocabulary itself is asserted).
SCAN_OF_FIXTURE='(.resource | test("^foo-agent(:|$)"))'
detected="$(audit_count "${SCAN_OF_FIXTURE} and .action == \"agents.scan\"
    and .result == \"detected\" and .agent_session_id == \"${DETECTION_ID}\"")"
if [ "${detected}" -ge 1 ]; then
    note "ok   audit: the detection transition was recorded for ${DETECTION_ID} (${detected} detected event(s))"
else
    note "FAIL audit: no agents.scan detected event for foo-agent (${DETECTION_ID})"
    FAILED=1
fi
cleared="$(audit_count "${SCAN_OF_FIXTURE} and .action == \"agents.scan\"
    and .result == \"cleared\" and .agent_session_id == \"${DETECTION_ID}\"")"
if [ "${cleared}" -ge 1 ]; then
    note "ok   audit: the cleared transition was recorded for ${DETECTION_ID} (${cleared} cleared event(s))"
else
    note "FAIL audit: no agents.scan cleared event for foo-agent (${DETECTION_ID})"
    FAILED=1
fi
# Transitions only: a scan that changes nothing must not write a line.
before="$(wc -l < "${AUDIT_LOG}" | tr -d ' ')"
as_punar "${CTL}" --json agents scan >/dev/null 2>&1
after="$(wc -l < "${AUDIT_LOG}" | tr -d ' ')"
check_eq "a no-change scan writes no audit lines (transitions only, spec 6.3 voice)" \
    "${before}" "${after}"
# The audit tail keeps its 12-key shape now that a second daemon writes it.
"${CTL}" --json audit tail -n 20 > "${RUN_DIR}/m7-audit-tail.json" 2>/dev/null
jq_check "audit tail still schema-shaped with two writers on one file" \
    "${RUN_DIR}/m7-audit-tail.json" \
    '(.events | length) > 0 and (.events | all(
       (keys | contains(["event_id","timestamp","device_id","user_id",
                         "agent_session_id","project_id","source","action",
                         "resource","decision","policy_ids","result"]))
       and (.agent_session_id | test("^agt_[A-Za-z0-9]+$"))))'

# --- 12. negative probes on the NEW socket (spec 60/61/74.4) ----------------
# agents.exec is probed on purpose: the registry socket must have no
# generic execution method either (spec 60 — the punard no-exec probe is
# m3-check's; this is the same claim for the second daemon).
for method in agents.bogus agents.access agents.exec; do
    probe_out="$(as_punar "${CTL}" debug rpc "${method}" 2>&1)"
    rc=$?
    if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi "${method}"; then
        note "ok   debug rpc ${method} rejected (closed method table, exit ${rc})"
    else
        note "FAIL debug rpc ${method} (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
        FAILED=1
    fi
done
probe_out="$(as_punar "${CTL}" debug rpc admin.query --socket agentd 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ]; then
    note "ok   debug rpc admin.query forced at the agentd socket rejected (exit ${rc}) — the remote-query surface is M10, not here"
else
    note "FAIL admin.query answered on the agentd socket: $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi
probe_out="$(as_punar "${CTL}" agents inspect agt_000000000000 2>&1)"
rc=$?
if [ "${rc}" -ne 0 ] && printf '%s' "${probe_out}" | grep -qi 'agt_000000000000'; then
    note "ok   agents inspect on an unknown id refused (exit ${rc}) without inventing a session"
else
    note "FAIL agents inspect on an unknown id (exit ${rc}): $(printf '%s' "${probe_out}" | head -c 200)"
    FAILED=1
fi
note "info the peer-credential DENIAL path (register claiming another user's pid) is covered by punar-agentd's host integration tests, not in-VM: no image tool sends arbitrary typed params to the socket, by design"

# --- verdict -----------------------------------------------------------------
if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M7_OK"
else
    note "PUNAR_M7_FAIL"
fi
# Full report onto stdout -> journal+console -> serial log, so a failed
# export still leaves the per-assertion detail (and the verdict fallback
# tools/boot-test.sh greps for) in serial.log.
cat "${REPORT}"
exit 0
