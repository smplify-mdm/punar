#!/bin/sh
# M12 in-VM exercise: per-managed-cgroup network enforcement, bounded local
# visibility, audit/ledger privacy, relay honesty, fail-safe policy reload,
# self-heal, and the graphical Privacy panel. Runs as root after M10; every
# human path is repeated as the real console user where authorization matters.
#
# The script always exits 0. Its typed verdict is /run/punar/m12-report.txt,
# consumed as a hard gate by tools/boot-test.sh.

set -u

RUN_DIR=/run/punar
REPORT="${RUN_DIR}/m12-report.txt"
CTL=/usr/bin/punarctl
ENV_BIN=/usr/bin/punar-env
AUDIT=/var/log/punar/audit.jsonl
MEMBERS=/usr/share/punar/network/zone-members.json
ATLAS=/home/punar/atlas
FIXTURE=/usr/share/punar/fixtures/projects/atlas
LAUNCH_OUT="${RUN_DIR}/m12-launch.txt"
PROBE_RESULTS="${ATLAS}/.punar-agent-net-results"
PROBE_READY="${ATLAS}/.punar-agent-net-ready"
PROBE_FIFO="${ATLAS}/.punar-agent-net-go"
FAILED=0
SID=""
TAG=""
SCOPE=""
LAUNCH_PID=""

: > "${REPORT}"
note() { printf '%s\n' "$*" >> "${REPORT}"; }

check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        note "FAIL $1 (expected '$2', got '$3')"
        FAILED=1
    fi
}

check_true() {
    if [ "$2" -eq 0 ]; then
        note "ok   $1"
    else
        note "FAIL $1 (status $2)"
        FAILED=1
    fi
}

jq_check() {
    if jq -e "$3" "$2" >/dev/null 2>&1; then
        note "ok   $1"
    else
        note "FAIL $1 (jq filter: $3; input: $(head -c 260 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
}

grep_row() {
    if grep -qiF "$3" "$2" 2>/dev/null; then
        note "ok   $1"
    else
        note "FAIL $1 (missing '$3'; input: $(head -c 260 "$2" 2>/dev/null || echo absent))"
        FAILED=1
    fi
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
        "WAYLAND_DISPLAY=${WL_DISPLAY}" "HOME=/home/punar" "$@"
}

shell_ipc() {
    as_punar qs -p /usr/share/punar/shell ipc call "$@" 2>/dev/null
}

stop_user_unit() {
    as_punar systemctl --user stop "$1" >/dev/null 2>&1 || true
    as_punar systemctl --user reset-failed "$1" >/dev/null 2>&1 || true
}

# Invoked indirectly by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
    [ -n "${SCOPE}" ] && stop_user_unit "${SCOPE}"
    stop_user_unit punar-m12-listener-allow.service
    stop_user_unit punar-m12-listener-deny.service
    if [ -n "${LAUNCH_PID}" ]; then
        kill "${LAUNCH_PID}" >/dev/null 2>&1 || true
        wait "${LAUNCH_PID}" >/dev/null 2>&1 || true
    fi
    "${CTL}" relay set direct >/dev/null 2>&1 || true
}
trap cleanup EXIT

note "info M12's loopback fixture proves policy, attachment, enforcement, attribution, observation and the ledger join; it proves no internet, VPN or real-relay behavior"

# 1. Shipped service, data, and kernel capability.
check_eq "punar-netd.service is active" "active" \
    "$(systemctl is-active punar-netd.service 2>/dev/null || true)"
check_eq "netd socket mode/owner" "660 root punar" \
    "$(stat -c '%a %U %G' /run/punar-netd/netd.sock 2>/dev/null || echo absent)"
"${CTL}" network status --json > "${RUN_DIR}/m12-status.json" 2>&1
jq_check "cgroup-v2 nft enforcement is available" "${RUN_DIR}/m12-status.json" \
    '.enforcement.state == "available"'
jq_check "network status refuses content and DNS inspection claims" "${RUN_DIR}/m12-status.json" \
    '.observation.content_inspection == false and .observation.dns_logging == false and .dns_protection.state == "not_configured"'

zones_ok=0
for zone in /usr/share/punar/network/zones/*.json; do
    if ! jq -e '.name | type == "string"' "${zone}" >/dev/null 2>&1 \
            || ! jq -e '.kind | IN("internet", "corporate", "production", "privileged")' "${zone}" >/dev/null 2>&1; then
        zones_ok=1
    fi
done
check_true "all shipped zone documents parse with closed kinds" "${zones_ok}"
jq_check "dev membership fixture is versioned and assigns both probes" "${MEMBERS}" \
    '.v == 1 and (.zones.corp_dev.cidrs | index("127.0.0.9/32")) != null and (.zones.corp_prod.cidrs | index("127.0.0.7/32")) != null'

# 2. Table partition before the managed session exists.
nft -j list table inet punar-net > "${RUN_DIR}/m12-nft-punar-net.json" 2>&1
nft -j list table inet punar-base > "${RUN_DIR}/m12-nft-punar-base.json" 2>&1
jq_check "netd owns an output-hook egress chain" "${RUN_DIR}/m12-nft-punar-net.json" \
    '[.nftables[].chain? | select(.name == "egress" and .hook == "output")] | length == 1'
jq_check "punard still owns the default-drop input chain" "${RUN_DIR}/m12-nft-punar-base.json" \
    '[.nftables[].chain? | select(.hook == "input" and .policy == "drop")] | length >= 1'
if grep -q 'punar-base' "${RUN_DIR}/m12-nft-punar-net.json" \
        || grep -q 'punar-net' "${RUN_DIR}/m12-nft-punar-base.json"; then
    note "FAIL nft table ownership is mixed"
    FAILED=1
else
    note "ok   punar-net and punar-base table ownership is disjoint"
fi

# 3. Two listeners outside the future agent cgroup. The denied listener is
# the same-user control proving that the service is genuinely reachable.
# Use systemd's own socket activator rather than a workload package: the lean
# image ships the Git client but intentionally does not carry git-daemon.
# Each accepted child inherits the socket and holds it long enough for the
# bounded /proc observation pass to see an ESTABLISHED connection.
as_punar systemd-run --user --quiet --collect --unit=punar-m12-listener-allow \
    -- /usr/bin/systemd-socket-activate --accept --listen=127.0.0.9:9418 \
       /usr/bin/sleep 120 >/dev/null 2>&1
as_punar systemd-run --user --quiet --collect --unit=punar-m12-listener-deny \
    -- /usr/bin/systemd-socket-activate --accept --listen=127.0.0.7:9418 \
       /usr/bin/sleep 120 >/dev/null 2>&1
sleep 1
check_eq "allow listener is active outside the agent scope" "active" \
    "$(as_punar systemctl --user is-active punar-m12-listener-allow.service 2>/dev/null || true)"
check_eq "deny control listener is active outside the agent scope" "active" \
    "$(as_punar systemctl --user is-active punar-m12-listener-deny.service 2>/dev/null || true)"
as_punar timeout 2 /bin/bash -c 'exec 8<>/dev/tcp/127.0.0.7/9418' >/dev/null 2>&1
check_true "same-user out-of-scope control reaches 127.0.0.7:9418" "$?"

# 4. Launch the real managed-session path with only the dev mock binary
# substituted. The FIFO prevents either probe from racing policy attachment.
mkdir -p "${ATLAS}"
cp "${FIXTURE}/project-environment.yaml" "${FIXTURE}/project-network-policy.json" "${ATLAS}/"
chown -R punar:punar "${ATLAS}"
rm -f "${PROBE_FIFO}" "${PROBE_RESULTS}" "${PROBE_READY}" "${LAUNCH_OUT}"
mkfifo -m 600 "${PROBE_FIFO}"
chown punar:punar "${PROBE_FIFO}"
as_punar systemd-run --user --pipe --wait --collect --quiet \
    --unit=punar-m12-launch --setenv=PUNAR_AGENT_MOCK=1 \
    --setenv=PUNAR_MOCK_AGENT_NET=1 \
    -- "${ENV_BIN}" -C "${ATLAS}" agent claude-code \
    > "${LAUNCH_OUT}" 2>&1 &
LAUNCH_PID=$!

waited=0
while [ "${waited}" -lt 180 ]; do
    grep -qi 'REGISTRY · ' "${LAUNCH_OUT}" 2>/dev/null && break
    kill -0 "${LAUNCH_PID}" 2>/dev/null || break
    sleep 2
    waited=$((waited + 2))
done
if grep -qi 'REGISTRY · ' "${LAUNCH_OUT}" 2>/dev/null; then
    note "ok   managed mock session registered in ${waited}s"
else
    note "FAIL managed session did not register (output: $(head -c 400 "${LAUNCH_OUT}" 2>/dev/null))"
    FAILED=1
fi
SID="$(sed -n 's/^Session  *\(agt_[0-9a-f]*\).*/\1/p' "${LAUNCH_OUT}" 2>/dev/null | head -n 1)"
if [ -n "${SID}" ]; then
    TAG="${SID#agt_}"
    SCOPE="punar-agent-${SID}.scope"
    note "ok   managed session id is ${SID}"
else
    SID=agt_missing
    TAG=missing
    SCOPE=""
    note "FAIL managed session id was not printed"
    FAILED=1
fi

waited=0
while [ "${waited}" -lt 90 ]; do
    nft -j list table inet punar-net > "${RUN_DIR}/m12-nft-attached.json" 2>/dev/null || true
    jq -e --arg chain "s_${TAG}" \
        '[.nftables[].chain? | select(.name == $chain)] | length == 1' \
        "${RUN_DIR}/m12-nft-attached.json" >/dev/null 2>&1 && break
    sleep 2
    waited=$((waited + 2))
done
jq_check "managed session has its own nft chain" "${RUN_DIR}/m12-nft-attached.json" \
    "[.nftables[].chain? | select(.name == \"s_${TAG}\")] | length == 1"

"${CTL}" agents list --json > "${RUN_DIR}/m12-agents.json" 2>&1
AGENT_PID="$(jq -r --arg sid "${SID}" '.sessions[] | select(.session_id == $sid) | .process_id' "${RUN_DIR}/m12-agents.json" 2>/dev/null | head -n 1)"
CGROUP_PATH="$(sed -n 's/^0:://p' "/proc/${AGENT_PID}/cgroup" 2>/dev/null | head -n 1)"
# nft's JSON formatter canonicalizes the cgroup-v2 selector without the root
# slash; /proc/cgroup includes it. They identify the same kernel path.
NFT_CGROUP_PATH="${CGROUP_PATH#/}"
if [ -n "${NFT_CGROUP_PATH}" ] && jq -e --arg path "${NFT_CGROUP_PATH}" \
        '.. | strings | select(. == $path)' "${RUN_DIR}/m12-nft-attached.json" >/dev/null 2>&1; then
    note "ok   nft cgroup path equals the normalized kernel-attested session path"
else
    note "FAIL nft cgroup path does not equal ${CGROUP_PATH:-absent}"
    FAILED=1
fi

"${CTL}" network policy atlas --json > "${RUN_DIR}/m12-policy.json" 2>&1
jq_check "strict policy compiles allow dev and deny production" "${RUN_DIR}/m12-policy.json" \
    '([.rules[] | select(.zone == "corp_dev" and .decision == "allow")] | length == 1) and ([.rules[] | select(.zone == "corp_prod" and .decision == "deny")] | length == 1)'
jq_check "container allow remains ungrantable without a rootless network helper" "${RUN_DIR}/m12-policy.json" \
    '.container_network.mode == "none" and .container_network.reason == "allow_not_grantable"'

"${CTL}" network explain atlas corp_prod --json > "${RUN_DIR}/m12-explain.json" 2>&1
jq_check "network explanation names the decision, subject, policy, change and next step" \
    "${RUN_DIR}/m12-explain.json" \
    '.decision == "deny" and .zone == "corp_prod" and .project == "atlas"
     and (.why | contains("strictest")) and (.who | contains("Managed AI sessions"))
     and (.which_policy | length == 2) and (.can_you_change_it | contains("Edit"))
     and .next_step == "punarctl network policy atlas"
     and .enforcement.state == "available"'

as_punar "${ENV_BIN}" -C "${ATLAS}" status > "${RUN_DIR}/m12-env-status.txt" 2>&1
check_true "punar-env status succeeds with post-M12 truth" "$?"
grep_row "environment status names enforced agent scope" \
    "${RUN_DIR}/m12-env-status.txt" "enforced (agent scope) · container: deny only"
as_punar "${ENV_BIN}" -C "${ATLAS}" status --json > "${RUN_DIR}/m12-env-status.json" 2>&1
jq_check "environment JSON reports network enforcement as enforced" \
    "${RUN_DIR}/m12-env-status.json" '.enforcement.network == "enforced"'

# Explicit apply is also an observation trigger.
"${CTL}" network apply atlas > "${RUN_DIR}/m12-apply.txt" 2>&1
check_true "root policy apply succeeds" "$?"
printf 'go\n' > "${PROBE_FIFO}"
waited=0
while [ "${waited}" -lt 30 ] && [ ! -f "${PROBE_READY}" ]; do
    sleep 1
    waited=$((waited + 1))
done
if [ -f "${PROBE_RESULTS}" ]; then
    cp "${PROBE_RESULTS}" "${RUN_DIR}/m12-probe-results.txt"
else
    : > "${RUN_DIR}/m12-probe-results.txt"
fi
ALLOW_CODE="$(sed -n 's/^allow_code=\([0-9][0-9]*\)$/\1/p' "${PROBE_RESULTS}" 2>/dev/null | head -n 1)"
DENY_CODE="$(sed -n 's/^deny_code=\([0-9][0-9]*\)$/\1/p' "${PROBE_RESULTS}" 2>/dev/null | head -n 1)"
DENY_MS="$(sed -n 's/^deny_ms=\([0-9][0-9]*\)$/\1/p' "${PROBE_RESULTS}" 2>/dev/null | head -n 1)"
check_eq "agent-scope allow probe exit" "0" "${ALLOW_CODE:-missing}"
if [ -n "${DENY_CODE}" ] && [ "${DENY_CODE}" -ne 0 ] \
        && [ -n "${DENY_MS}" ] && [ "${DENY_MS}" -lt 2000 ]; then
    note "ok   agent-scope production probe denied in ${DENY_MS}ms (exit ${DENY_CODE})"
else
    note "FAIL production probe did not fail fast (exit ${DENY_CODE:-missing}, ${DENY_MS:-missing}ms)"
    FAILED=1
fi

# 5. Counters, local view, idempotent side file, and destination-free audit.
"${CTL}" privacy connections --json > "${RUN_DIR}/m12-connections.json" 2>&1
check_true "on-demand connection pass succeeds" "$?"
jq_check "allowed established socket is attributed to the managed session" "${RUN_DIR}/m12-connections.json" \
    "[.processes[] | select(.session.id == \"${SID}\") | .connections[] | select(.destination == \"127.0.0.9\" and .state == \"established\" and .zone == \"corp_dev\")] | length >= 1"
jq_check "denied production row carries a positive count and local destination" "${RUN_DIR}/m12-connections.json" \
    "[.processes[] | select(.session.id == \"${SID}\") | .denied[] | select(.zone == \"corp_prod\" and .kind == \"production\" and .attempts >= 1 and .last_destination == \"127.0.0.7\")] | length == 1"
jq_check "view is honest about DNS and contains no port-shaped fields" "${RUN_DIR}/m12-connections.json" \
    '.dns_protection.state == "not_configured" and (.scanned_at | type == "string")'
if grep -q '9418' "${RUN_DIR}/m12-connections.json"; then
    note "FAIL connection view persisted a port"
    FAILED=1
else
    note "ok   connection view contains no ports"
fi

nft -j list table inet punar-net > "${RUN_DIR}/m12-nft-counters.json" 2>&1
# A policy reconciliation atomically replaces nft's table and therefore
# starts fresh kernel objects; netd folds the previous values into its
# in-memory carry before replacement. The positive denial total above proves
# that carry. Here, assert that both named enforcement counters remain wired
# after any concurrent registry reconciliation rather than requiring an old
# kernel object's value to survive its destruction.
jq_check "named allow counter remains installed after reconciliation" "${RUN_DIR}/m12-nft-counters.json" \
    "[.nftables[].counter? | select(.name == \"c_${TAG}_corp_dev_allow\")] | length == 1"
jq_check "named deny counter remains installed after reconciliation" "${RUN_DIR}/m12-nft-counters.json" \
    "[.nftables[].counter? | select(.name == \"c_${TAG}_corp_prod_deny\")] | length == 1"

SIDE_BEFORE="$(sha256sum /run/punar-netd/connections.json 2>/dev/null | awk '{print $1}')"
SIDE_MTIME_BEFORE="$(stat -c '%y' /run/punar-netd/connections.json 2>/dev/null || echo absent)"
"${CTL}" privacy connections --json > /dev/null 2>&1
SIDE_AFTER="$(sha256sum /run/punar-netd/connections.json 2>/dev/null | awk '{print $1}')"
SIDE_MTIME_AFTER="$(stat -c '%y' /run/punar-netd/connections.json 2>/dev/null || echo missing)"
check_eq "unchanged observation does not rewrite the side file" "${SIDE_BEFORE}" "${SIDE_AFTER}"
check_eq "unchanged observation preserves the side-file mtime" "${SIDE_MTIME_BEFORE}" "${SIDE_MTIME_AFTER}"
check_eq "connections side file mode/owner" "640 root punar" \
    "$(stat -c '%a %U %G' /run/punar-netd/connections.json 2>/dev/null || echo absent)"
if systemctl list-timers --all --no-legend 2>/dev/null | grep -q 'punar-netd'; then
    note "FAIL punar-netd installed a polling timer"
    FAILED=1
else
    note "ok   punar-netd has no timer"
fi

jq -c --arg sid "${SID}" \
    'select(.action == "network.deny" and .agent_session_id == $sid and .project_id == "atlas" and .resource == "corp_prod" and .result == "denied_production")' \
    "${AUDIT}" 2>/dev/null | tail -n 1 > "${RUN_DIR}/m12-audit-deny.json"
jq_check "audit identifies session, project, zone and closed production result" "${RUN_DIR}/m12-audit-deny.json" \
    '.decision == "deny" and .action == "network.deny" and .resource == "corp_prod" and .result == "denied_production"'
if grep -q '127.0.0.7\|9418' "${AUDIT}"; then
    note "FAIL non-purgeable audit trail contains a destination or port"
    FAILED=1
else
    note "ok   non-purgeable audit trail contains neither destination nor port"
fi

# 6. The agent-owned, purgeable ledger receives the absolute destination
# aggregate and the audit event reference, with no schema widening.
"${CTL}" agents access "${SID}" --json > "${RUN_DIR}/m12-access.json" 2>&1
jq_check "ledger contains the reached destination" "${RUN_DIR}/m12-access.json" \
    '.summary.resources.network_destinations | index("127.0.0.9") != null'
jq_check "fulfilled network and production producers are no longer pending" "${RUN_DIR}/m12-access.json" \
    '[.not_yet_observed[].category] | (index("network_destinations") == null and index("production_access") == null and index("sensitive_resource_access") == null)'
jq_check "ledger detail identifies the netd aggregate evidence" "${RUN_DIR}/m12-access.json" \
    '[.detail.entries[] | select(.evidence == "netd_aggregate" and .category == "network_destinations")] | length >= 1'
DENY_EVENT="$(jq -r '.event_id // empty' "${RUN_DIR}/m12-audit-deny.json" 2>/dev/null)"
jq_check "production event joins the immutable audit event id" "${RUN_DIR}/m12-access.json" \
    "[.summary.security_events[] | select(.event_type == \"production_access\" and .event_id == \"${DENY_EVENT}\")] | length >= 1"
if grep -R -q '9418\|"payload"\|"sni"\|"dns_query"\|"cmdline"' \
        /var/lib/punar/agents/ledger /run/punar-agentd/ledger.json \
        /run/punar-netd/connections.json 2>/dev/null; then
    note "FAIL a privacy-owned file contains a port or forbidden content key"
    FAILED=1
else
    note "ok   privacy-owned files contain no ports, payload, SNI, DNS query or command line"
fi

# 7. Relay honesty and structural daemon confinement.
"${CTL}" relay status --json > "${RUN_DIR}/m12-relay.json" 2>&1
jq_check "relay status starts as a non-simulated direct path" "${RUN_DIR}/m12-relay.json" \
    '.mode == "direct" and .simulated == false'
"${CTL}" relay set private_relay > "${RUN_DIR}/m12-relay-set.txt" 2>&1
grep_row "private relay text is visibly simulated" "${RUN_DIR}/m12-relay-set.txt" "SIMULATED"
"${CTL}" relay status --json > "${RUN_DIR}/m12-relay.json" 2>&1
jq_check "simulated relay keeps knowledge halves structurally separate" "${RUN_DIR}/m12-relay.json" \
    '.simulated == true and (.hops[0].knows | index("destination") == null) and (.hops[1].knows | index("client_identity") == null) and (.property_not_held | contains("same process"))'

AF="$(systemctl show punar-netd.service -p RestrictAddressFamilies --value 2>/dev/null)"
DENY="$(systemctl show punar-netd.service -p IPAddressDeny --value 2>/dev/null)"
CAPS="$(systemctl show punar-netd.service -p CapabilityBoundingSet --value 2>/dev/null)"
AF_NORMALIZED="$(printf '%s\n' "${AF}" | tr ' ' '\n' | sed '/^$/d' | LC_ALL=C sort | paste -sd ' ' -)"
check_eq "netd sandbox admits only AF_UNIX and AF_NETLINK" \
    "AF_NETLINK AF_UNIX" "${AF_NORMALIZED:-absent}"
case "${DENY}" in
    *any*|*0.0.0.0/0*::/0*) note "ok   netd has IPAddressDeny=any (systemd-normalized)" ;;
    *) note "FAIL netd lacks IPAddressDeny=any (${DENY:-absent})"; FAILED=1 ;;
esac
case " ${CAPS} " in
    *" CAP_SYS_PTRACE "*|*" cap_sys_ptrace "*)
        note "FAIL netd holds CAP_SYS_PTRACE; managed attribution must use kernel cgroup ids, not process tracing"
        FAILED=1
        ;;
    *) note "ok   netd holds no CAP_SYS_PTRACE" ;;
esac

# 8. Negative probes and fail-safe live-data reload.
for method in network.bogus network.capture network.inspect network.export; do
    if "${CTL}" --socket netd debug rpc "${method}" > "${RUN_DIR}/m12-negative.txt" 2>&1; then
        note "FAIL ${method} unexpectedly exists"
        FAILED=1
    elif grep -qi 'does not exist' "${RUN_DIR}/m12-negative.txt"; then
        note "ok   ${method} is outside the closed method table"
    else
        note "FAIL ${method} refusal did not render the unknown-method explanation"
        FAILED=1
    fi
done
if as_punar "${CTL}" network apply atlas > "${RUN_DIR}/m12-user-apply.txt" 2>&1; then
    note "FAIL unprivileged network.apply succeeded"
    FAILED=1
else
    grep_row "unprivileged apply names the root requirement" "${RUN_DIR}/m12-user-apply.txt" "requires root"
fi
if as_punar "${CTL}" --socket agentd debug rpc ledger.network \
        --params "{\"session_id\":\"${SID}\",\"destinations\":[],\"source\":\"netd_aggregate\"}" \
        > "${RUN_DIR}/m12-user-ledger-write.txt" 2>&1; then
    note "FAIL unprivileged ledger.network producer write succeeded"
    FAILED=1
else
    grep_row "unprivileged process cannot forge network ledger evidence" \
        "${RUN_DIR}/m12-user-ledger-write.txt" "only the root-owned punar-netd"
fi

cp "${MEMBERS}" "${RUN_DIR}/m12-members.backup"
nft -j list table inet punar-net > "${RUN_DIR}/m12-before-invalid.json" 2>&1
INVALID_BEFORE="$(sha256sum "${RUN_DIR}/m12-before-invalid.json" | awk '{print $1}')"
printf '%s\n' '{"v":1,"zones":{"corp_prod":{"cidrs":["not-a-cidr"]}}}' > "${MEMBERS}"
if "${CTL}" network apply atlas > "${RUN_DIR}/m12-invalid-apply.txt" 2>&1; then
    note "FAIL malformed zone membership was applied"
    FAILED=1
else
    note "ok   malformed zone membership was refused before nft replacement"
fi
nft -j list table inet punar-net > "${RUN_DIR}/m12-after-invalid.json" 2>&1
INVALID_AFTER="$(sha256sum "${RUN_DIR}/m12-after-invalid.json" | awk '{print $1}')"
check_eq "previous nft table survives malformed policy" "${INVALID_BEFORE}" "${INVALID_AFTER}"
cp "${RUN_DIR}/m12-members.backup" "${MEMBERS}"
"${CTL}" network apply atlas >/dev/null 2>&1
check_true "restored valid membership applies" "$?"

# Removing only netd's table proves an on-demand read repairs its own table
# and leaves punard's device firewall untouched.
BASE_BEFORE="$(sha256sum "${RUN_DIR}/m12-nft-punar-base.json" | awk '{print $1}')"
nft destroy table inet punar-net >/dev/null 2>&1
"${CTL}" privacy connections --json > "${RUN_DIR}/m12-self-heal.json" 2>&1
check_true "connection read self-heals a missing netd table" "$?"
nft -j list table inet punar-net >/dev/null 2>&1
check_true "punar-net table exists after self-heal" "$?"
nft -j list table inet punar-base > "${RUN_DIR}/m12-base-after-heal.json" 2>&1
BASE_AFTER="$(sha256sum "${RUN_DIR}/m12-base-after-heal.json" | awk '{print $1}')"
check_eq "punar-base is byte-identical across netd self-heal" "${BASE_BEFORE}" "${BASE_AFTER}"

# 9. Graphical panel over the real, non-demo session state.
shell_ipc privacypanel open >/dev/null 2>&1
check_true "Privacy panel opens over shell IPC" "$?"
sleep 2
as_punar grim "${RUN_DIR}/punar-m12.png" >/dev/null 2>&1
if [ -s "${RUN_DIR}/punar-m12.png" ]; then
    note "ok   Privacy panel screenshot is non-empty"
else
    note "FAIL Privacy panel screenshot is absent or empty"
    FAILED=1
fi
shell_ipc privacypanel close >/dev/null 2>&1 || true

# 10. Detach removes enforcement but retains the user's purgeable ledger.
stop_user_unit "${SCOPE}"
wait "${LAUNCH_PID}" >/dev/null 2>&1 || true
LAUNCH_PID=""
waited=0
while [ "${waited}" -lt 60 ]; do
    nft -j list table inet punar-net > "${RUN_DIR}/m12-nft-detached.json" 2>/dev/null || true
    if ! jq -e --arg chain "s_${TAG}" \
            '[.nftables[].chain? | select(.name == $chain)] | length > 0' \
            "${RUN_DIR}/m12-nft-detached.json" >/dev/null 2>&1; then
        break
    fi
    sleep 2
    waited=$((waited + 2))
done
if jq -e --arg chain "s_${TAG}" \
        '[.nftables[].chain? | select(.name == $chain)] | length == 0' \
        "${RUN_DIR}/m12-nft-detached.json" >/dev/null 2>&1; then
    note "ok   session chain is gone after detach"
else
    note "FAIL session chain remains after detach"
    FAILED=1
fi
"${CTL}" agents access "${SID}" --json > "${RUN_DIR}/m12-access-ended.json" 2>&1
jq_check "ended ledger retains the reached destination" "${RUN_DIR}/m12-access-ended.json" \
    '.summary.resources.network_destinations | index("127.0.0.9") != null'
jq -c --arg sid "${SID}" \
    'select(.action == "network.session_detach" and .agent_session_id == $sid and .project_id == "atlas" and .result == "success")' \
    "${AUDIT}" 2>/dev/null | tail -n 1 > "${RUN_DIR}/m12-audit-detach.json"
jq_check "detach is recorded without destination detail" "${RUN_DIR}/m12-audit-detach.json" \
    '.decision == "allow" and .resource == "session_ended"'

"${CTL}" relay set direct >/dev/null 2>&1 || true
SCOPE=""

if [ "${FAILED}" -eq 0 ]; then
    note "PUNAR_M12_OK"
else
    note "PUNAR_M12_FAIL"
fi
cat "${REPORT}"
exit 0
