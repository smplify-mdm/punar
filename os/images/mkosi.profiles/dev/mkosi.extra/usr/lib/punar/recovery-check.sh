#!/bin/sh
# Punar identity-door exercise — runs as ROOT.
#
# WHAT THIS EXISTS FOR. The greeter draws "Forgot your password?" and relays a
# redemption over /run/punar-onboardd/onboard.sock. That socket used to be bound
# by punar-onboardd.service under
#   ConditionPathExists=!/var/lib/punar/onboarding/completed.json
# so on every machine that had finished onboarding — which is every machine
# where a person can have forgotten a password — systemd skipped the unit, the
# socket did not exist, and the door answered "The recovery service is
# unavailable". A lockout-recovery affordance that is dead precisely when it is
# needed is the worst shape a control can take, and nothing anywhere looked at
# it. This check is what looks at it.
#
# WHY ROOT. The socket directory is 0750 root:greeter, so User=punar cannot even
# traverse it, and the exercise restarts a system unit. Put in the surfaces
# check this would have reported "unavailable" and exercised nothing.
#
# NO SECRETS CROSS THIS SCRIPT. The probe sends a deliberately unsupported
# protocol version, so the daemon answers before it looks at any field. The
# discriminator is the whole point:
#   version_unsupported  -> the socket existed, systemd started a transaction
#                           process, and it framed a reply on stdin/stdout
#   service_unavailable  -> the client could not connect at all: THE BUG
#
# Verdict: PUNAR_RECOVERY_OK / PUNAR_RECOVERY_FAIL, last line of
# /run/punar/recovery-report.txt. Always exits 0; tools/boot-test.sh gates.
# shellcheck disable=SC2329
set -u

REPORT=/run/punar/recovery-report.txt
MARKER=/var/lib/punar/onboarding/completed.json
SOCKET=/run/punar-onboardd/onboard.sock
MARKER_PLANTED=0
FAILED=0
mkdir -p /run/punar
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
    if [ "$2" = "1" ]; then
        note "ok   $1"
    else
        note "FAIL $1"
        FAILED=1
    fi
}

# The planted marker must never outlive this script: materialize() parses it,
# and a stub would make every later identity operation on this boot fail for a
# reason that has nothing to do with the product.
cleanup() {
    if [ "${MARKER_PLANTED}" -eq 1 ]; then
        rm -f "${MARKER}"
        systemctl restart punar-onboardd.socket >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT INT TERM

finish() {
    cleanup
    MARKER_PLANTED=0
    if [ -e "${MARKER}" ]; then
        note "info a completion marker is present and was NOT planted by this check"
    fi
    if [ "${FAILED}" -eq 0 ]; then note "PUNAR_RECOVERY_OK"; else note "PUNAR_RECOVERY_FAIL"; fi
    cat "${REPORT}"
    exit 0
}

note "# Punar identity-door exercise — $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- Vacuity guard -------------------------------------------------------
# Everything below asserts that a door opens. If the client that knocks is not
# installed, every probe would fail identically and the check would look like a
# product failure instead of a broken exercise.
if [ ! -x /usr/bin/punar-onboard ]; then
    note "FAIL /usr/bin/punar-onboard is missing; the exercise cannot knock"
    FAILED=1
    finish
fi
note "ok   /usr/bin/punar-onboard is installed"

# Send a request the daemon must refuse on sight, and print only its code.
probe_code() {
    printf '{"v":99,"username":"probe","password":"probe","deviceName":"probe"}\n' \
        | /usr/bin/punar-onboard 2>/dev/null \
        | sed -n 's/.*"code":"\([a-z_]*\)".*/\1/p' \
        | head -1
}

# --- 1. The door exists --------------------------------------------------
state=$(systemctl is-active punar-onboardd.socket 2>/dev/null || true)
check_eq "punar-onboardd.socket is listening" "active" "${state}"

# The resident service is gone, observed in systemd's live unit table rather
# than in a file: a revert to the always-on daemon shows up here as "loaded".
load=$(systemctl show -p LoadState --value punar-onboardd.service 2>/dev/null || true)
check_eq "the resident punar-onboardd.service is not a unit" "not-found" "${load}"

# --- 2. The door opens, twice --------------------------------------------
# Two connections, because the previous implementation stopped listening after
# a transaction. One answered probe cannot tell a live socket from a spent one.
first=$(probe_code)
check_eq "first connection is answered by the daemon" "version_unsupported" "${first}"
second=$(probe_code)
check_eq "a second connection is answered too" "version_unsupported" "${second}"

# --- 3. Nothing privileged is resident between transactions --------------
# The reachability above was bought by socket activation, not by leaving a root
# process that can create accounts and change passwords alive through every
# session. That trade is the reason the old condition existed, so it is asserted
# rather than assumed.
# Polled rather than sampled once. The client returns as soon as it has read
# its reply, so the server process may still be on its way out for a moment
# after a probe; a single pgrep here would fail intermittently and teach
# whoever saw it that this check is flaky rather than that residency regressed.
# Five seconds is far longer than an exit and far shorter than "resident".
resident=1
settle=0
while [ "${settle}" -lt 5 ]; do
    if pgrep -f 'punar-onboardd session' >/dev/null 2>&1; then
        sleep 1
        settle=$((settle + 1))
    else
        resident=0
        break
    fi
done
check_eq "no transaction process is resident between connections" "0" "${resident}"

# --- 4. Completing onboarding does not take the door away ----------------
# This is the regression itself. The marker is the exact state the old
# ConditionPathExists keyed on, so planting it and restarting the socket asks
# systemd the same question that used to be answered by skipping the unit.
if [ -e "${MARKER}" ]; then
    note "info onboarding is already complete on this machine; the marker is real"
else
    if printf '{"v":1,"probe":"recovery-check"}\n' > "${MARKER}" 2>/dev/null; then
        MARKER_PLANTED=1
        note "info planted a completion marker for the duration of this check"
    else
        note "FAIL could not write ${MARKER}; the regression leg did not run"
        FAILED=1
        finish
    fi
fi

systemctl restart punar-onboardd.socket >/dev/null 2>&1 || true
state=$(systemctl is-active punar-onboardd.socket 2>/dev/null || true)
check_eq "the socket still listens with onboarding complete" "active" "${state}"
if [ -S "${SOCKET}" ]; then
    present=1
else
    present=0
fi
check_true "the socket file exists with onboarding complete" "${present}"

# Removing the planted marker before probing keeps materialize() away from a
# stub it would rightly refuse to parse. The connection probe under a REAL
# completed marker belongs to tools/test-release-onboarding.sh, which is the
# only harness that drives a genuine account into existence; see NOT PROVEN.
cleanup
MARKER_PLANTED=0
after=$(probe_code)
check_eq "the door still opens after the marker is withdrawn" "version_unsupported" "${after}"

note "# NOT PROVEN HERE: a successful redemption. That needs a real recovery"
note "# record, which needs a real completed account, which this image does not"
note "# have — the dev profile autologins instead of onboarding. The end-to-end"
note "# redemption belongs to tools/test-release-onboarding.sh. What is proven"
note "# here is that the door exists, opens, opens again, stays open once"
note "# onboarding is complete, and leaves nothing privileged running."

finish
