#!/bin/sh
# Contract: nothing on the network, in a desktop session or among Punar's own
# services can move the wall clock that M9 grant and approval expiry trusts
# (Grant::is_live, ApprovalEnvelope::has_lapsed in
# crates/punar-common/src/approval.rs).
#
#   C1  every shipped .network file refuses DHCP-supplied NTP servers
#       (UseNTP=no under [DHCPv4] and [DHCPv6]) and no drop-in turns them
#       back on;
#   C2  the desktop polkit rule answers NO to timedated's set-time, set-ntp
#       and set-local-rtc, leaves set-timezone alone, no other shipped rule
#       mentions timedate1, and every lane's desktop image carries the tree
#       and a polkit daemon to read it;
#   C3  every Punar system service carries ProtectClock=yes unless it is a
#       reviewed exclusion below, no drop-in switches it off, and no unit is
#       handed CAP_SYS_TIME;
#   C4  each check rejects a fixture tree that breaks it, so a check that
#       silently stopped matching cannot pass for a working one.
#
# Source-tree only: no image build, no root, a few seconds.
set -eu

REPO_ROOT=$(cd -- "$(dirname "$0")/../.." && pwd)
IMAGES="${REPO_ROOT}/os/images"

# Services that keep the power to set the clock, each with its reason. A new
# unit is not exempt by default: it gets ProtectClock=yes or a line here.
#   punard.service — the root broker that applies OS capabilities and runs the
#     installer. Everything it spawns inherits the unit's syscall filter, and
#     the trusted-time design reserves the clock (clock.* IPC, step detection)
#     to it. Excluded by review, not by omission.
EXCLUDED_UNITS='
punard.service
'

# The units that must carry ProtectClock=yes today. The generic rule in C3
# already covers them; naming them keeps the check from passing vacuously if
# the unit directory moves.
REQUIRED_UNITS='
punar-agentd-scan.service
punar-agentd.service
punar-authd@.service
punar-identity-materialize.service
punar-installer-unattended.service
punar-mail-account@.service
punar-mail-accounts@.service
punar-mail@.service
punar-netd.service
punar-onboardd@.service
punar-pi-update-health.service
punar-pimd@.service
punar-secrets.service
punar-shm-hardening.service
punar-smplifyd.service
punar-update-health.service
punard-reconcile.service
'

TIMEDATE_NO_ACTIONS='
set-time
set-ntp
set-local-rtc
'

# ini_value FILE SECTION KEY — the value KEY last takes in [SECTION] (a
# section may repeat; the last assignment wins, as in systemd), "empty" for a
# bare `KEY=` reset, or "unset".
ini_value() {
    awk -v want="[$2]" -v key="$3" '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*\[/ {
            section = $0
            gsub(/[[:space:]]/, "", section)
            next
        }
        section == want {
            line = $0
            sub(/^[[:space:]]+/, "", line)
            if (index(line, key "=") == 1) {
                seen = 1
                value = substr(line, length(key) + 2)
                sub(/[[:space:]]+$/, "", value)
            }
        }
        END {
            if (!seen) print "unset"
            else if (value == "") print "empty"
            else print value
        }
    ' "$1"
}

is_false() {
    case "$1" in no|false|off|0) return 0 ;; *) return 1 ;; esac
}

is_true() {
    case "$1" in yes|true|on|1) return 0 ;; *) return 1 ;; esac
}

# The trees that reach an installed or live Punar root. The lane-local
# mkosi.extra directories are build-staged and usually absent from a
# checkout; they are scanned when present.
shipped_trees() {
    for tree in \
        "$1/mkosi.profiles/desktop/mkosi.extra" \
        "$1/mkosi.profiles/dev/mkosi.extra" \
        "$1/debian-mkosi.extra" \
        "$1/installer-initrd" \
        "$1/arm64/mkosi.extra" \
        "$1/arm64/mkosi.profiles/desktop/mkosi.extra" \
        "$1/arm64/mkosi.profiles/dev/mkosi.extra" \
        "$1/amd64-debian/mkosi.profiles/desktop/mkosi.extra" \
        "$1/amd64-debian/mkosi.profiles/dev/mkosi.extra"; do
        [ -d "${tree}" ] && printf '%s\n' "${tree}"
    done
    return 0
}

is_excluded() {
    for excluded in ${EXCLUDED_UNITS}; do
        [ "$1" = "${excluded}" ] && return 0
    done
    return 1
}

# check_tree IMAGES_DIR — print every violation; exit non-zero if any.
#
# Every list it walks is newline-separated and globbing is off inside the
# subshell, so the for-loops over find output split on newlines only.
# shellcheck disable=SC2044
check_tree() (
    IFS='
'
    set -f
    images=$1
    desktop="${images}/mkosi.profiles/desktop/mkosi.extra"
    violations=0
    violation() {
        printf 'clock-trust violation %s\n' "$*" >&2
        violations=$((violations + 1))
    }
    trees=$(shipped_trees "${images}")

    # --- C1: the network does not pick the NTP server ----------------------
    for required in 50-punar-dhcp.network 60-punar-wifi.network; do
        [ -f "${desktop}/usr/lib/systemd/network/${required}" ] \
            || violation "C1: usr/lib/systemd/network/${required} is missing"
    done
    for tree in ${trees}; do
        for network in $(find "${tree}" -type f -name '*.network' | sort); do
            relative=${network#"${images}/"}
            for section in DHCPv4 DHCPv6; do
                value=$(ini_value "${network}" "${section}" UseNTP)
                is_false "${value}" \
                    || violation "C1: ${relative} [${section}] UseNTP is ${value}, not no"
            done
        done
        for dropin in $(find "${tree}" -type f -path '*.network.d/*.conf' | sort); do
            for section in DHCPv4 DHCPv6; do
                value=$(ini_value "${dropin}" "${section}" UseNTP)
                [ "${value}" = unset ] || is_false "${value}" \
                    || violation "C1: ${dropin#"${images}/"} sets [${section}] UseNTP=${value}"
            done
        done
    done

    # --- C2: timedated refuses the session ---------------------------------
    rule="${desktop}/usr/share/polkit-1/rules.d/50-punar-clock.rules"
    if [ ! -f "${rule}" ]; then
        violation 'C2: usr/share/polkit-1/rules.d/50-punar-clock.rules is missing'
    else
        for action in ${TIMEDATE_NO_ACTIONS}; do
            grep -Fq "case \"org.freedesktop.timedate1.${action}\":" "${rule}" \
                || violation "C2: the clock rule does not name ${action}"
        done
        grep -Fq 'return polkit.Result.NO;' "${rule}" \
            || violation 'C2: the clock rule never answers NO'
        if grep -Eq 'polkit\.Result\.(YES|AUTH_)' "${rule}"; then
            violation 'C2: the clock rule can answer YES or ask for a password'
        fi
        # This rule sorts before systemd-networkd.rules, which lets networkd
        # apply a DHCP-supplied zone; a NO here would silently end that.
        if grep -Fq 'org.freedesktop.timedate1.set-timezone"' "${rule}"; then
            violation 'C2: the clock rule refuses set-timezone, which only changes how time is shown'
        fi
    fi
    # polkit takes the first answer in file-name order across rules.d, so
    # another shipped rule that mentions timedate1 could answer first.
    for tree in ${trees}; do
        for other in $(find "${tree}" -type f -path '*/polkit-1/rules.d/*' | sort); do
            [ "${other}" = "${rule}" ] && continue
            if grep -Fq 'timedate1' "${other}"; then
                violation "C2: ${other#"${images}/"} also rules on timedate1"
            fi
        done
    done
    for lane in amd64-debian arm64; do
        conf="${images}/${lane}/mkosi.profiles/desktop/mkosi.conf"
        if [ ! -f "${conf}" ]; then
            violation "C2: ${lane}/mkosi.profiles/desktop/mkosi.conf is missing"
            continue
        fi
        grep -Fqx 'ExtraTrees=../../../mkosi.profiles/desktop/mkosi.extra' "${conf}" \
            || violation "C2: the ${lane} desktop image does not carry the shared desktop tree"
        grep -Eq '^[[:space:]]+polkitd$' "${conf}" \
            || violation "C2: the ${lane} desktop image installs no polkitd to read the rule"
    done
    grep -Eq '^[[:space:]]+polkit$' "${images}/mkosi.profiles/desktop/mkosi.conf" \
        || violation 'C2: the Arch desktop image installs no polkit to read the rule'

    # --- C3: Punar's own services cannot set the clock ---------------------
    units="${desktop}/usr/lib/systemd/system"
    for name in ${REQUIRED_UNITS}; do
        [ -f "${units}/${name}" ] || violation "C3: ${name} is missing"
    done
    for name in ${EXCLUDED_UNITS}; do
        [ -f "${units}/${name}" ] \
            || violation "C3: the exclusion ${name} names no unit; remove it"
    done
    for unit in $(find "${units}" -maxdepth 1 -type f -name '*.service' | sort); do
        name=${unit##*/}
        is_excluded "${name}" && continue
        value=$(ini_value "${unit}" Service ProtectClock)
        is_true "${value}" \
            || violation "C3: ${name} has ProtectClock=${value}; set yes or add a reviewed exclusion"
    done
    for tree in ${trees}; do
        for dropin in $(find "${tree}" -type f -path '*.service.d/*.conf' | sort); do
            value=$(ini_value "${dropin}" Service ProtectClock)
            [ "${value}" = unset ] || is_true "${value}" \
                || violation "C3: ${dropin#"${images}/"} sets ProtectClock=${value}"
        done
        for file in $(find "${tree}" -type f \( -name '*.service' -o -path '*.service.d/*.conf' \) | sort); do
            if grep -Eq '^(AmbientCapabilities|CapabilityBoundingSet)=[^~]*CAP_SYS_TIME' "${file}"; then
                violation "C3: ${file#"${images}/"} grants CAP_SYS_TIME"
            fi
        done
    done

    [ "${violations}" -eq 0 ]
)

# --- the real tree ----------------------------------------------------------
if ! check_tree "${IMAGES}"; then
    echo 'clock-trust-contract-test: FAIL' >&2
    exit 1
fi
echo 'ok   the network, the session and Punar services cannot set the clock'

# --- C4: each check rejects a tree that breaks it ---------------------------
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/punar-clock-trust.XXXXXX")
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

make_fixture() {
    fixture="${TEST_ROOT}/$1"
    rm -rf "${fixture}"
    for part in \
        mkosi.profiles/desktop/mkosi.conf \
        mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd \
        mkosi.profiles/desktop/mkosi.extra/usr/share/polkit-1 \
        amd64-debian/mkosi.profiles/desktop/mkosi.conf \
        arm64/mkosi.profiles/desktop/mkosi.conf; do
        mkdir -p "$(dirname "${fixture}/${part}")"
        cp -R "${IMAGES}/${part}" "${fixture}/${part}"
    done
    printf '%s\n' "${fixture}"
}

# expect_rejected NAME DESCRIPTION — the fixture NAME must fail check_tree.
expect_rejected() {
    if check_tree "${TEST_ROOT}/$1" 2>/dev/null; then
        echo "clock-trust-contract-test: FAIL: accepted $2" >&2
        exit 1
    fi
    echo "ok   rejects $2"
}

# Replace one exact line of FILE (fixed string) with another.
replace_line() {
    awk -v from="$2" -v to="$3" '$0 == from && !done { print to; done = 1; next } { print }' \
        "$1" > "$1.new"
    mv "$1.new" "$1"
}

fixture=$(make_fixture clean)
check_tree "${fixture}" || {
    echo 'clock-trust-contract-test: FAIL: the unmodified fixture is rejected' >&2
    exit 1
}

net="mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/network"
fixture=$(make_fixture wifi-v4)
awk '/^\[DHCPv6\]/ { v6 = 1 } !(!v6 && $0 == "UseNTP=no") { print }' \
    "${fixture}/${net}/60-punar-wifi.network" > "${TEST_ROOT}/tmp.network"
mv "${TEST_ROOT}/tmp.network" "${fixture}/${net}/60-punar-wifi.network"
expect_rejected wifi-v4 'Wi-Fi that takes NTP servers from DHCPv4'

fixture=$(make_fixture wired-v6)
awk '/^\[DHCPv6\]/ { v6 = 1 } !(v6 && $0 == "UseNTP=no") { print }' \
    "${fixture}/${net}/50-punar-dhcp.network" > "${TEST_ROOT}/tmp.network"
mv "${TEST_ROOT}/tmp.network" "${fixture}/${net}/50-punar-dhcp.network"
expect_rejected wired-v6 'wired networking that takes NTP servers from DHCPv6'

fixture=$(make_fixture dropin-ntp)
mkdir -p "${fixture}/${net}/60-punar-wifi.network.d"
printf '[DHCPv4]\nUseNTP=yes\n' > "${fixture}/${net}/60-punar-wifi.network.d/90-ntp.conf"
expect_rejected dropin-ntp 'a drop-in that turns DHCP NTP back on'

rules="mkosi.profiles/desktop/mkosi.extra/usr/share/polkit-1/rules.d"
fixture=$(make_fixture no-rule)
rm "${fixture}/${rules}/50-punar-clock.rules"
expect_rejected no-rule 'a desktop without the clock rule'

fixture=$(make_fixture rule-drops-ntp)
replace_line "${fixture}/${rules}/50-punar-clock.rules" \
    '    case "org.freedesktop.timedate1.set-ntp":' '    case "org.example.unrelated":'
expect_rejected rule-drops-ntp 'a clock rule that no longer refuses set-ntp'

fixture=$(make_fixture earlier-rule)
printf '%s\n' 'polkit.addRule(function (action, subject) {' \
    '    if (action.id == "org.freedesktop.timedate1.set-time") { return polkit.Result.YES; }' \
    '});' > "${fixture}/${rules}/10-punar-convenience.rules"
expect_rejected earlier-rule 'an earlier-sorting rule that allows set-time'

fixture=$(make_fixture lane-drops-tree)
replace_line "${fixture}/arm64/mkosi.profiles/desktop/mkosi.conf" \
    'ExtraTrees=../../../mkosi.profiles/desktop/mkosi.extra' 'ExtraTrees=mkosi.extra'
expect_rejected lane-drops-tree 'an arm64 desktop image without the shared tree'

system="mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system"
fixture=$(make_fixture unit-loses)
replace_line "${fixture}/${system}/punar-secrets.service" 'ProtectClock=yes' 'ProtectClock=no'
expect_rejected unit-loses 'punar-secrets.service without ProtectClock'

fixture=$(make_fixture new-unit)
printf '[Service]\nExecStart=/usr/bin/true\n' > "${fixture}/${system}/punar-new.service"
expect_rejected new-unit 'a new root service that made no clock decision'

fixture=$(make_fixture dropin-off)
mkdir -p "${fixture}/${system}/punar-agentd.service.d"
printf '[Service]\nProtectClock=no\n' > "${fixture}/${system}/punar-agentd.service.d/90-clock.conf"
expect_rejected dropin-off 'a drop-in that switches ProtectClock off'

fixture=$(make_fixture sys-time)
mkdir -p "${fixture}/${system}/punard.service.d"
printf '[Service]\nAmbientCapabilities=CAP_SYS_TIME\n' \
    > "${fixture}/${system}/punard.service.d/90-cap.conf"
expect_rejected sys-time 'a drop-in that hands a service CAP_SYS_TIME'

echo 'clock-trust-contract-test: PASS'
