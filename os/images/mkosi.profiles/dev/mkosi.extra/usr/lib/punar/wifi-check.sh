#!/bin/sh
# Punar wireless exercise — runs as ROOT.
#
# WHY ROOT AND NOT THE SURFACES CHECK. Wi-Fi is a system concern, not a user-
# session one: loading the simulator needs modprobe and talking to iwd needs a
# D-Bus policy an unprivileged user does not hold. Put in the User=punar
# surfaces check this would have failed to load the module, honestly reported
# "unavailable", and exercised nothing — a false negative wearing an honest
# label, which is worse than no check because it looks like coverage.
#
# THE HARDWARE IS SIMULATED, AND THAT IS THE POINT. The CI VM has no wireless
# card, so wireless would otherwise be another reasoned-about-never-executed
# path, exactly like DHCP is today. mac80211_hwsim is the kernel's own wireless
# simulator and creates real cfg80211 interfaces that iwd and systemd-networkd
# cannot tell from hardware. If it loads, everything here is a genuine exercise
# of the shipped configuration. If it does not, that is REPORTED and nothing is
# claimed.
#
# Verdict: PUNAR_WIFI_OK / PUNAR_WIFI_FAIL, last line of
# /run/punar/wifi-report.txt. Always exits 0; tools/boot-test.sh gates.
# shellcheck disable=SC2329
set -u

REPORT=/run/punar/wifi-report.txt
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
finish() {
    if [ "${FAILED}" -eq 0 ]; then note "PUNAR_WIFI_OK"; else note "PUNAR_WIFI_FAIL"; fi
    cat "${REPORT}"
    exit 0
}

note "# Punar wireless exercise — $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- 1. the shipped privacy posture, asserted whatever the hardware does -----
# These are the settings that make a laptop untrackable between networks, and a
# silent typo in one is invisible until somebody is followed. Asserted first so
# they are covered even on a kernel with no simulator.
check_eq "iwd randomizes its MAC per network" "1" \
    "$(grep -c '^AddressRandomization=network' /etc/iwd/main.conf 2>/dev/null || echo 0)"
for nf in /usr/lib/systemd/network/50-punar-dhcp.network \
          /usr/lib/systemd/network/60-punar-wifi.network; do
    check_eq "$(basename "${nf}") does not announce the hostname" "1" \
        "$(grep -c '^SendHostname=no' "${nf}" 2>/dev/null || echo 0)"
    check_eq "$(basename "${nf}") uses RFC 4941 temporary addresses" "1" \
        "$(grep -c '^IPv6PrivacyExtensions=yes' "${nf}" 2>/dev/null || echo 0)"
done

# --- 2. a wireless interface, simulated ------------------------------------
if [ -e /sys/class/ieee80211 ] || modprobe mac80211_hwsim 2>/dev/null; then
    wifi_dev=""
    wi=0
    while [ "${wi}" -lt 20 ]; do
        wifi_dev="$(find /sys/class/net -maxdepth 1 -name 'wl*' -exec basename {} \; 2>/dev/null | head -1)"
        [ -n "${wifi_dev}" ] && break
        wi=$((wi + 1))
        sleep 1
    done
else
    wifi_dev=""
    note "info mac80211_hwsim unavailable in this kernel — WIRELESS IS NOT EXERCISED and nothing about it is claimed"
    finish
fi

if [ -z "${wifi_dev}" ]; then
    note "info simulator loaded but no wl* interface appeared within 20s — wireless not exercised"
    finish
fi
note "ok   a wireless interface exists (${wifi_dev}, simulated by mac80211_hwsim)"

# --- 3. iwd is running and has adopted it -----------------------------------
# Running, not merely installed: the unit is enabled by a vendor .wants symlink
# and the mkosi preset wipe has silently broken exactly that before (greetd).
if systemctl is-active --quiet iwd 2>/dev/null; then
    note "ok   iwd is running"
else
    note "FAIL iwd is not active — the vendor .wants symlink did not take"
    FAILED=1
fi

iwd_sees() { iwctl device list 2>/dev/null | grep -q "$1"; }
di=0
adopted=0
while [ "${di}" -lt 20 ]; do
    if iwd_sees "${wifi_dev}"; then adopted=1; break; fi
    di=$((di + 1))
    sleep 1
done
if [ "${adopted}" -eq 1 ]; then
    note "ok   iwd adopted ${wifi_dev} (it would associate on real hardware)"
else
    note "FAIL iwd does not list ${wifi_dev} — association would never happen"
    FAILED=1
fi

# --- 4. networkd matched the WIRELESS file, not the ethernet one ------------
# This is the assertion that catches a Type= typo, which would otherwise leave
# a laptop associated and permanently address-less.
mi=0
matched=0
while [ "${mi}" -lt 20 ]; do
    if networkctl status "${wifi_dev}" 2>/dev/null | grep -q '60-punar-wifi\.network'; then
        matched=1
        break
    fi
    mi=$((mi + 1))
    sleep 1
done
if [ "${matched}" -eq 1 ]; then
    note "ok   networkd applied 60-punar-wifi.network to ${wifi_dev}"
else
    note "FAIL networkd did not apply 60-punar-wifi.network to ${wifi_dev} — associated but never addressed"
    FAILED=1
fi

networkctl status "${wifi_dev}" > /run/punar/wifi-link.txt 2>&1 || true
iwctl device list > /run/punar/wifi-devices.txt 2>&1 || true

finish
