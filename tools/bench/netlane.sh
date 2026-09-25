#!/usr/bin/env bash
# The benchmark's own network segment (tools/bench/README.md, "Network lane").
#
#   sudo tools/bench/netlane.sh up OWNER_UID     # tap + DHCP/DNS + IPv6 RA + NAT
#   sudo tools/bench/netlane.sh down
#
# One tap device, benchtap0, owned by OWNER_UID so QEMU opens it without
# root. dnsmasq on the tap hands the guest 192.168.77.50-99 by DHCP, forwards
# DNS to the host's resolver and advertises the ULA prefix fd77:77:77:77::/64
# (router advertisements, SLAAC), so the guest has a link-local and a
# routable-looking IPv6 address to be scanned on. IPv4 is NATed out of the
# runner's default route; IPv6 has no route out. 192.168.0.0/16 is used on
# purpose: firewalls that trust "the LAN" usually trust that range, which is
# what a scan from a neighbour on a home network looks like.
#
# The host side of the tap is 192.168.77.1. Everything is labelled
# "bench-netlane" and removed by `down`.
set -euo pipefail

TAP="${BENCH_TAP:-benchtap0}"
STATE="${BENCH_NETLANE_STATE:-/run/bench-netlane}"
PREFIX4=192.168.77
PREFIX6=fd77:77:77:77
COMMENT=bench-netlane

die() {
    echo "netlane: $*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || die "must run as root"

rules() {
    # rules ACTION -- apply or delete every rule this lane owns.
    action=$1
    uplink=$2
    iptables -t nat "${action}" POSTROUTING -s "${PREFIX4}.0/24" -o "${uplink}" -j MASQUERADE \
        -m comment --comment "${COMMENT}"
    iptables "${action}" FORWARD -i "${TAP}" -o "${uplink}" -j ACCEPT -m comment --comment "${COMMENT}"
    iptables "${action}" FORWARD -i "${uplink}" -o "${TAP}" -m conntrack --ctstate RELATED,ESTABLISHED \
        -j ACCEPT -m comment --comment "${COMMENT}"
}

case "${1:-}" in
    up)
        owner="${2:-${SUDO_UID:-}}"
        [ -n "${owner}" ] || die "usage: netlane.sh up OWNER_UID"
        for tool in ip iptables dnsmasq; do
            command -v "${tool}" >/dev/null 2>&1 || die "${tool} is required"
        done
        uplink="$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')"
        [ -n "${uplink}" ] || die "no default route"
        upstream="$(awk '$1 == "nameserver" {print $2; exit}' /run/systemd/resolve/resolv.conf 2>/dev/null || true)"
        [ -n "${upstream}" ] || upstream="$(awk '$1 == "nameserver" {print $2; exit}' /etc/resolv.conf)"
        mkdir -p "${STATE}"
        ip tuntap add dev "${TAP}" mode tap user "${owner}"
        ip addr add "${PREFIX4}.1/24" dev "${TAP}"
        ip -6 addr add "${PREFIX6}::1/64" dev "${TAP}" nodad
        ip link set "${TAP}" up
        sysctl -q -w net.ipv4.ip_forward=1
        # Docker on hosted runners sets FORWARD to DROP; insert ahead of it.
        rules -I "${uplink}"
        dnsmasq --conf-file=/dev/null --interface="${TAP}" --bind-interfaces --except-interface=lo \
            --dhcp-range="${PREFIX4}.50,${PREFIX4}.99,255.255.255.0,12h" \
            --dhcp-range="${PREFIX6}::,ra-stateless,64,12h" --enable-ra \
            --dhcp-leasefile="${STATE}/leases" --pid-file="${STATE}/dnsmasq.pid" \
            --log-queries --log-dhcp --log-facility="${STATE}/dnsmasq.log" \
            --no-resolv --no-hosts --server="${upstream}"
        chmod 0644 "${STATE}/leases" "${STATE}/dnsmasq.log" 2>/dev/null || true
        {
            echo "TAP=${TAP}"
            echo "UPLINK=${uplink}"
            echo "GATEWAY4=${PREFIX4}.1"
            echo "PREFIX6=${PREFIX6}::/64"
            echo "LEASES=${STATE}/leases"
            echo "DNS_LOG=${STATE}/dnsmasq.log"
        } > "${STATE}/env"
        echo "netlane: ${TAP} up (${PREFIX4}.0/24, ${PREFIX6}::/64) via ${uplink}, DNS to ${upstream}"
        ;;
    down)
        if [ -r "${STATE}/dnsmasq.pid" ]; then
            kill "$(cat "${STATE}/dnsmasq.pid")" 2>/dev/null || true
        fi
        if [ -r "${STATE}/env" ]; then
            uplink="$(awk -F= '$1 == "UPLINK" {print $2}' "${STATE}/env")"
            rules -D "${uplink}" 2>/dev/null || true
        fi
        ip link del "${TAP}" 2>/dev/null || true
        echo "netlane: ${TAP} down"
        ;;
    *)
        die "usage: netlane.sh up OWNER_UID | down"
        ;;
esac
