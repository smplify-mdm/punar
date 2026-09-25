#!/usr/bin/env python3
"""Summarise what a guest said on the network (privacy lane, tools/bench/README.md).

    pcap_summary.py CAPTURE.pcap --guest-mac 52:54:00:be:0c:01 [--out SUMMARY.json]

The capture is taken on the guest's own NIC from power-on to the end of the
idle window (tcpdump on the tap, or QEMU's filter-dump on user networking).
This reads it with the standard library only and reports:

- every remote address the guest exchanged packets with, the bytes each way
  and the names DNS gave for it; which of those are on the internet;
- every DNS name it looked up, every TLS server name it sent (SNI, from the
  ClientHello, reassembled across segments), HTTP hosts and user agents;
- identifiers it volunteered: DHCP hostname/FQDN/vendor class, DHCPv6 FQDN,
  mDNS names, names sent to the whole link in LLMNR or mDNS questions, and
  whether its MAC address matched the one the harness gave it;
- the guest's own IPv4 and IPv6 addresses (DHCP, and IPv6 duplicate-address
  detection), which the exposure lane then scans.

QUIC's server name is encrypted in the Initial packet and is not decoded
here; QUIC flows are listed by address with any DNS name that resolved to it.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import struct
import sys
from collections import defaultdict
from pathlib import Path

ETH_IPV4, ETH_IPV6, ETH_VLAN, ETH_ARP = 0x0800, 0x86DD, 0x8100, 0x0806


def read_pcap(path: Path):
    """Yield (timestamp, linktype, frame bytes)."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
    else:
        raise ValueError("not a libpcap capture")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    linktype = struct.unpack(endian + "I", data[20:24])[0]
    offset = 24
    while offset + 16 <= len(data):
        sec, frac, incl, _orig = struct.unpack(endian + "IIII", data[offset:offset + 16])
        offset += 16
        frame = data[offset:offset + incl]
        offset += incl
        yield sec + frac / (1e9 if nano else 1e6), linktype, frame


def mac_text(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


def dns_name(message: bytes, offset: int, depth: int = 0) -> tuple[str, int]:
    labels = []
    jumped_to = None
    while offset < len(message):
        length = message[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if depth > 10 or offset + 1 >= len(message):
                break
            pointer = ((length & 0x3F) << 8) | message[offset + 1]
            name, _ = dns_name(message, pointer, depth + 1)
            labels.append(name)
            offset += 2
            jumped_to = offset
            break
        labels.append(message[offset + 1:offset + 1 + length].decode("ascii", errors="replace"))
        offset += 1 + length
    return ".".join(l for l in labels if l), (jumped_to if jumped_to is not None else offset)


DNS_TYPES = {1: "A", 28: "AAAA", 5: "CNAME", 12: "PTR", 16: "TXT", 33: "SRV", 65: "HTTPS", 64: "SVCB", 255: "ANY"}


def parse_dns(message: bytes):
    """Return (is_response, [(qname, qtype)], [(name, ip)])."""
    if len(message) < 12:
        return None
    _ident, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", message[:12])
    offset = 12
    questions, answers = [], []
    for _ in range(qd):
        name, offset = dns_name(message, offset)
        if offset + 4 > len(message):
            return None
        qtype = struct.unpack(">H", message[offset:offset + 2])[0]
        offset += 4
        questions.append((name.lower(), DNS_TYPES.get(qtype, str(qtype))))
    for _ in range(an):
        name, offset = dns_name(message, offset)
        if offset + 10 > len(message):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", message[offset:offset + 10])
        offset += 10
        rdata = message[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append((name.lower(), str(ipaddress.IPv4Address(rdata))))
        elif rtype == 28 and rdlen == 16:
            answers.append((name.lower(), str(ipaddress.IPv6Address(rdata))))
    return bool(flags & 0x8000), questions, answers


def parse_dhcp(payload: bytes):
    if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
        return None
    op = payload[0]
    chaddr = payload[28:34]
    yiaddr = payload[16:20]
    options = {}
    offset = 240
    while offset < len(payload):
        code = payload[offset]
        if code == 255:
            break
        if code == 0:
            offset += 1
            continue
        if offset + 1 >= len(payload):
            break
        length = payload[offset + 1]
        options[code] = payload[offset + 2:offset + 2 + length]
        offset += 2 + length
    return op, mac_text(chaddr), str(ipaddress.IPv4Address(yiaddr)), options


def parse_dhcpv6(payload: bytes):
    if len(payload) < 4:
        return None
    msg_type = payload[0]
    options = {}
    offset = 4
    while offset + 4 <= len(payload):
        code, length = struct.unpack(">HH", payload[offset:offset + 4])
        options[code] = payload[offset + 4:offset + 4 + length]
        offset += 4 + length
    return msg_type, options


def fqdn_from_wire(raw: bytes) -> str:
    labels, offset = [], 0
    while offset < len(raw):
        length = raw[offset]
        if length == 0:
            break
        labels.append(raw[offset + 1:offset + 1 + length].decode("ascii", errors="replace"))
        offset += 1 + length
    return ".".join(labels)


def tls_sni(buffer: bytes):
    """SNI from a (possibly multi-segment) TLS ClientHello, or None."""
    if len(buffer) < 5 or buffer[0] != 0x16 or buffer[1] != 0x03:
        return None
    record_len = struct.unpack(">H", buffer[3:5])[0]
    body = buffer[5:5 + record_len]
    # A ClientHello can span records; concatenate handshake fragments.
    offset = 5 + record_len
    while len(body) >= 4 and offset + 5 <= len(buffer) and buffer[offset] == 0x16:
        more = struct.unpack(">H", buffer[offset + 3:offset + 5])[0]
        body += buffer[offset + 5:offset + 5 + more]
        offset += 5 + more
    if len(body) < 4 or body[0] != 0x01:
        return None
    hs_len = int.from_bytes(body[1:4], "big")
    hello = body[4:4 + hs_len]
    if len(hello) < hs_len:
        return "incomplete"
    try:
        pos = 2 + 32
        sid_len = hello[pos]
        pos += 1 + sid_len
        cs_len = struct.unpack(">H", hello[pos:pos + 2])[0]
        pos += 2 + cs_len
        comp_len = hello[pos]
        pos += 1 + comp_len
        ext_total = struct.unpack(">H", hello[pos:pos + 2])[0]
        pos += 2
        end = pos + ext_total
        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack(">HH", hello[pos:pos + 4])
            ext = hello[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == 0 and len(ext) >= 5:
                name_len = struct.unpack(">H", ext[3:5])[0]
                return ext[5:5 + name_len].decode("ascii", errors="replace").lower()
    except (IndexError, struct.error):
        return None
    return ""


def scope(ip: str) -> str:
    address = ipaddress.ip_address(ip)
    if address.is_multicast or ip == "255.255.255.255":
        return "multicast"
    # fec0::/10 (deprecated site-local) is what QEMU's user networking uses
    # for its IPv6 gateway and resolver; Python counts it as global.
    if getattr(address, "is_site_local", False):
        return "local"
    if address.is_global:
        return "internet"
    return "local"


def summarize(path: Path, guest_mac: str | None) -> dict:
    guest_macs = set()
    configured = guest_mac.lower() if guest_mac else None
    if configured:
        guest_macs.add(configured)
    frames = list(read_pcap(path))
    # DHCP requests name the client hardware address: learn MACs first.
    parsed = []
    for ts, linktype, frame in frames:
        packet = decode(linktype, frame)
        if packet is None:
            continue
        parsed.append((ts, packet))
        if packet.get("udp") and packet["dport"] == 67 and packet["sport"] == 68:
            dhcp = parse_dhcp(packet["payload"])
            if dhcp and dhcp[0] == 1:
                guest_macs.add(dhcp[1])
    observed_macs = set()
    guest_v4, guest_v6 = set(), set()
    destinations = defaultdict(lambda: {"bytes_out": 0, "bytes_in": 0, "packets": 0, "protocols": set()})
    dns_queries = defaultdict(int)
    name_for_ip = defaultdict(set)
    sni = defaultdict(int)
    http = []
    identifiers = {"dhcp_hostname": set(), "dhcp_fqdn": set(), "dhcp_vendor_class": set(),
                   "dhcp_client_id": set(), "dhcpv6_fqdn": set(), "dhcpv6_duid": set(),
                   "mdns_names": set(), "link_local_name_queries": set(), "http_user_agents": set()}
    ntp = set()
    tcp_buffers: dict = {}
    first_ts = parsed[0][0] if parsed else 0.0
    last_ts = parsed[-1][0] if parsed else 0.0
    for _ts, p in parsed:
        outbound = p["src_mac"] in guest_macs
        inbound = p["dst_mac"] in guest_macs
        if not (outbound or inbound):
            continue
        if outbound:
            observed_macs.add(p["src_mac"])
        if "src" not in p:
            continue
        local_ip, remote_ip = (p["src"], p["dst"]) if outbound else (p["dst"], p["src"])
        if outbound and local_ip not in ("0.0.0.0", "::"):
            (guest_v4 if p["version"] == 4 else guest_v6).add(local_ip)
        proto = "tcp" if p.get("tcp") else "udp" if p.get("udp") else p.get("proto_name", "ip")
        port = p.get("dport") if outbound else p.get("sport")
        entry = destinations[remote_ip]
        entry["packets"] += 1
        entry["bytes_out" if outbound else "bytes_in"] += p["length"]
        if port is not None:
            entry["protocols"].add(f"{proto}/{port}")
        else:
            entry["protocols"].add(proto)
        if p.get("icmp6_type") == 135 and outbound and p["src"] == "::" and p.get("nd_target"):
            guest_v6.add(p["nd_target"])
        if p.get("udp"):
            sport, dport, payload = p["sport"], p["dport"], p["payload"]
            if 53 in (sport, dport) or 5353 in (sport, dport) or 5355 in (sport, dport):
                dns = parse_dns(payload)
                if dns:
                    is_response, questions, answers = dns
                    if outbound and not is_response and dport == 53:
                        for name, qtype in questions:
                            dns_queries[(name, qtype)] += 1
                    # LLMNR and mDNS questions go to everyone on the link;
                    # a name sent there (often the machine's own, probed for
                    # conflicts) is an identifier, not a lookup.
                    if outbound and not is_response and dport in (5355, 5353):
                        for name, _qtype in questions:
                            identifiers["link_local_name_queries"].add(name)
                    if outbound and 5353 in (sport, dport):
                        for name, _ in answers:
                            identifiers["mdns_names"].add(name)
                        if is_response:
                            for name, _qtype in questions:
                                identifiers["mdns_names"].add(name)
                    for name, ip in answers:
                        name_for_ip[ip].add(name)
            elif outbound and dport == 67:
                dhcp = parse_dhcp(payload)
                if dhcp:
                    options = dhcp[3]
                    if 12 in options:
                        identifiers["dhcp_hostname"].add(options[12].decode("ascii", errors="replace"))
                    if 81 in options and len(options[81]) > 3:
                        raw = options[81][3:]
                        identifiers["dhcp_fqdn"].add(fqdn_from_wire(raw) if options[81][0] & 0x04 else raw.decode("ascii", errors="replace"))
                    if 60 in options:
                        identifiers["dhcp_vendor_class"].add(options[60].decode("ascii", errors="replace"))
                    if 61 in options:
                        identifiers["dhcp_client_id"].add(options[61].hex())
            elif inbound and dport == 68:
                dhcp = parse_dhcp(payload)
                if dhcp and dhcp[0] == 2 and dhcp[2] != "0.0.0.0":
                    guest_v4.add(dhcp[2])
            elif outbound and dport == 547:
                v6 = parse_dhcpv6(payload)
                if v6:
                    options = v6[1]
                    if 39 in options and len(options[39]) > 1:
                        identifiers["dhcpv6_fqdn"].add(fqdn_from_wire(options[39][1:]))
                    if 1 in options:
                        identifiers["dhcpv6_duid"].add(options[1].hex())
            elif outbound and dport == 123:
                ntp.add(remote_ip)
        if p.get("tcp") and outbound and p["payload"]:
            key = (p["src"], p["sport"], p["dst"], p["dport"])
            buffer = tcp_buffers.get(key)
            if buffer is None:
                buffer = tcp_buffers[key] = {"data": b"", "done": False}
            if not buffer["done"] and len(buffer["data"]) < 65536:
                buffer["data"] += p["payload"]
                if buffer["data"][:1] == b"\x16":
                    name = tls_sni(buffer["data"])
                    if name not in (None, "incomplete"):
                        buffer["done"] = True
                        if name:
                            sni[(name, p["dst"])] += 1
                    elif name is None:
                        buffer["done"] = True
                elif buffer["data"][:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                    head = buffer["data"].split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
                    host = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("host:")), "")
                    agent = next((h.split(":", 1)[1].strip() for h in head[1:] if h.lower().startswith("user-agent:")), "")
                    http.append({"host": host, "request": head[0][:200], "user_agent": agent})
                    if agent:
                        identifiers["http_user_agents"].add(agent)
                    buffer["done"] = True
                else:
                    buffer["done"] = True
    rows = []
    for ip, entry in destinations.items():
        rows.append({
            "ip": ip,
            "scope": scope(ip),
            "names": sorted(name_for_ip.get(ip, set())),
            "bytes_out": entry["bytes_out"],
            "bytes_in": entry["bytes_in"],
            "packets": entry["packets"],
            "protocols": sorted(entry["protocols"]),
        })
    rows.sort(key=lambda r: (r["scope"] != "internet", -(r["bytes_out"] + r["bytes_in"])))
    internet = [r for r in rows if r["scope"] == "internet"]
    names = sorted({name for (name, _t) in dns_queries} | {name for (name, _d) in sni})
    found = {k: sorted(v) for k, v in identifiers.items()}
    return {
        "schema": "punar-bench-privacy/1",
        "packets": len(parsed),
        "duration_s": round(last_ts - first_ts, 1),
        "configured_mac": configured,
        "guest_macs_observed": sorted(observed_macs),
        "mac_matches_configured": (observed_macs <= {configured}) if configured else None,
        "guest_addresses": {"ipv4": sorted(guest_v4), "ipv6": sorted(guest_v6)},
        "destinations": rows,
        "internet_destination_count": len(internet),
        "internet_bytes_out": sum(r["bytes_out"] for r in internet),
        "internet_bytes_in": sum(r["bytes_in"] for r in internet),
        "dns_queries": [{"name": n, "type": t, "count": c} for (n, t), c in sorted(dns_queries.items())],
        "tls_sni": [{"name": n, "dst": d, "count": c} for (n, d), c in sorted(sni.items())],
        "http": http,
        "distinct_names": names,
        "distinct_name_count": len(names),
        "ntp_servers": sorted(ntp),
        "identifiers": found,
        "identifier_kinds_sent": sorted(k for k, v in found.items() if v and k != "dhcp_client_id"),
    }


def decode(linktype: int, frame: bytes) -> dict | None:
    if linktype == 1:
        if len(frame) < 14:
            return None
        dst_mac, src_mac = mac_text(frame[0:6]), mac_text(frame[6:12])
        ethertype = struct.unpack(">H", frame[12:14])[0]
        offset = 14
        if ethertype == ETH_VLAN and len(frame) >= 18:
            ethertype = struct.unpack(">H", frame[16:18])[0]
            offset = 18
    else:
        return None
    packet = {"src_mac": src_mac, "dst_mac": dst_mac, "length": len(frame)}
    body = frame[offset:]
    if ethertype == ETH_IPV4 and len(body) >= 20:
        ihl = (body[0] & 0x0F) * 4
        proto = body[9]
        packet.update(version=4, src=str(ipaddress.IPv4Address(body[12:16])),
                      dst=str(ipaddress.IPv4Address(body[16:20])))
        transport = body[ihl:]
    elif ethertype == ETH_IPV6 and len(body) >= 40:
        proto = body[6]
        packet.update(version=6, src=str(ipaddress.IPv6Address(body[8:24])),
                      dst=str(ipaddress.IPv6Address(body[24:40])))
        transport = body[40:]
        while proto in (0, 43, 60) and len(transport) >= 8:
            proto, transport = transport[0], transport[(transport[1] + 1) * 8:]
        if proto == 44 and len(transport) >= 8:
            proto, transport = transport[0], transport[8:]
    else:
        return packet
    if proto == 6 and len(transport) >= 20:
        data_offset = (transport[12] >> 4) * 4
        packet.update(tcp=True, sport=struct.unpack(">H", transport[0:2])[0],
                      dport=struct.unpack(">H", transport[2:4])[0], payload=transport[data_offset:])
    elif proto == 17 and len(transport) >= 8:
        packet.update(udp=True, sport=struct.unpack(">H", transport[0:2])[0],
                      dport=struct.unpack(">H", transport[2:4])[0], payload=transport[8:])
    elif proto == 58 and len(transport) >= 4:
        packet.update(proto_name="icmp6", icmp6_type=transport[0])
        if transport[0] in (135, 136) and len(transport) >= 24:
            packet["nd_target"] = str(ipaddress.IPv6Address(transport[8:24]))
    elif proto == 1:
        packet.update(proto_name="icmp")
    else:
        packet.update(proto_name=f"ip{proto}")
    return packet


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("capture", type=Path)
    parser.add_argument("--guest-mac")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    summary = summarize(args.capture, args.guest_mac)
    text = json.dumps(summary, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
