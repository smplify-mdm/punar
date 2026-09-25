#!/usr/bin/env python3
"""Reachable-port scan of a guest from the host (exposure lane, tools/bench/README.md).

    portscan.py --target 192.168.77.50 [--target fe80::1%benchtap0 ...] --out SCAN.json

With nmap (and root through `sudo -n`): a SYN scan of all 65,535 TCP ports
and a UDP scan of the 200 most common ports, per address. Without nmap: a
TCP connect scan of every port from this process, and no UDP verdicts
(telling a silent UDP port from a filtered one needs raw sockets); the
result says which method ran. Only ports that answered as open are counted
as open. UDP ports that never answered are "open|filtered" and are reported
separately, never as open.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def parse_nmap_xml(text: str) -> dict:
    root = ET.fromstring(text)
    out = {"tcp_open": [], "udp_open": [], "udp_open_filtered": 0, "tcp_filtered_or_closed": 0}
    for port in root.iter("port"):
        proto = port.get("protocol")
        number = int(port.get("portid"))
        state = port.find("state").get("state")
        service = port.find("service")
        name = service.get("name") if service is not None else None
        if proto == "tcp" and state == "open":
            out["tcp_open"].append({"port": number, "service": name})
        elif proto == "udp" and state == "open":
            out["udp_open"].append({"port": number, "service": name})
        elif proto == "udp" and state == "open|filtered":
            out["udp_open_filtered"] += 1
    for extra in root.iter("extraports"):
        if extra.get("state") in ("filtered", "closed"):
            out["tcp_filtered_or_closed"] += int(extra.get("count", "0"))
        elif extra.get("state") == "open|filtered":
            out["udp_open_filtered"] += int(extra.get("count", "0"))
    return out


def nmap_scan(target: str, udp_ports: int) -> dict:
    base = ["sudo", "-n", "nmap", "-n", "-Pn", "-T4", "--max-retries", "1", "-oX", "-"]
    if ":" in target:
        base.append("-6")
        if "%" in target:
            base += ["-e", target.split("%", 1)[1]]
    tcp = subprocess.run(base + ["-sS", "-p-", "--min-rate", "2000", target],
                         capture_output=True, text=True, timeout=900, check=False)
    udp = subprocess.run(base + ["-sU", "--top-ports", str(udp_ports), target],
                         capture_output=True, text=True, timeout=900, check=False)
    if tcp.returncode != 0 or udp.returncode != 0:
        raise RuntimeError((tcp.stderr or udp.stderr).strip()[:500])
    tcp_result = parse_nmap_xml(tcp.stdout)
    udp_result = parse_nmap_xml(udp.stdout)
    return {
        "method": "nmap",
        "tcp_ports_scanned": 65535,
        "udp_ports_scanned": udp_ports,
        "tcp_open": tcp_result["tcp_open"],
        "udp_open": udp_result["udp_open"],
        "udp_open_filtered": udp_result["udp_open_filtered"],
    }


async def _connect_scan(host: str, ports: range, concurrency: int, timeout: float) -> list[int]:
    semaphore = asyncio.Semaphore(concurrency)
    open_ports = []

    async def probe(port: int) -> None:
        async with semaphore:
            try:
                _reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            except (OSError, asyncio.TimeoutError):
                return
            open_ports.append(port)
            writer.close()

    await asyncio.gather(*(probe(p) for p in ports))
    return sorted(open_ports)


def connect_scan(target: str) -> dict:
    ports = asyncio.run(_connect_scan(target, range(1, 65536), 1000, 1.5))
    return {
        "method": "tcp-connect (no nmap: UDP not scanned)",
        "tcp_ports_scanned": 65535,
        "udp_ports_scanned": 0,
        "tcp_open": [{"port": p, "service": None} for p in ports],
        "udp_open": [],
        "udp_open_filtered": None,
    }


def scan(targets: list[str], udp_ports: int = 200) -> dict:
    use_nmap = shutil.which("nmap") is not None
    results = {}
    for target in targets:
        try:
            results[target] = nmap_scan(target, udp_ports) if use_nmap else connect_scan(target)
        except (RuntimeError, subprocess.TimeoutExpired, OSError) as error:
            results[target] = {"method": "failed", "error": str(error)}
    scanned = [r for r in results.values() if r.get("method") != "failed"]
    return {
        "schema": "punar-bench-scan/1",
        "targets": results,
        "open_tcp_total": sum(len(r["tcp_open"]) for r in scanned),
        "open_udp_total": sum(len(r["udp_open"]) for r in scanned),
        "complete": len(scanned) == len(targets) and bool(targets),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--udp-top-ports", type=int, default=200)
    parser.add_argument("--nmap-xml", type=Path, action="append", default=[],
                        help="parse saved nmap -oX output instead of scanning (tests)")
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    if args.nmap_xml:
        result = {str(p): parse_nmap_xml(p.read_text()) for p in args.nmap_xml}
    else:
        result = scan(args.target, args.udp_top_ports)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
