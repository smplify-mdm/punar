#!/usr/bin/env python3
"""Unit tests for the benchmark harness's host side (tools/bench).

Run by tests/performance/bench-summarize-test.sh. Standard library only.
Covers the D1 rule and the report (never a "win" without it, losses always
printed), the parser's edge cases, the privacy summary on a synthetic
capture, nmap parsing, the dispatch plan, the Omarchy CIDATA rendering and
stock restore, and that the release image's test account is still where the
harness reads it.
"""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "tools" / "bench"))

import bench_parse  # noqa: E402
import bench_plan  # noqa: E402
import bench_report  # noqa: E402
import pcap_summary  # noqa: E402
import portscan  # noqa: E402


def result(lane, shape, index, used, *, valid=True, login="punar-greeter", encryption="none",
           available=3000.0, boot_initrd=2.0, reasons=None):
    return {
        "schema": "punar-bench-run/1",
        "meta": {"lane": lane, "shape_mib": shape, "run_id": f"{lane}-{shape}-{index}", "login": login,
                 "disk_encryption": encryption, "net": "tap", "accel": "kvm",
                 "graphics": "virtio-vga, no GPU acceleration (llvmpipe)"},
        "idle": {"memory": {"used_mean_mib": used, "mem_available_mean_mib": available,
                            "thp_mode": "always", "min_free_kbytes": 67584}},
        "boot": {"initrd_s": boot_initrd},
        "host": {"cpu_model": "Test CPU"},
        "validity": {"valid_for_claims": valid, "reasons": reasons or ([] if valid else ["host steal 3% > 2%"])},
        "_path": f"/x/{lane}/{shape}/{index}/result.json",
    }


class D1RuleTest(unittest.TestCase):
    def compare(self, punar, rival, metric="idle_used_mean", **rival_kwargs):
        runs = [result("punar", 8192, i, v) for i, v in enumerate(punar)]
        runs += [result("omarchy", 8192, i, v, **rival_kwargs) for i, v in enumerate(rival)]
        report = bench_report.aggregate(runs, "punar")
        return report, next(c for c in report["comparisons"] if c["metric"] == metric)

    def test_win_needs_better_median_and_disjoint_ranges(self):
        _, c = self.compare([900, 905, 910, 912, 915], [1000, 1005, 1010, 1015, 1020])
        self.assertEqual(c["verdict"], "WIN")

    def test_overlapping_ranges_are_no_claim_even_with_better_median(self):
        _, c = self.compare([900, 905, 910, 912, 1001], [1000, 1005, 1010, 1015, 1020])
        self.assertEqual(c["verdict"], "NO_CLAIM")
        self.assertIn("overlap", c["reason"])

    def test_fewer_than_five_valid_runs_is_no_claim(self):
        _, c = self.compare([900, 905, 910, 912], [1000, 1005, 1010, 1015, 1020])
        self.assertEqual(c["verdict"], "NO_CLAIM")
        self.assertIn("fewer than 5", c["reason"])

    def test_invalid_runs_do_not_count(self):
        runs = [result("punar", 8192, i, v) for i, v in enumerate([900, 905, 910, 912])]
        runs.append(result("punar", 8192, 9, 800, valid=False))
        runs += [result("omarchy", 8192, i, v) for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        report = bench_report.aggregate(runs, "punar")
        c = next(c for c in report["comparisons"] if c["metric"] == "idle_used_mean")
        self.assertEqual(c["verdict"], "NO_CLAIM")
        self.assertEqual(c["subject"]["n"], 4)
        text = bench_report.markdown(report, "t")
        self.assertIn("excluded `punar-8192-9`: host steal 3% > 2%", text)

    def test_loss_is_published(self):
        report, c = self.compare([1000, 1005, 1010, 1015, 1020], [900, 905, 910, 912, 915])
        self.assertEqual(c["verdict"], "LOSS")
        text = bench_report.markdown(report, "t")
        losses = text.split("## Losses (published with the wins)")[1].split("## Wins")[0]
        self.assertIn("**LOSS** Idle RAM used (MemTotal - MemAvailable), mean at 8192 MiB vs omarchy", losses)
        self.assertNotIn("**WIN**", text)
        self.assertEqual(len(bench_report.to_json(report)["losses"]), 1)

    def test_worse_median_without_a_loss_is_still_printed(self):
        report, c = self.compare([1000, 1005, 1010, 1015, 1016], [900, 905, 910, 1012, 1030])
        self.assertEqual(c["verdict"], "NO_CLAIM")
        text = bench_report.markdown(report, "t")
        self.assertIn("Worse medians that are not a D1 loss", text)

    def test_higher_is_better_metric(self):
        runs = [result("punar", 4096, i, 900, available=v) for i, v in enumerate([3100, 3110, 3120, 3130, 3140])]
        runs += [result("omarchy", 4096, i, 900, available=v) for i, v in enumerate([2900, 2910, 2920, 2930, 2940])]
        report = bench_report.aggregate(runs, "punar")
        c = next(c for c in report["comparisons"] if c["metric"] == "idle_available")
        self.assertEqual(c["verdict"], "WIN")

    def test_boot_is_not_comparable_when_login_differs(self):
        _, c = self.compare([900] * 5, [1000] * 5, metric="boot_initrd", login="luks-autologin",
                            encryption="luks2")
        self.assertEqual(c["verdict"], "NOT_COMPARABLE")
        self.assertIn("differs", c["reason"])

    def test_wins_only_ever_come_from_the_rule(self):
        report, _ = self.compare([900, 905, 910, 912, 915], [1000, 1005, 1010, 1015, 1020])
        text = bench_report.markdown(report, "t")
        wins = [c for c in report["comparisons"] if c["verdict"] == "WIN"]
        self.assertEqual(text.count("**WIN**"), len(wins))

    def test_informational_report_never_judges(self):
        runs = [result("punar", 8192, i, v) for i, v in enumerate([900, 905, 910, 912, 915])]
        runs += [result("omarchy", 8192, i, v, valid=False) for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        report = bench_report.aggregate(runs, "punar", include_invalid=True)
        c = next(c for c in report["comparisons"] if c["metric"] == "idle_used_mean")
        self.assertEqual(c["verdict"], "NO_CLAIM")
        self.assertIn("Nothing here is a result", bench_report.markdown(report, "t"))

    def test_subject_only_makes_no_claim_and_writes_a_baseline(self):
        runs = [result("punar", 8192, i, v) for i, v in enumerate([900, 905, 910, 912, 915])]
        report = bench_report.aggregate(runs, "punar")
        text = bench_report.markdown(report, "t")
        self.assertIn("nothing was compared and nothing is claimed", text)
        self.assertNotIn("**WIN**", text)
        baseline = bench_report.baseline(report, "punar")
        self.assertEqual(baseline["shapes"]["8192"]["metrics"]["idle_used_mean"]["median"], 910)
        self.assertEqual(baseline["shapes"]["8192"]["metrics"]["idle_used_mean"]["iqr"], 7)


def counters(phase, uptime, cpu, intr, disk_sectors, cgroups):
    return [
        {"type": "counters", "phase": phase, "uptime": uptime,
         "stat": {"cpus": {"cpu": cpu, "cpu0": cpu}, "intr": intr, "ctxt": 0},
         "diskstats": {"254:0": {"name": "vda", "wr_sectors": disk_sectors}}, "interrupts": [], "vmstat": {},
         "pressure": {}},
        {"type": "cgroups", "phase": phase, "uptime": uptime, "list": cgroups},
    ]


class ParseTest(unittest.TestCase):
    def base(self, end_cgroups, start_cgroups):
        records = [
            {"type": "facts", "canonical": "yes", "samples": "1", "probe_cgroup": "/system.slice/bench-probe.service"},
            {"type": "devices", "list": [{"kind": "disk", "dev": "254:0"}, {"kind": "virtual", "dev": "252:0"}]},
            {"type": "window_start"},
            *counters("start", 100.0, [0] * 10, 0, 0, start_cgroups),
            {"type": "sample", "i": "0", "meminfo": {"MemTotal": "8000000", "MemAvailable": "7000000"},
             "probe": {}},
            *counters("end", 400.0, [100, 0, 0, 11900, 0, 0, 0, 0, 0, 0], 3000, 1000, end_cgroups),
            {"type": "window_end"},
        ]
        return bench_parse.parse_run(records, {"meta": {"accel": "kvm"}})

    def test_diskstats_fallback_when_the_root_has_no_io_stat(self):
        cg = [{"p": "/"}, {"p": "/system.slice", "io": {"254:0": [0, 1000, 0, 0]}}]
        writes = self.base(cg, [{"p": "/"}, {"p": "/system.slice", "io": {"254:0": [0, 0, 0, 0]}}])["idle"]["writes"]
        self.assertEqual(writes["device_source"], "diskstats")
        self.assertEqual(writes["device_bytes"], 512000)
        self.assertEqual(writes["kernel_fs_remainder_bytes"], 511000)

    def test_new_cgroup_counts_from_zero_and_remainder_never_negative(self):
        start = [{"p": "/", "io": {"254:0": [0, 0, 0, 0]}}]
        end = [{"p": "/", "io": {"254:0": [0, 4096, 0, 0]}},
               {"p": "/user.slice", "io": {"254:0": [0, 8192, 0, 0], "252:0": [0, 999999, 0, 0]}}]
        writes = self.base(end, start)["idle"]["writes"]
        self.assertEqual(writes["top_level_cgroups_bytes"], 8192)
        self.assertEqual(writes["kernel_fs_remainder_bytes"], 0)
        self.assertTrue(any("lazy flush" in n for n in writes["notes"]))

    def test_partial_last_line_is_ignored(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            handle.write('{"type":"probe_start"}\n{"type":"sam')
        try:
            self.assertEqual(bench_parse.load_stream(Path(handle.name)), [{"type": "probe_start"}])
        finally:
            os.unlink(handle.name)

    def test_cpu_and_steal(self):
        cpu = self.base([{"p": "/"}], [{"p": "/"}])["idle"]["cpu"]
        self.assertEqual(cpu["window_s"], 300.0)
        self.assertAlmostEqual(cpu["system_pct"], 100 * 100 / 12000, places=3)
        self.assertEqual(cpu["interrupts_per_s"], 10.0)


# ---- a synthetic capture -------------------------------------------------------------

GUEST = bytes.fromhex("525400be0c01")
ROUTER = bytes.fromhex("525400000001")


def ipv4(src, dst, proto, payload):
    header = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                         ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    return header + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, payload):
    return struct.pack(">HHIIBBHHH", sport, dport, 1, 0, 5 << 4, 0x18, 65535, 0, 0) + payload


def ether(src, dst, kind, payload):
    return dst + src + struct.pack(">H", kind) + payload


def dns_query(name, qtype=1, response_ip=None):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    if response_ip is None:
        return struct.pack(">HHHHHH", 1, 0x0100, 1, 0, 0, 0) + labels + struct.pack(">HH", qtype, 1)
    answer = struct.pack(">HHHIH", 0xC00C, 1, 1, 60, 4) + ipaddress.IPv4Address(response_ip).packed
    return struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0) + labels + struct.pack(">HH", qtype, 1) + answer


def client_hello(host):
    name = host.encode()
    sni = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    extensions = struct.pack(">HH", 0, len(sni)) + sni + struct.pack(">HH", 0x15, 1600) + b"\x00" * 1600
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def dhcp_discover(hostname):
    fixed = bytes([1, 1, 6, 0]) + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 16 + GUEST + b"\x00" * 10
    fixed += b"\x00" * 192
    options = b"\x63\x82\x53\x63" + bytes([53, 1, 1, 12, len(hostname)]) + hostname.encode() + b"\xff"
    return fixed + options


def write_pcap(path, frames):
    with open(path, "wb") as handle:
        handle.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, frame in enumerate(frames):
            handle.write(struct.pack("<IIII", 1000 + index, 0, len(frame), len(frame)))
            handle.write(frame)


class PrivacyTest(unittest.TestCase):
    def test_capture_summary(self):
        hello = client_hello("telemetry.example.com")
        ns_target = ipaddress.IPv6Address("fd77:77:77:77::1234").packed
        ns = bytes([135, 0, 0, 0, 0, 0, 0, 0]) + ns_target
        v6 = struct.pack(">IHBB", 0x60000000, len(ns), 58, 255) + b"\x00" * 16 + \
            ipaddress.IPv6Address("ff02::1:ff00:1234").packed + ns
        frames = [
            ether(GUEST, b"\xff" * 6, 0x0800, ipv4("0.0.0.0", "255.255.255.255", 17,
                                                   udp(68, 67, dhcp_discover("omarchy-bench")))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "192.168.77.1", 17,
                                              udp(40000, 53, dns_query("telemetry.example.com")))),
            ether(ROUTER, GUEST, 0x0800, ipv4("192.168.77.1", "192.168.77.50", 17,
                                              udp(53, 40000, dns_query("telemetry.example.com",
                                                                       response_ip="93.184.216.34")))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "93.184.216.34", 6, tcp(50000, 443, hello[:1000]))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "93.184.216.34", 6, tcp(50000, 443, hello[1000:]))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "93.184.216.35", 6,
                                              tcp(50001, 80, b"GET /check?v=4.0.4 HTTP/1.1\r\nHost: up.example.com\r\n"
                                                             b"User-Agent: bench-agent/4.0.4\r\n\r\n"))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "162.159.200.1", 17, udp(123, 123, b"\x23" + b"\x00" * 47))),
            ether(GUEST, b"\x01\x00\x5e\x00\x00\xfc", 0x0800, ipv4("192.168.77.50", "224.0.0.252", 17,
                                                                 udp(5355, 5355, dns_query("omarchy-bench", 255)))),
            ether(GUEST, b"\x33\x33\xff\x00\x12\x34", 0x86DD, v6),
            ether(bytes.fromhex("525400aaaaaa"), ROUTER, 0x0800,
                  ipv4("192.168.77.51", "1.1.1.1", 17, udp(1, 53, dns_query("not-the-guest.example")))),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "c.pcap"
            write_pcap(path, frames)
            summary = pcap_summary.summarize(path, "52:54:00:be:0c:01")
        self.assertEqual(summary["identifiers"]["dhcp_hostname"], ["omarchy-bench"])
        self.assertEqual(summary["identifiers"]["link_local_name_queries"], ["omarchy-bench"])
        self.assertEqual(summary["identifiers"]["http_user_agents"], ["bench-agent/4.0.4"])
        self.assertEqual([s["name"] for s in summary["tls_sni"]], ["telemetry.example.com"])
        self.assertEqual(summary["dns_queries"], [{"name": "telemetry.example.com", "type": "A", "count": 1}])
        self.assertNotIn("not-the-guest.example", summary["distinct_names"])
        self.assertEqual(summary["internet_destination_count"], 3)
        self.assertEqual(summary["ntp_servers"], ["162.159.200.1"])
        tls_row = next(r for r in summary["destinations"] if r["ip"] == "93.184.216.34")
        self.assertEqual(tls_row["names"], ["telemetry.example.com"])
        self.assertIn("fd77:77:77:77::1234", summary["guest_addresses"]["ipv6"])
        self.assertIn("192.168.77.50", summary["guest_addresses"]["ipv4"])
        self.assertTrue(summary["mac_matches_configured"])
        self.assertEqual(sorted(summary["identifier_kinds_sent"]),
                         ["dhcp_hostname", "http_user_agents", "link_local_name_queries"])

    def test_site_local_is_not_internet(self):
        self.assertEqual(pcap_summary.scope("fec0::2"), "local")
        self.assertEqual(pcap_summary.scope("8.8.8.8"), "internet")
        self.assertEqual(pcap_summary.scope("ff02::1"), "multicast")


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><ports>
<extraports state="filtered" count="65533"/>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
<port protocol="tcp" portid="53317"><state state="open"/><service name="unknown"/></port>
<port protocol="udp" portid="53317"><state state="open"/></port>
<port protocol="udp" portid="123"><state state="open|filtered"/></port>
</ports></host></nmaprun>"""


class ScanTest(unittest.TestCase):
    def test_nmap_xml(self):
        parsed = portscan.parse_nmap_xml(NMAP_XML)
        self.assertEqual([p["port"] for p in parsed["tcp_open"]], [22, 53317])
        self.assertEqual([p["port"] for p in parsed["udp_open"]], [53317])
        self.assertEqual(parsed["udp_open_filtered"], 1)


class PlanTest(unittest.TestCase):
    def test_plan_is_seeded_and_gated(self):
        a = bench_plan.plan("punar+omarchy", 5, "8192,4096", "4096", 42, omarchy_approved=True)
        b = bench_plan.plan("punar+omarchy", 5, "8192,4096", "4096", 42, omarchy_approved=True)
        self.assertEqual(a, b)
        self.assertEqual(len(a["cells"]), 10)
        self.assertEqual({c["order"] for c in a["cells"]} <= {"punar,omarchy", "omarchy,punar"}, True)
        self.assertTrue(all(c["workload"] == (c["shape"] == 4096) for c in a["cells"]))
        gated = bench_plan.plan("punar+omarchy", 5, "8192", "", 42, omarchy_approved=False)
        self.assertEqual(gated["lanes"], ["punar"])
        self.assertTrue(all(c["order"] == "punar" for c in gated["cells"]))
        self.assertTrue(any("not approved" in n for n in gated["notes"]))

    def test_plan_refuses_bad_input(self):
        for args in (("punar;rm", 5, "8192", ""), ("punar", 0, "8192", ""), ("punar", 5, "8192,1", ""),
                     ("punar", 5, "8192,8192", "")):
            with self.assertRaises(ValueError):
                bench_plan.plan(*args, seed=1, omarchy_approved=False)


class OmarchyLaneTest(unittest.TestCase):
    @unittest.skipUnless(shutil.which("openssl"), "openssl not installed")
    def test_cidata_renders_valid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            secret = Path(directory) / "secret"
            secret.write_text("abc123throwaway\n")
            key = Path(directory) / "key.pub"
            key.write_text("ssh-ed25519 AAAA bench\n")
            out = subprocess.run([str(REPO / "tools/bench/omarchy/make-cidata.sh"), "-", str(secret), str(key)],
                                 capture_output=True, text=True, check=True).stdout
            config = json.loads(out.split("== user_configuration.json\n")[1].split("== user_credentials.json")[0])
            creds = json.loads(out.split("== user_credentials.json\n")[1].split("== user_encrypt_installation.txt")[0])
            self.assertEqual(config["disk_config"]["disk_encryption"]["encryption_password"], "abc123throwaway")
            self.assertEqual(config["disk_config"]["disk_encryption"]["iter_time"], 2000)
            parts = config["disk_config"]["device_modifications"][0]["partitions"]
            self.assertEqual(parts[1]["start"]["value"], 1024 ** 2 + 2 * 1024 ** 3)
            self.assertEqual(parts[1]["size"]["value"], 40 * 1024 ** 3 - parts[1]["start"]["value"] - 1024 ** 2)
            self.assertTrue(creds["users"][0]["enc_password"].startswith("$6$"))
            self.assertEqual(creds["root_enc_password"], creds["users"][0]["enc_password"])
            secret.write_text("Not-Typeable\n")
            bad = subprocess.run([str(REPO / "tools/bench/omarchy/make-cidata.sh"), "-", str(secret), str(key)],
                                 capture_output=True, text=True, check=False)
            self.assertNotEqual(bad.returncode, 0)

    def test_restore_stock(self):
        with tempfile.TemporaryDirectory() as directory:
            mnt = Path(directory)
            osroot = mnt / "@"
            wants = osroot / "etc/systemd/system/multi-user.target.wants"
            wants.mkdir(parents=True)
            (wants / "sshd.service").symlink_to("/usr/lib/systemd/system/sshd.service")
            (wants / "NetworkManager.service").symlink_to("/usr/lib/systemd/system/NetworkManager.service")
            ufw = osroot / "etc/ufw"
            ufw.mkdir(parents=True)
            (ufw / "user.rules").write_text(
                "*filter\n### RULES ###\n\n"
                "### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n"
                "-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n\n"
                "### tuple ### allow any 53317 0.0.0.0/0 any 0.0.0.0/0 in\n"
                "-A ufw-user-input -p tcp --dport 53317 -j ACCEPT\n"
                "-A ufw-user-input -p udp --dport 53317 -j ACCEPT\n\n### END RULES ###\nCOMMIT\n")
            (osroot / "etc/sudoers.d").mkdir(parents=True)
            ssh = mnt / "@home/bench/.ssh"
            ssh.mkdir(parents=True)
            (ssh / "authorized_keys").write_text("ssh-ed25519 AAAA bench\n")
            record = mnt / "record.txt"
            env = dict(os.environ, BENCH_MOUNT=str(mnt), BENCH_OSROOT=str(osroot), BENCH_RECORD=str(record))
            subprocess.run([str(REPO / "tools/bench/omarchy/restore-stock.sh")], env=env, check=True,
                           capture_output=True)
            self.assertFalse((wants / "sshd.service").is_symlink())
            self.assertTrue((wants / "NetworkManager.service").is_symlink())
            rules = (ufw / "user.rules").read_text()
            self.assertNotIn("--dport 22 ", rules)
            self.assertNotIn("allow tcp 22 ", rules)
            self.assertIn("--dport 53317", rules)
            self.assertFalse((ssh / "authorized_keys").exists())
            sudoers = osroot / "etc/sudoers.d/90-bench-docker-build"
            self.assertEqual(oct(sudoers.stat().st_mode & 0o777), "0o440")
            self.assertIn("NOPASSWD: /usr/bin/docker build -t bench-fixture /opt/bench/fixture", sudoers.read_text())
            text = record.read_text()
            self.assertIn("DEVIATION", text)
            self.assertIn("REMOVED -A ufw-user-input -p tcp --dport 22 -j ACCEPT", text)


class CredentialsTest(unittest.TestCase):
    def test_release_test_account_is_read_from_the_onboarding_script(self):
        # bench_run imports QEMU-free helpers only at call time.
        import bench_run
        creds = bench_run.onboarding_credentials()
        self.assertEqual(creds["source"], "tools/test-release-onboarding.sh")
        self.assertTrue(creds["username"] and creds["password"] and creds["device"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
