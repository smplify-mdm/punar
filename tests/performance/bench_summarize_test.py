#!/usr/bin/env python3
"""Unit tests for the benchmark harness's host side (tools/bench).

Run by tests/performance/bench-summarize-test.sh. Standard library only.
Covers the D1 rule and the report (never a "win" without it, losses always
printed, one claim per family of figures, like setups only, failed and
missing runs counted, lower bounds never winning), the parser's edge cases
(dm-crypt attribution, the validity gate), the privacy summary on a
synthetic capture (names hidden behind QUIC, ECH and DoH counted), nmap
parsing, the dispatch plan (balanced order, the cell cap), the Omarchy
lane's secret, CIDATA rendering and stock restore, and that the release
image's test account is still where the harness reads it.
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


def merge(base: dict, extra: dict) -> dict:
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            merge(base[key], value)
        else:
            base[key] = value
    return base


def result(lane, shape, index, used, *, valid=True, login="punar-greeter", encryption="none",
           available=3000.0, boot_initrd=2.0, reasons=None, meta=None, **extra):
    document = {
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
    merge(document["meta"], meta or {})
    return merge(document, extra)


def verdicts(report, metric, shape=8192):
    return next(c for c in report["comparisons"] if c["metric"] == metric and c["shape_mib"] == shape)


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
        wins = [c for c in report["claims"] if c["verdict"] == "WIN"]
        self.assertEqual(text.count("**WIN**"), len(wins))
        self.assertTrue(all(c["verdict"] == "WIN" for w in wins for c in report["comparisons"]
                            if c["metric"] == w["headline"] and c["shape_mib"] == w["shape_mib"]))

    def test_every_metric_needs_the_same_disk_encryption(self):
        # An unencrypted pre-install image against an installed LUKS disk: even
        # idle RAM is not the same measurement, and the worse median still shows.
        report, c = self.compare([1000, 1005, 1010, 1015, 1020], [900, 905, 910, 912, 915],
                                 encryption="luks2 (installed)")
        self.assertEqual(c["verdict"], "NOT_COMPARABLE")
        self.assertIn("disk_encryption differs", c["reason"])
        self.assertFalse(any(x["verdict"] in ("WIN", "LOSS") for x in report["comparisons"]))
        text = bench_report.markdown(report, "t")
        self.assertIn("Idle RAM used (MemTotal - MemAvailable), mean at 8192 MiB vs omarchy: not comparable", text)

    def test_runs_that_mix_setups_are_not_pooled(self):
        runs = [result("punar", 8192, i, v, meta={"accel": "kvm" if i < 3 else "hvf"})
                for i, v in enumerate([900, 905, 910, 912, 915])]
        runs += [result("omarchy", 8192, i, v) for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        c = verdicts(bench_report.aggregate(runs, "punar"), "idle_used_mean")
        self.assertEqual(c["verdict"], "NOT_COMPARABLE")
        self.assertIn("punar runs mix accel (hvf/kvm)", c["reason"])
        runs = [result("punar", 8192, i, v, meta={"image_sha256": "a" if i else "b"})
                for i, v in enumerate([900, 905, 910, 912, 915])]
        runs += [result("omarchy", 8192, i, v) for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        self.assertIn("mix image_sha256", verdicts(bench_report.aggregate(runs, "punar"), "idle_used_mean")["reason"])

    def test_the_machine_must_match(self):
        _, c = self.compare([900, 905, 910, 912, 915], [1000, 1005, 1010, 1015, 1020], meta={"arch": "arm64"})
        self.assertEqual(c["verdict"], "NOT_COMPARABLE")
        self.assertIn("arch differs", c["reason"])

    def test_one_family_is_one_claim(self):
        runs = [result("punar", 8192, i, v, available=4000 - v) for i, v in enumerate([900, 905, 910, 912, 915])]
        runs += [result("omarchy", 8192, i, v, available=4000 - v) for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        report = bench_report.aggregate(runs, "punar")
        self.assertEqual(verdicts(report, "idle_used_mean")["verdict"], "WIN")
        self.assertEqual(verdicts(report, "idle_available")["verdict"], "WIN")
        claims = [c for c in report["claims"] if c["verdict"] == "WIN"]
        self.assertEqual([c["family"] for c in claims], ["idle_ram"])
        text = bench_report.markdown(report, "t")
        self.assertEqual(text.count("**WIN**"), 1)
        self.assertIn("one claim; the same family also passed on idle_available", text)

    def test_a_family_that_disagrees_claims_nothing(self):
        runs = [result("punar", 8192, i, v, idle={"memory": {"used_max_mib": 2000 + i}})
                for i, v in enumerate([900, 905, 910, 912, 915])]
        runs += [result("omarchy", 8192, i, v, idle={"memory": {"used_max_mib": 1500 + i}})
                 for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        report = bench_report.aggregate(runs, "punar")
        family = next(c for c in report["claims"] if c["family"] == "idle_ram")
        self.assertEqual(family["verdict"], "CONFLICT")
        text = bench_report.markdown(report, "t")
        self.assertNotIn("**WIN**", text)
        self.assertIn("**LOSS** Idle RAM used, max at 8192 MiB vs omarchy", text)
        self.assertIn("Families whose figures disagree", text)

    def test_a_system_that_fails_every_run_loses(self):
        runs = [result("punar", 8192, i, v, valid=False, reasons=["harness: the greeter never became ready"],
                       idle={}) for i, v in enumerate([900] * 5)]
        runs += [result("omarchy", 8192, i, v) for i, v in enumerate([1000, 1005, 1010, 1015, 1020])]
        report = bench_report.aggregate(runs, "punar")
        self.assertEqual(verdicts(report, "run_valid")["verdict"], "LOSS")
        c = verdicts(report, "idle_used_mean")
        self.assertTrue(c["subject_missing"])
        text = bench_report.markdown(report, "t")
        losses = text.split("## Losses (published with the wins)")[1].split("## Wins")[0]
        self.assertIn("**LOSS** Planned runs that produced a valid result", losses)
        self.assertIn("`punar-8192-0`: harness: the greeter never became ready", losses)
        self.assertIn("no usable `punar` runs (`omarchy` has 5)", losses)

    def test_planned_runs_that_never_reported_count_as_failed(self):
        plan = bench_plan.plan("punar+omarchy", 5, "8192", "", 7, omarchy_approved=True)
        runs = []
        for cell in plan["cells"]:
            runs.append(result("punar", 8192, cell["run"], 900 + cell["run"], meta={"cell": cell["cell"]}))
            if cell["run"] != 3:  # the omarchy run of one cell never reported
                runs.append(result("omarchy", 8192, cell["run"], 1000 + cell["run"], meta={"cell": cell["cell"]}))
        missing = bench_report.missing_from_plan(plan, runs)
        self.assertEqual([(m["meta"]["lane"], m["meta"]["cell"]) for m in missing], [("omarchy", "s8192-r3")])
        report = bench_report.aggregate(runs + missing, "punar")
        c = verdicts(report, "run_valid")
        self.assertEqual((c["subject"]["n"], c["rival_stats"]["n"]), (5, 5))
        self.assertEqual(c["rival_stats"]["min"], 0.0)
        self.assertNotEqual(c["verdict"], "NOT_COMPARABLE")
        self.assertEqual(verdicts(report, "idle_used_mean")["rival_stats"]["n"], 4)

    def test_subject_failures_are_published_without_a_rival(self):
        runs = [result("punar", 8192, i, 900) for i in range(4)]
        runs.append(result("punar", 8192, 9, 900, valid=False, reasons=["incomplete window"]))
        text = bench_report.markdown(bench_report.aggregate(runs, "punar"), "t")
        losses = text.split("## Losses (published with the wins)")[1].split("## Wins")[0]
        self.assertIn("8192 MiB `punar-8192-9`: incomplete window", losses)

    def test_names_that_are_a_lower_bound_cannot_win(self):
        def privacy(names, bound):
            return {"privacy": {"distinct_name_count": names, "names_are_lower_bound": bound,
                                "capture": {"complete": True}}}
        runs = [result("punar", 8192, i, 900, **privacy(2, True)) for i in range(5)]
        runs += [result("omarchy", 8192, i, 900, **privacy(9, False)) for i in range(5)]
        c = verdicts(bench_report.aggregate(runs, "punar"), "priv_names")
        self.assertEqual(c["verdict"], "NO_CLAIM")
        self.assertIn("lower bound in 5 of 5 runs", c["reason"])
        runs = [result("punar", 8192, i, 900, **privacy(2, False)) for i in range(5)]
        runs += [result("omarchy", 8192, i, 900, **privacy(9, True)) for i in range(5)]
        self.assertEqual(verdicts(bench_report.aggregate(runs, "punar"), "priv_names")["verdict"], "WIN")

    def test_privacy_needs_a_complete_capture(self):
        def privacy(count, complete):
            return {"privacy": {"internet_destination_count": count, "capture": {"complete": complete}}}
        runs = [result("punar", 8192, i, 900, **privacy(1, True)) for i in range(5)]
        runs += [result("omarchy", 8192, i, 900, **privacy(0, False)) for i in range(5)]
        c = verdicts(bench_report.aggregate(runs, "punar"), "priv_destinations")
        self.assertEqual((c["subject"]["n"], c["rival_stats"]["n"]), (5, 0))
        self.assertEqual(c["verdict"], "NO_CLAIM")

    def workload(self, tool, psi, completion, browser="ok", oom=0):
        return {"workload": {"status": "done", "container_tool": tool, "steps_ok": 3 if browser == "ok" else 2,
                             "browser_status": browser, "editor_status": "ok", "container_status": "ok",
                             "browser_editor_attempted": True, "all_steps_ran": browser == "ok",
                             "completion_s": completion,
                             "before_container": {"psi_full_avg10_max": psi, "oom_kills_total": oom}}}

    def test_whole_workload_needs_the_same_container_tool(self):
        runs = [result("punar", 4096, i, 900, **self.workload("podman", 1.0 + i / 10, 100 + i)) for i in range(5)]
        runs += [result("omarchy", 4096, i, 900, **self.workload("docker-sudo-rule", 5.0 + i / 10, 200 + i))
                 for i in range(5)]
        report = bench_report.aggregate(runs, "punar")
        self.assertEqual(verdicts(report, "wl_completion", 4096)["verdict"], "NOT_COMPARABLE")
        self.assertIn("workload.container_tool differs", verdicts(report, "wl_completion", 4096)["reason"])
        self.assertEqual(verdicts(report, "wl_psi_full", 4096)["verdict"], "WIN")

    def test_workload_failures_count_against_the_system(self):
        # oomd kills the subject's browser in every run: before, those runs
        # left the workload figures and the subject could never lose.
        runs = [result("punar", 4096, i, 900, **self.workload("podman", 60.0 + i, 300, browser="failed", oom=1))
                for i in range(5)]
        runs += [result("omarchy", 4096, i, 900, **self.workload("podman", 5.0 + i, 200)) for i in range(5)]
        report = bench_report.aggregate(runs, "punar")
        self.assertEqual(verdicts(report, "wl_steps_ok", 4096)["verdict"], "LOSS")
        self.assertEqual(verdicts(report, "wl_oom", 4096)["verdict"], "LOSS")
        self.assertEqual(verdicts(report, "wl_psi_full", 4096)["verdict"], "LOSS")

    def test_package_counts_need_one_package_manager(self):
        runs = [result("punar", 8192, i, 900, footprint={"packages": 700, "package_manager": "dpkg"}) for i in range(5)]
        runs += [result("omarchy", 8192, i, 900, footprint={"packages": 900, "package_manager": "pacman"})
                 for i in range(5)]
        c = verdicts(bench_report.aggregate(runs, "punar"), "fp_packages")
        self.assertEqual(c["verdict"], "NOT_COMPARABLE")

    def test_position_split_is_published(self):
        runs = [result("punar", 8192, i, 900 + 10 * (i % 2), meta={"position": str(1 + i % 2)}) for i in range(5)]
        report = bench_report.aggregate(runs, "punar")
        split = report["table"][("punar", 8192)]["context"]["position"]["idle_used_mean"]
        self.assertEqual(split, {"1": {"median": 900, "n": 3}, "2": {"median": 910, "n": 2}})
        self.assertIn("by position in the cell", bench_report.markdown(report, "t"))

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

    def test_dm_crypt_clone_charged_again_is_not_counted_twice(self):
        # Newer kernels charge the encrypted clone on vda to the writer again.
        devices = [{"kind": "disk", "name": "vda", "dev": "254:0"},
                   {"kind": "virtual", "name": "dm-0", "dev": "253:0", "slaves": "vda2"},
                   {"kind": "virtual", "name": "zram0", "dev": "252:0", "slaves": "-"}]
        physical, attribution = bench_parse.device_roles(devices)
        self.assertEqual((physical, attribution), (["254:0"], ["253:0"]))
        start = {"/": {"p": "/", "io": {"254:0": [0, 0, 0, 0]}},
                 "/system.slice": {"p": "/system.slice", "io": {"254:0": [0, 0, 0, 0], "253:0": [0, 0, 0, 0]}}}
        end = {"/": {"p": "/", "io": {"254:0": [0, 5000, 0, 0], "253:0": [0, 4000, 0, 0]}},
               "/system.slice": {"p": "/system.slice", "io": {"254:0": [0, 3000, 0, 0], "253:0": [0, 3000, 0, 0]}}}
        counters = {"diskstats": {}}
        writes = bench_parse.writes_section(physical, start, end, counters, counters, None, attribution)
        self.assertEqual(writes["device_bytes"], 5000)
        self.assertEqual(writes["top_level_cgroups_bytes"], 3000)
        self.assertEqual(writes["kernel_fs_remainder_bytes"], 2000)

    def test_device_roles_follow_the_stack(self):
        devices = [{"kind": "disk", "name": "nvme0n1", "dev": "259:0"},
                   {"kind": "disk", "name": "vdb", "dev": "254:16"},
                   {"kind": "virtual", "name": "dm-0", "dev": "253:0", "slaves": "nvme0n1p3"},
                   {"kind": "virtual", "name": "dm-1", "dev": "253:1", "slaves": "dm-0"}]
        self.assertEqual(bench_parse.device_roles(devices), (["259:0", "254:16"], ["253:1", "254:16"]))

    def test_missing_host_data_never_passes_the_gate(self):
        records = [{"type": "facts", "canonical": "yes", "samples": "0"}, {"type": "window_end"},
                   *counters("start", 100.0, [0] * 10, 0, 0, [{"p": "/"}])[:1],
                   *counters("end", 400.0, [100, 0, 0, 11900, 0, 0, 0, 0, 0, 0], 0, 0, [{"p": "/"}])[:1]]
        reasons = bench_parse.parse_run(records, {"meta": {"accel": "hvf"}})["validity"]["reasons"]
        self.assertIn("host steal not measured (no host /proc/stat over the window)", reasons)
        self.assertIn("accelerator is hvf, not KVM", reasons)
        valid = bench_parse.parse_run(records, {"meta": {"accel": "kvm"}, "host": {"steal_pct_window": 0.1}})
        self.assertTrue(valid["validity"]["valid_for_claims"], valid["validity"]["reasons"])


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
        self.assertEqual(summary["opaque_name_flow_count"], 0)
        self.assertFalse(summary["names_are_lower_bound"])

    def test_names_hidden_from_the_capture_are_counted(self):
        def hello(host, ech=False):
            data = bytearray(client_hello(host))
            if ech:  # rename the padding extension to encrypted_client_hello
                at = data.index(struct.pack(">HH", 0x15, 1600))
                data[at:at + 2] = struct.pack(">H", 0xFE0D)
            return bytes(data)
        frames = [
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "142.250.1.1", 17, udp(50000, 443, b"\xc3" + b"\x00" * 40))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "104.16.1.1", 6, tcp(50001, 443, hello("public.example", ech=True)))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "104.16.2.2", 6, tcp(50002, 443, hello("cloudflare-dns.com")))),
            ether(GUEST, ROUTER, 0x0800, ipv4("192.168.77.50", "9.9.9.9", 6, tcp(50003, 853, b""))),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "c.pcap"
            write_pcap(path, frames)
            summary = pcap_summary.summarize(path, "52:54:00:be:0c:01")
        kinds = sorted(row["kind"] for row in summary["opaque_name_flows"])
        self.assertEqual(kinds, ["dns-over-https", "dns-over-tls", "quic", "tls-encrypted-client-hello"])
        self.assertTrue(summary["names_are_lower_bound"])

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
    def test_lane_order_is_balanced_exactly(self):
        for seed in range(40):
            plan = bench_plan.plan("punar+omarchy", 5, "8192,4096", "4096", seed, omarchy_approved=True)
            per_shape = {}
            for cell in plan["cells"]:
                per_shape.setdefault(cell["shape"], []).append(cell["order"].split(",")[0])
            for shape, firsts in per_shape.items():
                self.assertEqual(sorted((firsts.count("punar"), firsts.count("omarchy"))), [2, 3], (seed, shape))
            total = [first for firsts in per_shape.values() for first in firsts]
            self.assertEqual(total.count("punar"), 5, seed)

    def test_cells_are_capped(self):
        with self.assertRaises(ValueError):
            bench_plan.plan("punar", 11, "8192,4096", "", 1, omarchy_approved=False)
        self.assertEqual(len(bench_plan.plan("punar", 10, "8192,4096", "", 1, omarchy_approved=False)["cells"]), 20)

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
    def test_new_secret_has_no_newline(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "secret"
            subprocess.run([str(REPO / "tools/bench/omarchy/new-secret.sh"), str(path)], check=True)
            data = path.read_bytes()
            self.assertEqual(len(data), 24)
            self.assertTrue(all(chr(b) in "abcdefghijklmnopqrstuvwxyz0123456789" for b in data))
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            again = subprocess.run([str(REPO / "tools/bench/omarchy/new-secret.sh"), str(path)],
                                   capture_output=True, check=False)
            self.assertNotEqual(again.returncode, 0)

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
