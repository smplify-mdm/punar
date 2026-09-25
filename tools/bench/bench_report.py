#!/usr/bin/env python3
"""Aggregate benchmark runs and compare systems under the D1 rule (tools/bench/README.md).

    bench_report.py RESULTS_DIR... --md SUMMARY.md --json SUMMARY.json
                    [--subject punar] [--baseline BASELINE.json] [--plan PLAN.json]

Reads every result.json under the given directories (bench_parse.py output),
groups runs by lane and VM shape, and reports median, min, max and IQR for
every metric over the runs that are valid for a claim.

The rule for a claim (decision D1) is enforced here and nowhere else:
the subject WINS a metric on a shape only when
  - both systems have at least 5 valid runs on that shape,
  - the subject's median is better, and
  - the min-max ranges do not overlap (subject max < rival min, for a
    lower-is-better metric).
The rival wins the same way, and that is a LOSS. Anything else is "no
claim" with the reason. Losses and worse medians are always printed, in
their own section, whether or not there are wins; the word "win" is never
used for a result that did not pass the rule.

What else keeps a comparison honest:
- Like with like. The runs pooled for one lane on one shape must share one
  setup (image, accelerator, architecture, resolution, network, disk format,
  probe version, login, disk encryption); a mixed pool is "not comparable",
  never averaged. The two systems must match on the machine (the same keys
  without image and login) and, for every metric, on disk encryption: an
  unencrypted pre-install image against an installed encrypted disk is not
  the same measurement, until an installed, encrypted Punar lane exists.
  Metrics add their own keys (login for boot, the package manager for a
  package count, the container tool for the whole workload).
- One difference, one claim. Figures that read one quantity several ways
  (idle RAM used, its max, MemAvailable ...) form a family. A family wins
  once, only when its headline figure wins and none of its figures loses;
  every figure that loses is printed on its own.
- Failures count. Whether each planned run produced a valid result is a
  metric of its own (a system that fails every run loses it); with --plan,
  planned runs that never reported count as failed; and every failed or
  invalid run of the subject is listed with the losses.
- Missing data never helps. A figure that is only a lower bound (names
  hidden behind encrypted DNS or QUIC) cannot win, privacy figures need a
  complete capture, and workload pressure figures need the same steps to
  have been attempted.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

MIN_RUNS = 5
# Facts that must be equal between the two systems for any comparison.
MACHINE_KEYS = ("arch", "accel", "resolution", "net", "vcpus", "graphics", "disk_format", "inject",
                "probe.version")
# Facts that must have one value across the runs pooled for one lane.
LANE_SETUP_KEYS = MACHINE_KEYS + ("image_sha256", "login", "disk_encryption")
# Until the installed, encrypted Punar lane exists, every figure depends on it.
COMMON_SAME = ("disk_encryption",)


def dig(document: dict, path: str):
    value = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def fact(result: dict, key: str):
    """A run fact: a dotted path into the result, or a key of result["meta"]."""
    return dig(result, key) if "." in key else (result.get("meta") or {}).get(key)


@dataclass
class Metric:
    key: str
    label: str
    unit: str
    better: str  # "lower" or "higher"
    path: str | None = None
    compute: Callable[[dict], float | None] | None = None
    group: str = "idle"
    # Run facts (meta keys or dotted result paths) that must be equal across
    # the systems compared, beyond MACHINE_KEYS and COMMON_SAME.
    same: tuple[str, ...] = ()
    # A run is used for this metric only when this returns True.
    usable: Callable[[dict], bool] | None = None
    note: str = ""
    # Figures of one family are one claim (the first listed is the headline).
    family: str | None = None
    # Counted over every run, valid or not (completion).
    all_runs: bool = False
    # True for a run whose figure is only a lower bound: such a side never wins.
    lower_bound: Callable[[dict], bool] | None = None

    def value(self, result: dict):
        raw = self.compute(result) if self.compute else dig(result, self.path)
        if isinstance(raw, bool) or raw is None:
            return None
        try:
            return float(raw)
        except (TypeError, ValueError):
            return None


def _identifier_kinds(result: dict):
    privacy = result.get("privacy")
    if not privacy:
        return None
    return len(privacy.get("identifier_kinds_sent", []))


def _run_valid(result: dict):
    return 1.0 if (result.get("validity") or {}).get("valid_for_claims") else 0.0


def _workload(result: dict) -> dict:
    return result.get("workload") or {}


def _workload_ran(result: dict) -> bool:
    return bool(_workload(result).get("all_steps_ran"))


def _workload_recorded(result: dict) -> bool:
    return bool(_workload(result)) and _workload(result).get("status") != "skipped"


def _browser_editor_attempted(result: dict) -> bool:
    return bool(_workload(result).get("browser_editor_attempted"))


def _editor_ok(result: dict) -> bool:
    return _workload(result).get("editor_status") == "ok"


def _scanned(result: dict) -> bool:
    return bool((dig(result, "exposure.scan") or {}).get("complete"))


def _captured(result: dict) -> bool:
    return bool(((result.get("privacy") or {}).get("capture") or {}).get("complete"))


def _names_lower_bound(result: dict) -> bool:
    return bool((result.get("privacy") or {}).get("names_are_lower_bound"))


METRICS = [
    Metric("run_valid", "Planned runs that produced a valid result", "share", "higher", compute=_run_valid,
           group="runs", all_runs=True,
           note="Every planned run counts: failed, invalid and never-reported runs are 0."),
    Metric("idle_used_mean", "Idle RAM used (MemTotal - MemAvailable), mean", "MiB", "lower", "idle.memory.used_mean_mib",
           family="idle_ram"),
    Metric("idle_used_max", "Idle RAM used, max", "MiB", "lower", "idle.memory.used_max_mib", family="idle_ram"),
    Metric("idle_used_net", "Idle RAM used, probe subtracted", "MiB", "lower", "idle.memory.used_net_mean_mib",
           family="idle_ram"),
    Metric("idle_shape_minus_available", "Machine memory minus MemAvailable (includes memory reserved at boot)",
           "MiB", "lower", "idle.memory.shape_minus_available_mean_mib", family="idle_ram"),
    Metric("idle_used_minus_totalreserve", "Idle RAM used minus the kernel's watermark reserve (totalreserve)",
           "MiB", "lower", "idle.memory.used_minus_totalreserve_mean_mib", family="idle_ram",
           note="totalreserve (high watermark + lowmem reserve, /proc/zoneinfo) is what THP's min_free_kbytes raises."),
    Metric("idle_unreclaimable", "Idle RAM neither free nor page cache nor reclaimable slab "
           "(MemTotal - MemFree - file LRU - KReclaimable)", "MiB", "lower", "idle.memory.unreclaimable_used_mean_mib",
           family="idle_ram"),
    Metric("idle_available", "MemAvailable, mean", "MiB", "higher", "idle.memory.mem_available_mean_mib",
           family="idle_ram"),
    Metric("idle_anon", "Anonymous memory (AnonPages)", "MiB", "lower", "idle.memory.anon_mean_mib"),
    Metric("idle_unevictable", "Unevictable memory", "MiB", "lower", "idle.memory.unevictable_mean_mib"),
    Metric("idle_shmem", "Shared memory (Shmem)", "MiB", "lower", "idle.memory.shmem_mean_mib"),
    Metric("idle_swap", "Swap in use", "MiB", "lower", "idle.memory.swap_used_mean_mib"),
    Metric("idle_pss_total", "Summed process PSS", "MiB", "lower", "idle.memory.pss_total_mib"),
    Metric("idle_cpu", "Idle CPU, whole system, probe subtracted", "% of all CPUs", "lower", "idle.cpu.system_pct_net"),
    Metric("idle_interrupts", "Interrupts (wakeups)", "per s", "lower", "idle.cpu.interrupts_per_s",
           family="idle_wakeups"),
    Metric("idle_ctxt", "Context switches", "per s", "lower", "idle.cpu.ctxt_per_s", family="idle_wakeups"),
    Metric("idle_writes", "Idle disk writes, whole device, probe subtracted", "bytes / window", "lower",
           "idle.writes.device_bytes_net"),
    Metric("idle_writes_journald", "Idle writes charged to journald", "bytes / window", "lower", "idle.writes.journald_bytes"),
    Metric("idle_writes_remainder", "Idle writes no cgroup was charged for (kernel/filesystem)", "bytes / window", "lower",
           "idle.writes.kernel_fs_remainder_bytes"),
    Metric("idle_psi_memory", "Memory pressure (some), share of the window", "%", "lower", "idle.pressure.memory_some_stall_pct"),
    Metric("idle_psi_cpu", "CPU pressure (some), share of the window", "%", "lower", "idle.pressure.cpu_some_stall_pct"),
    Metric("idle_psi_io", "I/O pressure (some), share of the window", "%", "lower", "idle.pressure.io_some_stall_pct"),
    Metric("boot_kernel", "Boot: kernel", "s", "lower", "boot.kernel_s", group="boot"),
    Metric("boot_initrd", "Boot: initrd", "s", "lower", "boot.initrd_s", group="boot", same=("login",)),
    Metric("boot_userspace", "Boot: userspace to boot finished", "s", "lower", "boot.userspace_s", group="boot",
           same=("login",)),
    Metric("boot_graphical", "Boot: kernel start to graphical.target", "s", "lower", "boot.kernel_to_graphical_target_s",
           group="boot", same=("login",), family="boot_to_desktop"),
    Metric("boot_greeter", "Boot: kernel start to the greeter's shell", "s", "lower", "boot.kernel_to_greeter_shell_s",
           group="boot", same=("login",), family="boot_to_desktop"),
    Metric("boot_login", "Login: session start to the shell process", "s", "lower", "boot.login_to_shell_s",
           group="boot", same=("login",)),
    Metric("sec_unsafe", "Services rated UNSAFE by systemd-analyze security", "count", "lower",
           "security.services_unsafe", group="security"),
    Metric("sec_exposure", "systemd-analyze security exposure, summed over services", "sum of 0-10", "lower",
           "security.exposure_sum", group="security",
           note="A sum: every service adds to it, so many small sandboxed units cannot lower it."),
    Metric("sec_setuid", "setuid files", "count", "lower", "security.setuid_count", group="security"),
    Metric("sec_setgid", "setgid files", "count", "lower", "security.setgid_count", group="security"),
    Metric("sec_listeners", "Non-loopback listening sockets (guest view)", "count", "lower",
           "exposure.guest.non_loopback_count", group="security"),
    Metric("sec_open_tcp", "Open TCP ports reachable from the network", "count", "lower", "exposure.scan.open_tcp_total",
           group="security", usable=_scanned),
    Metric("sec_open_udp", "Open UDP ports reachable from the network", "count", "lower", "exposure.scan.open_udp_total",
           group="security", usable=_scanned),
    Metric("priv_destinations", "Internet destinations contacted, power-on to end of idle", "count", "lower",
           "privacy.internet_destination_count", group="privacy", usable=_captured),
    Metric("priv_names", "Distinct names looked up or sent (DNS, SNI)", "count", "lower", "privacy.distinct_name_count",
           group="privacy", usable=_captured, lower_bound=_names_lower_bound,
           note="A lower bound when names may travel encrypted (QUIC, DoT, DoH, ECH); such a figure never wins."),
    Metric("priv_opaque", "Flows whose server name the capture cannot read (QUIC, DoT, DoH, ECH, no SNI)", "count",
           "lower", "privacy.opaque_name_flow_count", group="privacy", usable=_captured),
    Metric("priv_bytes_out", "Bytes sent to the internet", "bytes", "lower", "privacy.internet_bytes_out",
           group="privacy", usable=_captured),
    Metric("priv_identifiers", "Kinds of identifier volunteered on the network", "count", "lower",
           compute=_identifier_kinds, group="privacy", usable=_captured),
    Metric("fp_os_files", "Operating-system files (/usr and /opt, apparent size)", "MiB", "lower",
           "footprint.os_files_mib", group="footprint", same=("footprint.os_files_size",)),
    Metric("fp_packages", "Installed packages", "count", "lower", "footprint.packages", group="footprint",
           same=("footprint.package_manager",),
           note="Package managers split software differently, so counts compare only within one."),
    Metric("fp_enabled", "Enabled unit files", "count", "lower", "footprint.enabled_unit_files", group="footprint"),
    Metric("fp_running", "Running services at idle", "count", "lower", "footprint.running_services", group="footprint"),
    Metric("wl_steps_ok", "Workload steps that completed (of 3)", "count", "higher", "workload.steps_ok",
           group="workload", usable=_workload_recorded,
           note="A step that failed or never started counts against the system."),
    Metric("wl_psi_full", "Workload, browser and editor phase: memory pressure (full avg10), max", "%", "lower",
           "workload.before_container.psi_full_avg10_max", group="workload", usable=_browser_editor_attempted,
           family="wl_pressure"),
    Metric("wl_available_min", "Workload, browser and editor phase: lowest MemAvailable", "MiB", "higher",
           "workload.before_container.mem_available_min_mib", group="workload", usable=_browser_editor_attempted,
           family="wl_pressure"),
    Metric("wl_oom", "Workload, browser and editor phase: OOM kills (kernel + systemd-oomd)", "count", "lower",
           "workload.before_container.oom_kills_total", group="workload", usable=_browser_editor_attempted),
    Metric("wl_editor", "Workload: editor pass", "s", "lower", "workload.editor_s", group="workload", usable=_editor_ok),
    Metric("wl_container", "Workload: container build", "s", "lower", "workload.container_s", group="workload",
           usable=_workload_ran, same=("workload.container_tool",)),
    Metric("wl_completion", "Workload completion time, all three steps", "s", "lower", "workload.completion_s",
           group="workload", usable=_workload_ran, same=("workload.container_tool",),
           note="Includes the container step, so it compares only runs that used the same container tool."),
]
GROUP_TITLES = {
    "runs": "Runs (every planned run, valid or not)",
    "idle": "Idle (10 min settle, then 30 samples at 10 s)",
    "boot": "Boot and login (firmware excluded)",
    "security": "Security and exposure",
    "privacy": "Privacy (power-on to the end of the idle window)",
    "footprint": "Footprint",
    "workload": "Workload under memory pressure (experimental)",
}
# Headline figures whose split by lane position (first or second in the cell)
# is published, to show whether running first or second moved them.
POSITION_METRICS = ("idle_used_mean", "idle_cpu", "idle_writes", "boot_greeter")


@dataclass
class Stats:
    values: list[float]
    runs: list[str]
    n: int = 0
    median: float | None = None
    minimum: float | None = None
    maximum: float | None = None
    q1: float | None = None
    q3: float | None = None
    extra: dict = field(default_factory=dict)

    @classmethod
    def of(cls, pairs: list[tuple[float, str]]) -> "Stats":
        values = [v for v, _ in pairs]
        stats = cls(values=values, runs=[r for _, r in pairs], n=len(values))
        if values:
            stats.median = statistics.median(values)
            stats.minimum, stats.maximum = min(values), max(values)
            if len(values) >= 2:
                stats.q1, _, stats.q3 = statistics.quantiles(values, n=4, method="inclusive")
            else:
                stats.q1 = stats.q3 = values[0]
        return stats

    @property
    def iqr(self):
        return None if self.q1 is None else self.q3 - self.q1

    def as_dict(self) -> dict:
        return {"n": self.n, "median": self.median, "min": self.minimum, "max": self.maximum,
                "q1": self.q1, "q3": self.q3, "iqr": self.iqr, "runs": self.runs}


def verdict(metric: Metric, subject: Stats, rival: Stats, subject_name: str, rival_name: str) -> tuple[str, str]:
    """(code, sentence). code is WIN, LOSS, TIE or NO_CLAIM."""
    if subject.n < MIN_RUNS or rival.n < MIN_RUNS:
        return "NO_CLAIM", (f"fewer than {MIN_RUNS} valid runs ({subject_name} {subject.n}, "
                            f"{rival_name} {rival.n})")
    lower = metric.better == "lower"
    if subject.median == rival.median:
        return "TIE", "equal medians"
    subject_better = subject.median < rival.median if lower else subject.median > rival.median
    if lower:
        subject_clear = subject.maximum < rival.minimum
        rival_clear = rival.maximum < subject.minimum
    else:
        subject_clear = subject.minimum > rival.maximum
        rival_clear = rival.minimum > subject.maximum
    if subject_better and subject_clear:
        return "WIN", f"{subject_name} median better and ranges do not overlap"
    if not subject_better and rival_clear:
        return "LOSS", f"{rival_name} median better and ranges do not overlap"
    better = subject_name if subject_better else rival_name
    return "NO_CLAIM", f"{better} has the better median, but the ranges overlap"


def load_results(directories: list[Path]) -> list[dict]:
    results = []
    for directory in directories:
        for path in sorted(Path(directory).rglob("result.json")):
            try:
                document = json.loads(path.read_text())
            except (OSError, json.JSONDecodeError) as error:
                print(f"bench_report: skipping {path}: {error}", file=sys.stderr)
                continue
            document.setdefault("meta", {})
            document["_path"] = str(path)
            results.append(document)
    return results


def missing_from_plan(plan: dict, results: list[dict]) -> list[dict]:
    """A failed result for every planned (cell, lane) that never reported.

    A cell that timed out, was cancelled or lost its runner uploads nothing,
    and a report built only from what arrived would never see it."""
    seen = {(str(r["meta"].get("cell")), str(r["meta"].get("lane"))) for r in results}
    missing = []
    for cell in plan.get("cells", []):
        for lane in str(cell.get("order", "")).split(","):
            if lane and (str(cell.get("cell")), lane) not in seen:
                missing.append({
                    "meta": {"lane": lane, "shape_mib": cell.get("shape"), "cell": cell.get("cell"),
                             "run_id": f"{plan.get('seed')}.{cell.get('cell')}.{lane}", "missing": True},
                    "validity": {"valid_for_claims": False,
                                 "reasons": ["no result: the planned run never reported "
                                             "(its cell failed, timed out or was cancelled)"]},
                    "_path": "(plan)",
                })
    return missing


def run_id(result: dict) -> str:
    return str(result["meta"].get("run_id") or result["_path"])


def fmt(value, unit: str = "") -> str:
    if value is None:
        return "–"
    if float(value).is_integer() and unit not in ("bytes", "bytes / window"):
        return f"{int(value):,}"
    if unit in ("bytes", "bytes / window"):
        return f"{value / 1024:,.1f} KiB" if value < 1048576 else f"{value / 1048576:,.2f} MiB"
    if abs(value) >= 100:
        return f"{value:,.0f}"
    if abs(value) >= 1:
        return f"{value:,.2f}"
    return f"{value:.4f}"


def stat_cell(stats: Stats | None, unit: str) -> str:
    if not stats or stats.n == 0:
        return "no valid runs"
    return (f"{fmt(stats.median, unit)} [{fmt(stats.minimum, unit)}–{fmt(stats.maximum, unit)}], "
            f"IQR {fmt(stats.iqr, unit)}, n={stats.n}")


def _values(runs: list[dict], key: str, skip_unknown: bool) -> set[str]:
    found = set()
    for r in runs:
        if skip_unknown and r["meta"].get("missing"):
            continue
        value = fact(r, key)
        if value is None and skip_unknown:
            continue
        found.add(str(value))
    return found


def incomparable(metric: Metric, subject_runs: list[dict], rival_runs: list[dict],
                 subject: str = "subject", rival: str = "rival") -> str | None:
    """Why the runs behind a comparison do not measure the same thing, or None."""
    skip = metric.all_runs  # failed runs may lack facts the probe would have recorded
    for name, runs in ((subject, subject_runs), (rival, rival_runs)):
        for key in LANE_SETUP_KEYS:
            values = _values(runs, key, skip)
            if len(values) > 1:
                return f"{name} runs mix {key} ({'/'.join(sorted(values))})"
    if not subject_runs or not rival_runs:
        return None
    for key in MACHINE_KEYS + COMMON_SAME + metric.same:
        a, b = _values(subject_runs, key, skip), _values(rival_runs, key, skip)
        if a != b:
            return f"{key} differs ({'/'.join(sorted(a))} vs {'/'.join(sorted(b))})"
    return None


def aggregate(results: list[dict], subject: str, include_invalid: bool = False) -> dict:
    lanes = sorted({r["meta"].get("lane", "?") for r in results})
    shapes = sorted({int(r["meta"].get("shape_mib") or 0) for r in results}, reverse=True)
    rivals = [lane for lane in lanes if lane != subject]
    groups: dict = {}
    for result in results:
        key = (result["meta"].get("lane", "?"), int(result["meta"].get("shape_mib") or 0))
        groups.setdefault(key, []).append(result)
    table: dict = {}
    for (lane, shape), runs in groups.items():
        valid = [r for r in runs if (r.get("validity") or {}).get("valid_for_claims")]
        counted = runs if include_invalid else valid
        entry = {
            "runs": [run_id(r) for r in runs],
            "valid_runs": [run_id(r) for r in valid],
            "invalid": {run_id(r): (r.get("validity") or {}).get("reasons", []) for r in runs if r not in valid},
            "metrics": {},
            "used": {},
            "context": context(runs),
        }
        for metric in METRICS:
            pool = runs if metric.all_runs else counted
            pairs, used = [], []
            for r in pool:
                if metric.usable and not metric.usable(r):
                    continue
                v = metric.value(r)
                if v is not None:
                    pairs.append((v, run_id(r)))
                    used.append(r)
            entry["metrics"][metric.key] = Stats.of(pairs)
            entry["used"][metric.key] = used
        entry["context"]["position"] = position_split(counted)
        table[(lane, shape)] = entry
    comparisons = []
    for rival in rivals:
        for shape in shapes:
            s_entry, r_entry = table.get((subject, shape)), table.get((rival, shape))
            if not s_entry or not r_entry:
                continue
            for metric in METRICS:
                s_stats, r_stats = s_entry["metrics"][metric.key], r_entry["metrics"][metric.key]
                if s_stats.n == 0 and r_stats.n == 0:
                    continue
                s_used, r_used = s_entry["used"][metric.key], r_entry["used"][metric.key]
                mismatch = incomparable(metric, s_used, r_used, subject, rival)
                if mismatch:
                    code, reason = "NOT_COMPARABLE", mismatch
                elif include_invalid:
                    code, reason = "NO_CLAIM", "informational report: includes runs that are not valid for a claim"
                else:
                    code, reason = verdict(metric, s_stats, r_stats, subject, rival)
                    if metric.lower_bound:
                        winner, runs_behind = ((subject, s_used) if code == "WIN" else
                                               (rival, r_used) if code == "LOSS" else (None, []))
                        bounded = sum(1 for r in runs_behind if metric.lower_bound(r))
                        if bounded:
                            code, reason = "NO_CLAIM", (f"{winner}'s figure is only a lower bound in {bounded} of "
                                                        f"{len(runs_behind)} runs, so it cannot win")
                worse_median = (s_stats.median is not None and r_stats.median is not None
                                and ((s_stats.median > r_stats.median) if metric.better == "lower"
                                     else (s_stats.median < r_stats.median)))
                comparisons.append({
                    "rival": rival, "shape_mib": shape, "metric": metric.key, "label": metric.label,
                    "unit": metric.unit, "better": metric.better, "group": metric.group,
                    "family": metric.family or metric.key,
                    "verdict": code, "reason": reason, "subject_worse_median": worse_median,
                    "subject_missing": s_stats.n == 0 and r_stats.n > 0,
                    "subject": s_stats.as_dict(), "rival_stats": r_stats.as_dict(),
                })
    failures = {}
    for (lane, shape), entry in table.items():
        if lane == subject and entry["invalid"]:
            failures[shape] = entry["invalid"]
    return {"lanes": lanes, "shapes": shapes, "subject": subject, "rivals": rivals,
            "table": table, "comparisons": comparisons, "claims": family_claims(comparisons),
            "subject_failures": failures, "include_invalid": include_invalid}


def family_claims(comparisons: list[dict]) -> list[dict]:
    """One claim per family of figures: WIN only if the headline wins and nothing loses."""
    families: dict = {}
    for c in comparisons:
        families.setdefault((c["rival"], c["shape_mib"], c["family"]), []).append(c)
    claims = []
    for (rival, shape, family), members in families.items():
        headline = members[0]
        wins = [m["metric"] for m in members if m["verdict"] == "WIN"]
        losses = [m["metric"] for m in members if m["verdict"] == "LOSS"]
        if wins and losses:
            code = "CONFLICT"
        elif losses:
            code = "LOSS"
        elif headline["verdict"] == "WIN":
            code = "WIN"
        else:
            code = headline["verdict"]
        claims.append({"rival": rival, "shape_mib": shape, "family": family, "headline": headline["metric"],
                       "label": headline["label"], "unit": headline["unit"], "verdict": code,
                       "members": [m["metric"] for m in members], "wins": wins, "losses": losses,
                       "subject": headline["subject"], "rival_stats": headline["rival_stats"]})
    return claims


def position_split(runs: list[dict]) -> dict:
    """Headline medians by the lane's position in its cell (1 = ran first)."""
    out = {}
    for key in POSITION_METRICS:
        metric = next(m for m in METRICS if m.key == key)
        by_position: dict = {}
        for r in runs:
            position = r["meta"].get("position")
            v = metric.value(r)
            if position is not None and v is not None:
                by_position.setdefault(str(position), []).append(v)
        if len(by_position) > 1:
            out[key] = {p: {"median": statistics.median(v), "n": len(v)} for p, v in sorted(by_position.items())}
    return out


def context(runs: list[dict]) -> dict:
    def values(path):
        return sorted({str(dig(r, path)) for r in runs if dig(r, path) is not None})

    def numbers(path):
        found = [dig(r, path) for r in runs]
        found = [float(v) for v in found if isinstance(v, (int, float)) and not isinstance(v, bool)]
        return {"median": statistics.median(found), "min": min(found), "max": max(found)} if found else None

    return {
        "thp_mode": values("idle.memory.thp_mode"),
        "min_free_kbytes": numbers("idle.memory.min_free_kbytes"),
        "totalreserve_mib": numbers("idle.memory.totalreserve_mib"),
        "mem_total_mib": numbers("idle.memory.mem_total_mib"),
        "kernel": values("system.kernel"),
        "os": values("system.os_pretty"),
        "host_cpu": values("host.cpu_model"),
        "accel": values("meta.accel"),
        "resolution": values("meta.resolution"),
        "graphics": values("meta.graphics"),
        "login": values("meta.login"),
        "disk_encryption": values("meta.disk_encryption"),
        "disk_format": values("meta.disk_format"),
        "image": values("meta.image_sha256"),
        "warmup": values("meta.warmup"),
        "guest_steal_pct": numbers("idle.cpu.steal_pct"),
        "host_steal_pct": numbers("host.steal_pct_window"),
        "host_iowait_pct": numbers("host.iowait_pct_window"),
        "host_flush_wait_s": numbers("host.quiesce.flush_wait_s"),
        "probe_cpu_pct": numbers("idle.cpu.probe_pct"),
        "probe_memory_mib": numbers("idle.memory.probe_mean_mib"),
        "probe_write_bytes": numbers("idle.writes.probe_bytes"),
        "writes_attributed_pct": numbers("idle.writes.attributed_pct"),
        "zram": values("idle.memory.settings.zram_zram0_disksize"),
        "package_manager": values("footprint.package_manager"),
        "container_tool": values("workload.container_tool"),
    }


def markdown(report: dict, title: str) -> str:
    subject = report["subject"]
    lines = [f"# {title}", ""]
    ctx_all = [e["context"] for e in report["table"].values()]
    accel = sorted({a for c in ctx_all for a in c["accel"]})
    graphics = sorted({g for c in ctx_all for g in c["graphics"]})
    cpus = sorted({h for c in ctx_all for h in c["host_cpu"]})
    lines += [
        f"Every figure is a **VM** measurement ({', '.join(accel) or '?'}; host CPU {', '.join(cpus) or '?'}) with "
        f"**software rendering** ({'; '.join(graphics) or '?'}). It is not a claim about real hardware or GPUs.",
        "",
        f"Rule for a claim (D1): at least {MIN_RUNS} valid runs per system on the same VM shape, a better median, "
        "and min–max ranges that do not overlap. Cells show median [min–max], IQR and n over valid runs. "
        "Figures that read one quantity several ways are one family and one claim.",
        "",
    ]
    if report.get("include_invalid"):
        lines += ["**Informational report: the cells below include runs that are not valid for a claim "
                  "(non-canonical, incomplete, emulated or noisy). Nothing here is a result.**", ""]
    comparisons = report["comparisons"]
    claims = report.get("claims", [])
    losses = [c for c in comparisons if c["verdict"] == "LOSS"]
    worse = [c for c in comparisons if c["verdict"] != "LOSS" and (c["subject_worse_median"] or c["subject_missing"])]
    lines += ["## Losses (published with the wins)", ""]
    if not report["rivals"]:
        lines.append(f"- Only `{subject}` was measured, so nothing was compared and nothing is claimed.")
    elif losses:
        for c in losses:
            lines.append(f"- **LOSS** {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: "
                         f"{subject} {stat_cell(Stats(**_stats_args(c['subject'])), c['unit'])}; "
                         f"{c['rival']} {stat_cell(Stats(**_stats_args(c['rival_stats'])), c['unit'])}.")
    else:
        lines.append("- No metric met the rule in the rival's favour.")
    if report.get("subject_failures"):
        lines += ["", f"Runs of `{subject}` that failed or are not valid (every one is published):", ""]
        for shape, invalid in sorted(report["subject_failures"].items(), reverse=True):
            for rid, reasons in invalid.items():
                lines.append(f"- {shape} MiB `{rid}`: {'; '.join(reasons) or 'invalid'}")
    if worse:
        lines += ["", "Worse medians that are not a D1 loss (still published):", ""]
        for c in worse:
            if c["subject_missing"]:
                lines.append(f"- {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: no usable `{subject}` runs "
                             f"(`{c['rival']}` has {c['rival_stats']['n']}).")
            else:
                verdict_text = "not comparable, " if c["verdict"] == "NOT_COMPARABLE" else ""
                lines.append(f"- {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: {verdict_text}{c['reason']}.")
    lines += ["", "## Wins", ""]
    won = [c for c in claims if c["verdict"] == "WIN"]
    if not report["rivals"]:
        lines.append("- None: no rival lane ran.")
    elif won:
        for c in won:
            also = [m for m in c["wins"] if m != c["headline"]]
            lines.append(f"- **WIN** {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: "
                         f"{subject} {stat_cell(Stats(**_stats_args(c['subject'])), c['unit'])}; "
                         f"{c['rival']} {stat_cell(Stats(**_stats_args(c['rival_stats'])), c['unit'])}"
                         + (f" (one claim; the same family also passed on {', '.join(also)})" if also else "") + ".")
    else:
        lines.append("- None. No metric met the rule.")
    conflicts = [c for c in claims if c["verdict"] == "CONFLICT"]
    if conflicts:
        lines += ["", "Families whose figures disagree (no claim either way):", ""]
        for c in conflicts:
            lines.append(f"- {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: better on {', '.join(c['wins'])}; "
                         f"worse on {', '.join(c['losses'])}.")
    not_comparable = sorted({(c["label"], c["reason"]) for c in comparisons if c["verdict"] == "NOT_COMPARABLE"})
    if not_comparable:
        lines += ["", "Not comparable (reported, never judged):", ""]
        lines += [f"- {label}: {reason}" for label, reason in not_comparable]
    lines.append("")
    for shape in report["shapes"]:
        lines += [f"## {shape} MiB, 4 vCPU", ""]
        lanes = [lane for lane in report["lanes"] if (lane, shape) in report["table"]]
        for lane in lanes:
            entry = report["table"][(lane, shape)]
            lines.append(f"- `{lane}`: {len(entry['valid_runs'])} valid of {len(entry['runs'])} runs "
                         f"({', '.join(entry['valid_runs']) or 'none'}).")
            for rid, reasons in entry["invalid"].items():
                lines.append(f"  - excluded `{rid}`: {'; '.join(reasons) or 'invalid'}")
        lines.append("")
        verdicts = {(c["rival"], c["metric"]): c for c in comparisons if c["shape_mib"] == shape}
        for group, title_text in GROUP_TITLES.items():
            metrics = [m for m in METRICS if m.group == group]
            if not any(report["table"][(lane, shape)]["metrics"][m.key].n for lane in lanes for m in metrics):
                continue
            lines += [f"### {title_text}", ""]
            rival_columns = [r for r in report["rivals"] if r in lanes]
            lines.append("| Metric | " + " | ".join(f"`{lane}`" for lane in lanes)
                         + "".join(f" | vs `{r}`" for r in rival_columns) + " |")
            lines.append("|" + "---|" * (1 + len(lanes) + len(rival_columns)))
            for m in metrics:
                cells = [stat_cell(report["table"][(lane, shape)]["metrics"][m.key], m.unit) for lane in lanes]
                judged = []
                for rival in rival_columns:
                    c = verdicts.get((rival, m.key))
                    judged.append(f"{c['verdict'].replace('_', ' ')}: {c['reason']}" if c else "–")
                better = "lower" if m.better == "lower" else "higher"
                family = f" [family {m.family}]" if m.family else ""
                lines.append(f"| {m.label} ({m.unit}, {better} is better){family} | " + " | ".join(cells + judged) + " |")
            lines.append("")
        lines += ["### Context (recorded, never scored)", ""]
        for lane in lanes:
            c = report["table"][(lane, shape)]["context"]
            lines.append(f"- `{lane}`: THP {', '.join(c['thp_mode']) or '?'}; min_free_kbytes "
                         f"{_range(c['min_free_kbytes'])}; totalreserve {_range(c['totalreserve_mib'])} MiB; "
                         f"MemTotal {_range(c['mem_total_mib'])} MiB; zram {', '.join(c['zram']) or 'none'}; kernel "
                         f"{', '.join(c['kernel']) or '?'}; login {', '.join(c['login']) or '?'}; disk encryption "
                         f"{', '.join(c['disk_encryption']) or '?'}; disk format {', '.join(c['disk_format']) or '?'}; "
                         f"warm-up {', '.join(c['warmup']) or '?'}; guest steal {_range(c['guest_steal_pct'])} %; "
                         f"host steal {_range(c['host_steal_pct'])} %; host iowait {_range(c['host_iowait_pct'])} %; "
                         f"host flush wait {_range(c['host_flush_wait_s'])} s; probe CPU {_range(c['probe_cpu_pct'])} %, "
                         f"memory {_range(c['probe_memory_mib'])} MiB, writes {_range(c['probe_write_bytes'])} B; "
                         f"writes attributed to top-level cgroups {_range(c['writes_attributed_pct'])} %; "
                         f"package manager {', '.join(c['package_manager']) or '?'}; container tool "
                         f"{', '.join(c['container_tool']) or 'none'}.")
            if c.get("position"):
                parts = []
                for key, split in c["position"].items():
                    label = next(m.label for m in METRICS if m.key == key)
                    parts.append(f"{label}: " + " / ".join(
                        f"position {p} {fmt(v['median'])} (n={v['n']})" for p, v in split.items()))
                lines.append(f"  - by position in the cell: {'; '.join(parts)}.")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _stats_args(d: dict) -> dict:
    return {"values": [], "runs": d["runs"], "n": d["n"], "median": d["median"], "minimum": d["min"],
            "maximum": d["max"], "q1": d["q1"], "q3": d["q3"]}


def _range(stats) -> str:
    if not stats:
        return "?"
    if stats["min"] == stats["max"]:
        return fmt(stats["median"])
    return f"{fmt(stats['median'])} [{fmt(stats['min'])}–{fmt(stats['max'])}]"


def baseline(report: dict, subject: str) -> dict:
    out = {"schema": "punar-bench-baseline/1", "subject": subject, "min_runs": MIN_RUNS, "shapes": {}}
    for (lane, shape), entry in report["table"].items():
        if lane != subject:
            continue
        out["shapes"][str(shape)] = {
            "valid_runs": entry["valid_runs"],
            "image": entry["context"]["image"],
            "metrics": {k: v.as_dict() for k, v in entry["metrics"].items() if v.n},
        }
    return out


def to_json(report: dict) -> dict:
    return {
        "schema": "punar-bench-summary/2",
        "subject": report["subject"],
        "lanes": report["lanes"],
        "shapes": report["shapes"],
        "min_runs": MIN_RUNS,
        "groups": {
            f"{lane}@{shape}": {
                "runs": e["runs"], "valid_runs": e["valid_runs"], "invalid": e["invalid"],
                "context": e["context"], "metrics": {k: v.as_dict() for k, v in e["metrics"].items()},
            }
            for (lane, shape), e in report["table"].items()
        },
        "comparisons": report["comparisons"],
        "claims": report.get("claims", []),
        "wins": [c for c in report.get("claims", []) if c["verdict"] == "WIN"],
        "losses": [c for c in report["comparisons"] if c["verdict"] == "LOSS"],
        "subject_failures": {str(k): v for k, v in report.get("subject_failures", {}).items()},
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--subject", default="punar")
    parser.add_argument("--title", default="Punar benchmark")
    parser.add_argument("--md", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--baseline", type=Path, help="write the subject's per-shape medians (idle-gate input)")
    parser.add_argument("--plan", type=Path, help="bench_plan.py output: planned runs that never reported count as failed")
    parser.add_argument("--include-invalid", action="store_true",
                        help="smoke tests: show runs that are not valid for a claim (never judged, no baseline)")
    args = parser.parse_args(argv)
    results = load_results(args.results)
    if args.plan:
        results += missing_from_plan(json.loads(args.plan.read_text()), results)
    if not results:
        print("bench_report: no result.json found", file=sys.stderr)
        return 1
    report = aggregate(results, args.subject, include_invalid=args.include_invalid)
    if args.include_invalid and args.baseline:
        print("bench_report: --include-invalid never writes a baseline", file=sys.stderr)
        return 2
    text = markdown(report, args.title)
    if args.md:
        args.md.write_text(text)
    else:
        sys.stdout.write(text)
    if args.json:
        args.json.write_text(json.dumps(to_json(report), indent=2, sort_keys=True) + "\n")
    if args.baseline:
        args.baseline.write_text(json.dumps(baseline(report, args.subject), indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
