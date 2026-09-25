#!/usr/bin/env python3
"""Aggregate benchmark runs and compare systems under the D1 rule (tools/bench/README.md).

    bench_report.py RESULTS_DIR... --md SUMMARY.md --json SUMMARY.json
                    [--subject punar] [--baseline BASELINE.json]

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
claim" with the reason. A metric whose runs differ in something that makes
them incomparable (for example how the disk is unlocked) is "not
comparable". Losses and worse medians are always printed, in their own
section, whether or not there are wins; the word "win" is never used for a
result that did not pass the rule.
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


def dig(document: dict, path: str):
    value = document
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


@dataclass
class Metric:
    key: str
    label: str
    unit: str
    better: str  # "lower" or "higher"
    path: str | None = None
    compute: Callable[[dict], float | None] | None = None
    group: str = "idle"
    # Run facts (result["meta"] keys) that must be equal across the systems
    # being compared, or the metric is "not comparable".
    same: tuple[str, ...] = ()
    # A run is used for this metric only when this returns True.
    usable: Callable[[dict], bool] | None = None
    note: str = ""

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


def _workload_ran(result: dict) -> bool:
    return bool((result.get("workload") or {}).get("all_steps_ran"))


def _scanned(result: dict) -> bool:
    return bool((dig(result, "exposure.scan") or {}).get("complete"))


METRICS = [
    Metric("idle_used_mean", "Idle RAM used (MemTotal - MemAvailable), mean", "MiB", "lower", "idle.memory.used_mean_mib"),
    Metric("idle_used_max", "Idle RAM used, max", "MiB", "lower", "idle.memory.used_max_mib"),
    Metric("idle_used_net", "Idle RAM used, probe subtracted", "MiB", "lower", "idle.memory.used_net_mean_mib"),
    Metric("idle_used_minus_reserve", "Idle RAM used minus the kernel's MemAvailable reserve", "MiB", "lower",
           "idle.memory.used_minus_reserve_mean_mib",
           note="Removes the watermark reserve THP raises; both figures are published."),
    Metric("idle_available", "MemAvailable, mean", "MiB", "higher", "idle.memory.mem_available_mean_mib"),
    Metric("idle_anon", "Anonymous memory (AnonPages)", "MiB", "lower", "idle.memory.anon_mean_mib"),
    Metric("idle_unevictable", "Unevictable memory", "MiB", "lower", "idle.memory.unevictable_mean_mib"),
    Metric("idle_shmem", "Shared memory (Shmem)", "MiB", "lower", "idle.memory.shmem_mean_mib"),
    Metric("idle_swap", "Swap in use", "MiB", "lower", "idle.memory.swap_used_mean_mib"),
    Metric("idle_pss_total", "Summed process PSS", "MiB", "lower", "idle.memory.pss_total_mib"),
    Metric("idle_cpu", "Idle CPU, whole system, probe subtracted", "% of all CPUs", "lower", "idle.cpu.system_pct_net"),
    Metric("idle_interrupts", "Interrupts (wakeups)", "per s", "lower", "idle.cpu.interrupts_per_s"),
    Metric("idle_ctxt", "Context switches", "per s", "lower", "idle.cpu.ctxt_per_s"),
    Metric("idle_writes", "Idle disk writes, whole device, probe subtracted", "bytes / window", "lower",
           "idle.writes.device_bytes_net"),
    Metric("idle_writes_journald", "Idle writes charged to journald", "bytes / window", "lower", "idle.writes.journald_bytes"),
    Metric("idle_writes_remainder", "Idle writes no cgroup was charged for (kernel/filesystem)", "bytes / window", "lower",
           "idle.writes.kernel_fs_remainder_bytes"),
    Metric("idle_psi_memory", "Memory pressure (some), share of the window", "%", "lower", "idle.pressure.memory_some_stall_pct"),
    Metric("idle_psi_cpu", "CPU pressure (some), share of the window", "%", "lower", "idle.pressure.cpu_some_stall_pct"),
    Metric("idle_psi_io", "I/O pressure (some), share of the window", "%", "lower", "idle.pressure.io_some_stall_pct"),
    Metric("boot_kernel", "Boot: kernel", "s", "lower", "boot.kernel_s", group="boot", same=("disk_encryption",)),
    Metric("boot_initrd", "Boot: initrd", "s", "lower", "boot.initrd_s", group="boot", same=("disk_encryption", "login")),
    Metric("boot_userspace", "Boot: userspace to boot finished", "s", "lower", "boot.userspace_s", group="boot",
           same=("disk_encryption", "login")),
    Metric("boot_graphical", "Boot: kernel start to graphical.target", "s", "lower", "boot.kernel_to_graphical_target_s",
           group="boot", same=("disk_encryption", "login")),
    Metric("boot_greeter", "Boot: kernel start to the greeter's shell", "s", "lower", "boot.kernel_to_greeter_shell_s",
           group="boot", same=("disk_encryption", "login")),
    Metric("boot_login", "Login: session start to the shell process", "s", "lower", "boot.login_to_shell_s",
           group="boot", same=("login",)),
    Metric("sec_unsafe", "Services rated UNSAFE by systemd-analyze security", "count", "lower",
           "security.services_unsafe", group="security"),
    Metric("sec_exposure", "Mean systemd-analyze security exposure", "0-10", "lower", "security.exposure_mean", group="security"),
    Metric("sec_setuid", "setuid files", "count", "lower", "security.setuid_count", group="security"),
    Metric("sec_setgid", "setgid files", "count", "lower", "security.setgid_count", group="security"),
    Metric("sec_listeners", "Non-loopback listening sockets (guest view)", "count", "lower",
           "exposure.guest.non_loopback_count", group="security"),
    Metric("sec_open_tcp", "Open TCP ports reachable from the network", "count", "lower", "exposure.scan.open_tcp_total",
           group="security", usable=_scanned),
    Metric("sec_open_udp", "Open UDP ports reachable from the network", "count", "lower", "exposure.scan.open_udp_total",
           group="security", usable=_scanned),
    Metric("priv_destinations", "Internet destinations contacted, power-on to end of idle", "count", "lower",
           "privacy.internet_destination_count", group="privacy", same=("net",)),
    Metric("priv_names", "Distinct names looked up or sent (DNS, SNI)", "count", "lower", "privacy.distinct_name_count",
           group="privacy", same=("net",)),
    Metric("priv_bytes_out", "Bytes sent to the internet", "bytes", "lower", "privacy.internet_bytes_out",
           group="privacy", same=("net",)),
    Metric("priv_identifiers", "Kinds of identifier volunteered on the network", "count", "lower",
           compute=_identifier_kinds, group="privacy", same=("net",)),
    Metric("fp_root", "Root filesystem used", "MiB", "lower", "footprint.root_used_mib", group="footprint"),
    Metric("fp_packages", "Installed packages", "count", "lower", "footprint.packages", group="footprint"),
    Metric("fp_enabled", "Enabled unit files", "count", "lower", "footprint.enabled_unit_files", group="footprint"),
    Metric("fp_running", "Running services at idle", "count", "lower", "footprint.running_services", group="footprint"),
    Metric("wl_completion", "Workload completion time", "s", "lower", "workload.completion_s", group="workload",
           usable=_workload_ran, note="Experimental lane; runs where a step did not run are excluded."),
    Metric("wl_editor", "Workload: editor pass", "s", "lower", "workload.editor_s", group="workload", usable=_workload_ran),
    Metric("wl_container", "Workload: container build", "s", "lower", "workload.container_s", group="workload",
           usable=_workload_ran),
    Metric("wl_psi_full", "Workload: memory pressure (full avg10), max", "%", "lower", "workload.psi_full_avg10_max",
           group="workload", usable=_workload_ran),
    Metric("wl_oom", "Workload: OOM kills (kernel + systemd-oomd)", "count", "lower", "workload.oom_kills_total",
           group="workload", usable=_workload_ran),
    Metric("wl_available_min", "Workload: lowest MemAvailable", "MiB", "higher", "workload.mem_available_min_mib",
           group="workload", usable=_workload_ran),
]
GROUP_TITLES = {
    "idle": "Idle (10 min settle, then 30 samples at 10 s)",
    "boot": "Boot and login (firmware excluded)",
    "security": "Security and exposure",
    "privacy": "Privacy (power-on to the end of the idle window)",
    "footprint": "Footprint",
    "workload": "Workload under memory pressure (experimental)",
}


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


def aggregate(results: list[dict], subject: str, include_invalid: bool = False) -> dict:
    lanes = sorted({r["meta"].get("lane", "?") for r in results})
    shapes = sorted({int(r["meta"].get("shape_mib", 0)) for r in results}, reverse=True)
    rivals = [lane for lane in lanes if lane != subject]
    groups: dict = {}
    for result in results:
        key = (result["meta"].get("lane", "?"), int(result["meta"].get("shape_mib", 0)))
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
            "context": context(runs),
        }
        for metric in METRICS:
            pairs = []
            for r in counted:
                if metric.usable and not metric.usable(r):
                    continue
                v = metric.value(r)
                if v is not None:
                    pairs.append((v, run_id(r)))
            entry["metrics"][metric.key] = Stats.of(pairs)
        table[(lane, shape)] = entry
    comparisons = []
    for rival in rivals:
        for shape in shapes:
            s_entry, r_entry = table.get((subject, shape)), table.get((rival, shape))
            if not s_entry or not r_entry:
                continue
            for metric in METRICS:
                s_stats, r_stats = s_entry["metrics"][metric.key], r_entry["metrics"][metric.key]
                mismatch = incomparable(metric, groups.get((subject, shape), []), groups.get((rival, shape), []))
                if mismatch:
                    code, reason = "NOT_COMPARABLE", mismatch
                elif s_stats.n == 0 and r_stats.n == 0:
                    continue
                elif include_invalid:
                    code, reason = "NO_CLAIM", "informational report: includes runs that are not valid for a claim"
                else:
                    code, reason = verdict(metric, s_stats, r_stats, subject, rival)
                worse_median = (s_stats.median is not None and r_stats.median is not None
                                and ((s_stats.median > r_stats.median) if metric.better == "lower"
                                     else (s_stats.median < r_stats.median)))
                comparisons.append({
                    "rival": rival, "shape_mib": shape, "metric": metric.key, "label": metric.label,
                    "unit": metric.unit, "better": metric.better, "group": metric.group,
                    "verdict": code, "reason": reason, "subject_worse_median": worse_median,
                    "subject": s_stats.as_dict(), "rival_stats": r_stats.as_dict(),
                })
    return {"lanes": lanes, "shapes": shapes, "subject": subject, "rivals": rivals,
            "table": table, "comparisons": comparisons, "include_invalid": include_invalid}


def incomparable(metric: Metric, subject_runs: list[dict], rival_runs: list[dict]) -> str | None:
    for key in metric.same:
        a = {str(r["meta"].get(key)) for r in subject_runs}
        b = {str(r["meta"].get(key)) for r in rival_runs}
        if a != b:
            return f"{key} differs ({'/'.join(sorted(a))} vs {'/'.join(sorted(b))})"
    return None


def context(runs: list[dict]) -> dict:
    def values(path):
        return sorted({str(dig(r, path)) for r in runs if dig(r, path) is not None})

    def numbers(path):
        found = [dig(r, path) for r in runs]
        found = [float(v) for v in found if isinstance(v, (int, float))]
        return {"median": statistics.median(found), "min": min(found), "max": max(found)} if found else None

    return {
        "thp_mode": values("idle.memory.thp_mode"),
        "min_free_kbytes": numbers("idle.memory.min_free_kbytes"),
        "kernel": values("system.kernel"),
        "os": values("system.os_pretty"),
        "host_cpu": values("host.cpu_model"),
        "accel": values("meta.accel"),
        "resolution": values("meta.resolution"),
        "graphics": values("meta.graphics"),
        "login": values("meta.login"),
        "disk_encryption": values("meta.disk_encryption"),
        "image": values("meta.image_sha256"),
        "guest_steal_pct": numbers("idle.cpu.steal_pct"),
        "host_steal_pct": numbers("host.steal_pct_window"),
        "probe_cpu_pct": numbers("idle.cpu.probe_pct"),
        "probe_memory_mib": numbers("idle.memory.probe_mean_mib"),
        "probe_write_bytes": numbers("idle.writes.probe_bytes"),
        "writes_attributed_pct": numbers("idle.writes.attributed_pct"),
        "zram": values("idle.memory.settings.zram_zram0_disksize"),
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
        "and min–max ranges that do not overlap. Cells show median [min–max], IQR and n over valid runs.",
        "",
    ]
    if report.get("include_invalid"):
        lines += ["**Informational report: the cells below include runs that are not valid for a claim "
                  "(non-canonical, incomplete, emulated or noisy). Nothing here is a result.**", ""]
    comparisons = report["comparisons"]
    wins = [c for c in comparisons if c["verdict"] == "WIN"]
    losses = [c for c in comparisons if c["verdict"] == "LOSS"]
    worse = [c for c in comparisons
             if c["verdict"] not in ("LOSS", "NOT_COMPARABLE") and c["subject_worse_median"]]
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
    if worse:
        lines += ["", "Worse medians that are not a D1 loss (still published):", ""]
        for c in worse:
            lines.append(f"- {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: {c['reason']}.")
    lines += ["", "## Wins", ""]
    if not report["rivals"]:
        lines.append("- None: no rival lane ran.")
    elif wins:
        for c in wins:
            lines.append(f"- **WIN** {c['label']} at {c['shape_mib']} MiB vs {c['rival']}: "
                         f"{subject} {stat_cell(Stats(**_stats_args(c['subject'])), c['unit'])}; "
                         f"{c['rival']} {stat_cell(Stats(**_stats_args(c['rival_stats'])), c['unit'])}.")
    else:
        lines.append("- None. No metric met the rule.")
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
        for group, title in GROUP_TITLES.items():
            metrics = [m for m in METRICS if m.group == group]
            if not any(report["table"][(lane, shape)]["metrics"][m.key].n for lane in lanes for m in metrics):
                continue
            lines += [f"### {title}", ""]
            rival_columns = [r for r in report["rivals"] if r in lanes]
            lines.append("| Metric | " + " | ".join(f"`{lane}`" for lane in lanes)
                         + "".join(f" | vs `{r}`" for r in rival_columns) + " |")
            lines.append("|" + "---|" * (1 + len(lanes) + len(rival_columns)))
            for m in metrics:
                cells = [stat_cell(report["table"][(lane, shape)]["metrics"][m.key], m.unit) for lane in lanes]
                judged = []
                for rival in report["rivals"]:
                    if rival not in lanes:
                        continue
                    c = verdicts.get((rival, m.key))
                    judged.append(f"{c['verdict'].replace('_', ' ')}: {c['reason']}" if c else "–")
                better = "lower" if m.better == "lower" else "higher"
                lines.append(f"| {m.label} ({m.unit}, {better} is better) | " + " | ".join(cells + judged) + " |")
            lines.append("")
        lines += ["### Context (recorded, never scored)", ""]
        for lane in lanes:
            c = report["table"][(lane, shape)]["context"]
            lines.append(f"- `{lane}`: THP {', '.join(c['thp_mode']) or '?'}; min_free_kbytes "
                         f"{_range(c['min_free_kbytes'])}; zram {', '.join(c['zram']) or 'none'}; kernel "
                         f"{', '.join(c['kernel']) or '?'}; login {', '.join(c['login']) or '?'}; disk encryption "
                         f"{', '.join(c['disk_encryption']) or '?'}; guest steal {_range(c['guest_steal_pct'])} %; "
                         f"host steal {_range(c['host_steal_pct'])} %; probe CPU {_range(c['probe_cpu_pct'])} %, "
                         f"memory {_range(c['probe_memory_mib'])} MiB, writes {_range(c['probe_write_bytes'])} B; "
                         f"writes attributed to top-level cgroups {_range(c['writes_attributed_pct'])} %.")
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
        "schema": "punar-bench-summary/1",
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
        "wins": [c for c in report["comparisons"] if c["verdict"] == "WIN"],
        "losses": [c for c in report["comparisons"] if c["verdict"] == "LOSS"],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("results", nargs="+", type=Path)
    parser.add_argument("--subject", default="punar")
    parser.add_argument("--title", default="Punar benchmark")
    parser.add_argument("--md", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--baseline", type=Path, help="write the subject's per-shape medians (idle-gate input)")
    parser.add_argument("--include-invalid", action="store_true",
                        help="smoke tests: show runs that are not valid for a claim (never judged, no baseline)")
    args = parser.parse_args(argv)
    results = load_results(args.results)
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
