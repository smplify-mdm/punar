#!/usr/bin/env python3
"""Turn one run's probe stream into a result document (tools/bench/README.md).

    bench_parse.py EXPORT.jsonl [--host HOST.json] [--out RESULT.json]

EXPORT.jsonl is what bench-probe.sh streamed over the bench.export port;
HOST.json is what bench_run.py measured from outside the guest (clocks, host
steal, packet capture, port scan). Every derived number is computed here, in
one place, from raw counters the probe recorded, so a reader can recompute
it. Nothing here decides a winner: bench_report.py does that.

Rules this file keeps (tools/bench/README.md, "Attribution"):
- idle writes: the device total comes from the root cgroup's io.stat for the
  physical disks (the disk's own counter) or diskstats. Cgroups are charged
  on the device their writes enter: the top of each device-mapper/md stack
  (dm-crypt's dm-0, not the disk under it) and any physical disk that
  carries no such stack. Top-level cgroups are summed; the rest is the
  kernel/filesystem remainder. The root is never added to its children, and
  a cgroup's bytes on the disk under a stack are never added to its bytes
  on the stack.
- the probe's own CPU, memory and writes are reported and subtracted.
- a run is valid for a claim only when it is canonical (600 s settle, 30
  samples at 10 s), complete, ran under KVM, and host and guest steal were
  both measured and both <= 2%. Missing data never passes the gate.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import statistics
import sys
from pathlib import Path

SCHEMA = "punar-bench-run/1"
STEAL_LIMIT_PCT = 2.0
KIB = 1024.0


def load_stream(path: Path) -> list[dict]:
    records = []
    with open(path, "rb") as handle:
        for raw in handle:
            line = raw.decode("utf-8", errors="replace").strip()
            if not line.startswith("{"):
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                # A run cut short can leave a partial last line.
                continue
    return records


def first(records: list[dict], kind: str, **match) -> dict | None:
    for record in records:
        if record.get("type") == kind and all(record.get(k) == v for k, v in match.items()):
            return record
    return None


def num(value, default=None):
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def mean(values):
    values = [v for v in values if v is not None]
    return statistics.fmean(values) if values else None


def rnd(value, places=3):
    return None if value is None else round(value, places)


# ---- memory -------------------------------------------------------------------

def memory_section(samples: list[dict], processes: dict | None, mm: dict | None,
                   shape_mib: float | None = None) -> dict:
    def series(key):
        return [num(s["meminfo"].get(key)) for s in samples if key in s.get("meminfo", {})]

    used = [num(s["meminfo"].get("MemTotal")) - num(s["meminfo"].get("MemAvailable"))
            for s in samples
            if num(s.get("meminfo", {}).get("MemTotal")) is not None
            and num(s.get("meminfo", {}).get("MemAvailable")) is not None]
    probe = []
    for s in samples:
        p = s.get("probe", {})
        anon, kernel, current = num(p.get("anon")), num(p.get("kernel")), num(p.get("memory_current"))
        if anon is not None:
            probe.append((anon + (kernel or 0)) / KIB)
        elif current is not None:
            probe.append(current / KIB)
    net = [u - p for u, p in zip(used, probe)] if len(probe) == len(used) and probe else []

    def kb_mean(key):
        return mean(series(key))

    reclaimable = "KReclaimable" if any("KReclaimable" in s.get("meminfo", {}) for s in samples) else "SReclaimable"
    # MemAvailable = MemFree - totalreserve + (file LRU - min(file LRU/2, low))
    #              + (KReclaimable - min(KReclaimable/2, low))      (si_mem_available)
    # so MemFree + file LRU + KReclaimable - MemAvailable is exactly what the
    # kernel held back for its watermarks: totalreserve (high watermark and
    # lowmem reserve, from /proc/zoneinfo) plus up to twice the low watermark
    # kept out of page cache and reclaimable slab.
    deductions = []
    for s in samples:
        m = s.get("meminfo", {})
        parts = [num(m.get(k)) for k in ("MemFree", "Active(file)", "Inactive(file)", reclaimable, "MemAvailable")]
        if None not in parts:
            deductions.append(parts[0] + parts[1] + parts[2] + parts[3] - parts[4])
    swap_used = [num(s["meminfo"].get("SwapTotal")) - num(s["meminfo"].get("SwapFree"))
                 for s in samples
                 if num(s.get("meminfo", {}).get("SwapTotal")) is not None
                 and num(s.get("meminfo", {}).get("SwapFree")) is not None]

    def mib(value):
        return rnd(value / KIB if value is not None else None, 1)

    totalreserve_kib = None
    if mm and num(mm.get("zone_totalreserve_pages")) is not None:
        page_kib = (num(mm.get("pagesize"), 4096) or 4096) / 1024.0
        totalreserve_kib = num(mm.get("zone_totalreserve_pages")) * page_kib
    available = series("MemAvailable")
    out = {
        "samples": len(used),
        "used_mean_mib": mib(mean(used)),
        "used_max_mib": mib(max(used) if used else None),
        "used_min_mib": mib(min(used) if used else None),
        "probe_mean_mib": mib(mean(probe)),
        "used_net_mean_mib": mib(mean(net)) if net else None,
        # Everything MemAvailable leaves out for watermarks (see above).
        "watermark_deductions_mean_mib": mib(mean(deductions)),
        # MemTotal - MemFree - file LRU - KReclaimable: memory that is neither
        # free nor page cache nor reclaimable slab.
        "unreclaimable_used_mean_mib": mib(mean(used) - mean(deductions)) if used and deductions else None,
        # The kernel's own reserve (high watermark + lowmem reserve, which
        # THP's min_free_kbytes raises), from /proc/zoneinfo, and used without it.
        "totalreserve_mib": mib(totalreserve_kib),
        "used_minus_totalreserve_mean_mib": mib(mean(used) - totalreserve_kib)
        if used and totalreserve_kib is not None else None,
        # Memory at boot never reaches MemTotal (kernel image, reservations),
        # so "used" cannot see it; the machine's memory minus MemAvailable can.
        "shape_minus_available_mean_mib": rnd(shape_mib - mean(available) / KIB, 1)
        if shape_mib and available else None,
        "mem_available_mean_mib": mib(kb_mean("MemAvailable")),
        "anon_mean_mib": mib(kb_mean("AnonPages")),
        "unevictable_mean_mib": mib(kb_mean("Unevictable")),
        "mlocked_mean_mib": mib(kb_mean("Mlocked")),
        "shmem_mean_mib": mib(kb_mean("Shmem")),
        "kreclaimable_mean_mib": mib(kb_mean(reclaimable)),
        "sunreclaim_mean_mib": mib(kb_mean("SUnreclaim")),
        "page_tables_mean_mib": mib(kb_mean("PageTables")),
        "kernel_stack_mean_mib": mib(kb_mean("KernelStack")),
        "swap_used_mean_mib": mib(mean(swap_used)),
        "mem_total_mib": mib(kb_mean("MemTotal")),
    }
    if processes:
        procs = processes.get("list", [])
        total = sum(num(p.get("pss"), 0) for p in procs)
        out["pss_total_mib"] = mib(total)
        out["pss_process_count"] = len(procs)
        top = sorted(procs, key=lambda p: num(p.get("pss"), 0), reverse=True)[:15]
        out["pss_top15"] = [
            {
                "comm": p.get("comm"),
                "pid": p.get("pid"),
                "uid": p.get("uid"),
                "cgroup": p.get("cgroup"),
                "pss_mib": mib(num(p.get("pss"), 0)),
                "pss_anon_mib": mib(num(p.get("pss_anon"), 0)),
                "pss_file_mib": mib(num(p.get("pss_file"), 0)),
                "pss_shmem_mib": mib(num(p.get("pss_shmem"), 0)),
            }
            for p in top
        ]
    if mm:
        out["settings"] = {k: v for k, v in mm.items() if k not in ("type", "phase", "uptime")}
        thp = str(mm.get("thp_enabled", ""))
        match = re.search(r"\[(\w+)\]", thp)
        out["thp_mode"] = match.group(1) if match else (thp or None)
        out["min_free_kbytes"] = num(mm.get("vm_min_free_kbytes"))
    return out


# ---- CPU, wakeups, pressure ------------------------------------------------------

CPU_FIELDS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice")


def cpu_split(vector):
    values = [num(v, 0) for v in vector]
    values += [0] * (10 - len(values))
    fields = dict(zip(CPU_FIELDS, values))
    total = sum(values[:8])
    idle = fields["idle"] + fields["iowait"]
    return total, idle, fields["steal"]


def cgroup_map(record: dict | None) -> dict:
    return {c["p"]: c for c in (record or {}).get("list", [])}


def depth(path: str) -> int:
    return 0 if path == "/" else path.strip("/").count("/") + 1


def delta(end, start, key):
    e = num((end or {}).get(key))
    s = num((start or {}).get(key), 0)
    if e is None:
        return None
    return e - s


def cpu_section(start: dict, end: dict, cg_start: dict, cg_end: dict, samples: list[dict],
                probe_cgroup: str | None) -> dict:
    window_s = num(end["uptime"]) - num(start["uptime"])
    cpus = start["stat"]["cpus"]
    ncpu = sum(1 for k in cpus if re.fullmatch(r"cpu\d+", k))
    t0, i0, s0 = cpu_split(start["stat"]["cpus"]["cpu"])
    t1, i1, s1 = cpu_split(end["stat"]["cpus"]["cpu"])
    total, idle, steal = t1 - t0, i1 - i0, s1 - s0
    busy = total - idle - steal
    out = {
        "window_s": rnd(window_s, 1),
        "ncpu": ncpu,
        "system_pct": rnd(100.0 * busy / total if total > 0 else None, 4),
        "steal_pct": rnd(100.0 * steal / total if total > 0 else None, 4),
        "interrupts_per_s": rnd((num(end["stat"].get("intr"), 0) - num(start["stat"].get("intr"), 0)) / window_s, 1),
        "ctxt_per_s": rnd((num(end["stat"].get("ctxt"), 0) - num(start["stat"].get("ctxt"), 0)) / window_s, 1),
    }
    irqs_start = {i["irq"]: num(i["total"], 0) for i in start.get("interrupts", [])}
    irq_rows = []
    for irq in end.get("interrupts", []):
        d = num(irq["total"], 0) - irqs_start.get(irq["irq"], 0)
        if d > 0:
            irq_rows.append({"irq": irq["irq"], "desc": irq.get("desc", ""), "per_s": rnd(d / window_s, 2)})
    out["top_interrupts"] = sorted(irq_rows, key=lambda r: r["per_s"], reverse=True)[:10]

    capacity_us = window_s * 1e6 * max(ncpu, 1)

    def pct(path):
        d = delta(cg_end.get(path), cg_start.get(path), "cpu_us")
        return None if d is None else 100.0 * d / capacity_us

    top_level = [(p, pct(p)) for p in cg_end if depth(p) == 1]
    out["top_level_cgroups"] = [
        {"cgroup": p, "cpu_pct": rnd(v, 4)}
        for p, v in sorted(top_level, key=lambda x: x[1] or 0, reverse=True)[:5] if v is not None
    ]
    parents = {p.rsplit("/", 1)[0] or "/" for p in cg_end if p != "/"}
    leaves = [(p, pct(p)) for p in cg_end if p not in parents and p != "/"]
    out["top_leaf_cgroups"] = [
        {"cgroup": p, "cpu_pct": rnd(v, 4)}
        for p, v in sorted(leaves, key=lambda x: x[1] or 0, reverse=True)[:10] if v is not None and v > 0
    ]
    probe_pct = pct(probe_cgroup) if probe_cgroup else None
    out["probe_pct"] = rnd(probe_pct, 4)
    if out["system_pct"] is not None and probe_pct is not None:
        out["system_pct_net"] = rnd(max(0.0, out["system_pct"] - probe_pct), 4)
    else:
        out["system_pct_net"] = out["system_pct"]
    return out


def pressure_section(start: dict, end: dict, samples: list[dict]) -> dict:
    window_us = (num(end["uptime"]) - num(start["uptime"])) * 1e6
    out = {}
    for resource, kinds in end.get("pressure", {}).items():
        for kind, values in kinds.items():
            s = num(start.get("pressure", {}).get(resource, {}).get(kind, {}).get("total"))
            e = num(values.get("total"))
            if s is not None and e is not None and window_us > 0:
                out[f"{resource}_{kind}_stall_pct"] = rnd(100.0 * (e - s) / window_us, 4)
            avg10 = [num(x.get("pressure", {}).get(resource, {}).get(kind, {}).get("avg10")) for x in samples]
            avg10 = [v for v in avg10 if v is not None]
            if avg10:
                out[f"{resource}_{kind}_avg10_max"] = max(avg10)
    return out


# ---- writes --------------------------------------------------------------------

def io_wbytes(entry: dict | None, devices: list[str]):
    if not entry:
        return None
    io = entry.get("io") or {}
    if not any(d in io for d in devices):
        return 0.0
    return sum(num(io[d][1], 0) for d in devices if d in io)


def is_partition_of(name: str, disk: str) -> bool:
    rest = name[len(disk):] if name.startswith(disk) else None
    return rest is not None and re.fullmatch(r"p?\d+", rest) is not None


def device_roles(device_list: list[dict]) -> tuple[list[str], list[str]]:
    """(physical disks, attribution devices) as MAJ:MIN.

    A write enters the block layer on the device its filesystem sits on and
    is charged there to the writer's cgroup. Under dm-crypt that is dm-0;
    the encrypted copy reaches the disk from a kernel worker, charged to the
    root cgroup or (on newer kernels) to the same cgroup again. So cgroups
    are attributed on the top of each dm/md stack plus every physical disk
    that no stack sits on, and the device total is always the physical
    disks'. zram is swap, not storage, and is in neither list.
    """
    disks = [d for d in device_list if d.get("kind") == "disk" and d.get("dev")]
    stacked = [d for d in device_list if d.get("kind") == "virtual" and d.get("dev")
               and not str(d.get("name", "")).startswith("zram")]
    slaves = {d.get("name"): [x for x in str(d.get("slaves") or "").split(",") if x and x != "-"] for d in stacked}
    below_a_stack = {x for names in slaves.values() for x in names}
    tops = [d["dev"] for d in stacked if d.get("name") not in below_a_stack and slaves.get(d.get("name"))]
    held = {d.get("name") for d in disks
            if any(x == d.get("name") or is_partition_of(x, str(d.get("name"))) for x in below_a_stack)}
    plain = [d["dev"] for d in disks if d.get("name") not in held]
    return [d["dev"] for d in disks], tops + plain


def writes_section(devices: list[str], cg_start: dict, cg_end: dict, start: dict, end: dict,
                   probe_cgroup: str | None, attribution: list[str] | None = None) -> dict:
    attribution = devices if attribution is None else attribution
    out = {"devices": devices, "attribution_devices": attribution}
    notes = []
    root_start = io_wbytes(cg_start.get("/"), devices)
    root_end = io_wbytes(cg_end.get("/"), devices)
    root_has_io = bool((cg_end.get("/") or {}).get("io"))
    disk_start = sum(num(start["diskstats"].get(d, {}).get("wr_sectors"), 0) for d in devices)
    disk_end = sum(num(end["diskstats"].get(d, {}).get("wr_sectors"), 0) for d in devices)
    diskstats_bytes = (disk_end - disk_start) * 512
    if root_has_io and root_end is not None and root_start is not None and root_end >= root_start:
        device_bytes, source = root_end - root_start, "cgroup-root"
    else:
        device_bytes, source = diskstats_bytes, "diskstats"
    out["device_bytes"] = device_bytes
    out["device_source"] = source
    out["diskstats_bytes"] = diskstats_bytes

    def write_delta(path):
        e = io_wbytes(cg_end.get(path), attribution)
        if e is None:
            return None
        s = io_wbytes(cg_start.get(path), attribution) or 0.0
        return e - s

    journald = write_delta("/system.slice/systemd-journald.service")
    out["journald_bytes"] = journald
    top = {}
    for path in cg_end:
        if depth(path) != 1:
            continue
        d = write_delta(path)
        if d is None:
            continue
        if d < 0:
            notes.append(f"{path} counter moved backwards")
            continue
        top[path] = d
    top_sum = sum(top.values())
    out["top_level_cgroups_bytes"] = top_sum
    out["top_level_cgroups"] = {p: v for p, v in sorted(top.items(), key=lambda x: x[1], reverse=True)}
    out["kernel_fs_remainder_bytes"] = max(0.0, device_bytes - top_sum)
    if top_sum > device_bytes:
        notes.append("top-level cgroups report more than the device (lazy flush); remainder is 0")
    out["attributed_pct"] = rnd(min(100.0, 100.0 * top_sum / device_bytes), 2) if device_bytes > 0 else None
    probe = write_delta(probe_cgroup) if probe_cgroup else None
    out["probe_bytes"] = probe
    out["device_bytes_net"] = max(0.0, device_bytes - (probe or 0))
    parents = {p.rsplit("/", 1)[0] or "/" for p in cg_end if p != "/"}
    leaves = [(p, write_delta(p)) for p in cg_end if p not in parents and p != "/"]
    out["top_leaf_writers"] = [
        {"cgroup": p, "bytes": v} for p, v in sorted(leaves, key=lambda x: x[1] or 0, reverse=True)[:10]
        if v
    ]
    out["notes"] = notes
    return out


# ---- blobs: boot, hardening, exposure, footprint -----------------------------------------

def blobs(records):
    return {r["name"]: r for r in records if r.get("type") == "blob"}


def keyvals(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def parse_duration(text: str):
    text = text.strip()
    match = re.fullmatch(r"(?:(\d+)min\s*)?(?:(\d+(?:\.\d+)?)s)?|(\d+(?:\.\d+)?)ms|(\d+(?:\.\d+)?)us", text)
    if not match or not text:
        return None
    minutes, seconds, millis, micros = match.groups()
    if millis:
        return float(millis) / 1000
    if micros:
        return float(micros) / 1e6
    return (float(minutes) * 60 if minutes else 0.0) + (float(seconds) if seconds else 0.0)


def boot_section(b: dict, facts: dict, greeter: dict | None, session: dict | None) -> dict:
    out = {}
    stamps = keyvals(b.get("systemd_manager_timestamps", {}).get("text", ""))
    get = lambda k: num(stamps.get(k))  # noqa: E731
    firmware, loader = get("FirmwareTimestampMonotonic"), get("LoaderTimestampMonotonic")
    initrd, userspace, finish = get("InitRDTimestampMonotonic"), get("UserspaceTimestampMonotonic"), get("FinishTimestampMonotonic")
    if firmware and loader:
        out["firmware_s"] = rnd((firmware - loader) / 1e6)
    if loader:
        out["loader_s"] = rnd(loader / 1e6)
    if userspace:
        out["kernel_s"] = rnd((initrd if initrd else userspace) / 1e6)
        if initrd:
            out["initrd_s"] = rnd((userspace - initrd) / 1e6)
        if finish:
            out["userspace_s"] = rnd((finish - userspace) / 1e6)
            out["kernel_to_boot_finished_s"] = rnd(finish / 1e6)
    graphical = num(keyvals(b.get("graphical_target", {}).get("text", "")).get("ActiveEnterTimestampMonotonic"))
    if graphical and userspace:
        out["graphical_target_after_userspace_s"] = rnd((graphical - userspace) / 1e6)
        out["kernel_to_graphical_target_s"] = rnd(graphical / 1e6)
    clk = num(facts.get("clk_tck"), 100) or 100
    if greeter and num(greeter.get("shell_start_ticks")):
        out["kernel_to_greeter_shell_s"] = rnd(num(greeter["shell_start_ticks"]) / clk)
    if session:
        if num(session.get("shell_start_ticks")):
            out["kernel_to_session_shell_s"] = rnd(num(session["shell_start_ticks"]) / clk)
        if num(session.get("compositor_start_ticks")):
            out["kernel_to_session_compositor_s"] = rnd(num(session["compositor_start_ticks"]) / clk)
    props = keyvals(b.get("session_properties", {}).get("text", ""))
    session_start = num(props.get("TimestampMonotonic"))
    if session_start and "kernel_to_session_shell_s" in out:
        out["session_start_s"] = rnd(session_start / 1e6)
        out["login_to_shell_s"] = rnd(out["kernel_to_session_shell_s"] - session_start / 1e6)
    time_text = b.get("systemd_analyze_time", {}).get("text", "")
    out["systemd_analyze_time"] = time_text.strip().splitlines()[0] if time_text.strip() else None
    blame = []
    for line in b.get("systemd_analyze_blame", {}).get("text", "").splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        unit = parts[-1]
        seconds = parse_duration(" ".join(parts[:-1]))
        if seconds is not None:
            blame.append({"unit": unit, "s": rnd(seconds)})
    out["blame_top20"] = blame[:20]
    unlock = [row for row in blame if row["unit"].startswith("systemd-cryptsetup@")]
    out["cryptsetup_units_s"] = rnd(sum(row["s"] for row in unlock)) if unlock else None
    out["critical_chain"] = b.get("systemd_analyze_critical_chain", {}).get("text")
    return out


def security_section(b: dict, facts: dict) -> dict:
    units = []
    for line in b.get("systemd_analyze_security", {}).get("text", "").splitlines():
        match = re.match(r"^(\S+\.service)\s+(\d+(?:\.\d+)?)\s+(\S+)", line.strip())
        # The harness's own probe is on every measured disk; it is not the system's.
        if match and match.group(1) != "bench-probe.service":
            units.append({"unit": match.group(1), "exposure": float(match.group(2)), "predicate": match.group(3)})
    setuid = setgid = 0
    setid_files = []
    for line in b.get("setid_files", {}).get("text", "").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and re.fullmatch(r"[0-7]{3,4}", parts[0]):
            mode = int(parts[0], 8)
            if mode & 0o4000:
                setuid += 1
            if mode & 0o2000:
                setgid += 1
            setid_files.append(parts[2])
    caps_blob = b.get("file_capabilities")
    caps = None
    if caps_blob and caps_blob.get("rc") in (0, "0", None):
        caps = sum(1 for line in caps_blob.get("text", "").splitlines() if line.strip() and " " in line)
    nft = b.get("nft_ruleset", {}).get("text", "")
    input_policy = None
    for match in re.finditer(r"type filter hook input[^;]*;[^}]*?policy (\w+);", nft):
        input_policy = match.group(1)
    exposures = [u["exposure"] for u in units]
    return {
        "services_analyzed": len(units),
        # The sum can only grow with every service a system runs; a mean
        # would fall by adding many small sandboxed units.
        "exposure_sum": rnd(sum(exposures), 2) if units else None,
        "exposure_mean": rnd(mean(exposures), 2),
        "exposure_max": max(exposures) if exposures else None,
        "services_unsafe": sum(1 for u in units if u["predicate"] == "UNSAFE"),
        "services_exposed": sum(1 for u in units if u["predicate"] == "EXPOSED"),
        "services": units,
        "setuid_count": setuid,
        "setgid_count": setgid,
        "setid_files": setid_files,
        "file_capability_count": caps,
        "nft_input_policy": input_policy,
        "kernel": {k: facts.get(k) for k in (
            "lockdown", "lsm", "kptr_restrict", "dmesg_restrict", "ptrace_scope",
            "unprivileged_bpf_disabled", "unprivileged_userns_clone", "perf_event_paranoid",
            "kexec_load_disabled", "randomize_va_space", "bpf_jit_harden",
            "protected_symlinks", "protected_hardlinks")},
    }


def _hex_addr(text: str) -> tuple[str, int]:
    """Decode /proc/net/{tcp,udp}[6] "ADDR:PORT" (host byte order per word)."""
    address, port = text.split(":")
    raw = bytes.fromhex(address)
    if len(raw) == 4:
        ip = ipaddress.IPv4Address(raw[::-1])
    else:
        ip = ipaddress.IPv6Address(b"".join(raw[i:i + 4][::-1] for i in range(0, 16, 4)))
    return str(ip), int(port, 16)


def listeners_section(b: dict) -> dict:
    owners = {}
    for line in b.get("socket_owners", {}).get("text", "").splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3:
            owners.setdefault(parts[0], set()).add(parts[2])
    rows = []
    for proto in ("tcp", "tcp6", "udp", "udp6"):
        text = b.get(f"proc_net_{proto}", {}).get("text", "")
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 10:
                continue
            state = parts[3]
            if proto.startswith("tcp") and state != "0A":
                continue
            if proto.startswith("udp") and state != "07":
                continue
            try:
                ip, port = _hex_addr(parts[1])
            except (ValueError, IndexError):
                continue
            inode = parts[9]
            loopback = ipaddress.ip_address(ip).is_loopback
            rows.append({
                "proto": proto, "address": ip, "port": port, "loopback": loopback,
                "owners": sorted(owners.get(inode, [])),
            })
    exposed = [r for r in rows if not r["loopback"]]
    return {
        "listening": rows,
        "non_loopback_count": len(exposed),
        "non_loopback": exposed,
        "ss_text": b.get("ss_tulpn", {}).get("text"),
    }


def footprint_section(b: dict, facts: dict) -> dict:
    filesystems = []
    for line in b.get("df", {}).get("text", "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[2].isdigit():
            filesystems.append({"source": parts[0], "used_kib": int(parts[2]), "mount": parts[5]})
    root = next((f for f in filesystems if f["mount"] == "/"), None)
    enabled = [l for l in b.get("units_enabled", {}).get("text", "").splitlines() if l.strip()]
    running = [l for l in b.get("services_running", {}).get("text", "").splitlines() if l.strip()]
    os_files = {}
    size_kind = None
    for name, kind in (("os_files_apparent", "apparent"), ("os_files_allocated", "allocated")):
        blob = b.get(name)
        if not blob or blob.get("rc") not in (0, "0"):
            continue
        for line in blob.get("text", "").splitlines():
            parts = line.split(None, 1)
            if len(parts) == 2 and parts[0].isdigit():
                os_files[parts[1].strip()] = int(parts[0])
        size_kind = kind
        break
    return {
        "filesystems": filesystems,
        # Recorded, never compared: df / is the whole btrfs filesystem on one
        # system and one A/B root slot on another.
        "root_used_mib": rnd(root["used_kib"] / KIB, 1) if root else None,
        "os_files_mib": rnd(sum(os_files.values()) / KIB, 1) if os_files else None,
        "os_files_trees": os_files,
        "os_files_size": size_kind,
        "packages": num(facts.get("packages")),
        "package_manager": facts.get("package_manager") or None,
        "enabled_unit_files": len(enabled),
        "running_services": len(running),
    }


def workload_section(record: dict | None, start: dict | None) -> dict | None:
    if not record:
        return None
    out = {k: v for k, v in record.items() if k not in ("type", "uptime")}
    for key in ("completion_ms", "editor_ms", "container_ms", "browser_peak_bytes",
                "psi_full_avg10_max", "mem_available_min_kb", "swap_used_max_kb",
                "oom_kills_kernel", "oom_kills_oomd", "psi_full_total_start_us", "psi_full_total_end_us",
                "before_container_ms", "before_container_psi_full_avg10_max",
                "before_container_mem_available_min_kb", "before_container_swap_used_max_kb",
                "before_container_oom_kills_kernel", "before_container_oom_kills_oomd",
                "before_container_psi_full_total_end_us", "before_container_samples"):
        out[key] = num(record.get(key))
    if out.get("completion_ms") is not None:
        out["completion_s"] = rnd(out["completion_ms"] / 1000, 2)
    for key in ("editor_ms", "container_ms"):
        if out.get(key) is not None:
            out[key.replace("_ms", "_s")] = rnd(out[key] / 1000, 2)
    if out.get("mem_available_min_kb") is not None:
        out["mem_available_min_mib"] = rnd(out["mem_available_min_kb"] / KIB, 1)
    if out.get("oom_kills_kernel") is not None:
        out["oom_kills_total"] = out["oom_kills_kernel"] + (out.get("oom_kills_oomd") or 0)
    s, e = out.get("psi_full_total_start_us"), out.get("psi_full_total_end_us")
    if s is not None and e is not None and out.get("completion_ms"):
        out["psi_full_stall_pct"] = rnd(100.0 * (e - s) / (out["completion_ms"] * 1000), 3)
    # The browser and editor phase (identical on every system) on its own.
    before = {}
    if out.get("before_container_mem_available_min_kb") is not None:
        before["mem_available_min_mib"] = rnd(out["before_container_mem_available_min_kb"] / KIB, 1)
    if out.get("before_container_psi_full_avg10_max") is not None:
        before["psi_full_avg10_max"] = out["before_container_psi_full_avg10_max"]
    if out.get("before_container_oom_kills_kernel") is not None:
        before["oom_kills_total"] = out["before_container_oom_kills_kernel"] + (
            out.get("before_container_oom_kills_oomd") or 0)
    e = out.get("before_container_psi_full_total_end_us")
    if s is not None and e is not None and out.get("before_container_ms"):
        before["psi_full_stall_pct"] = rnd(100.0 * (e - s) / (out["before_container_ms"] * 1000), 3)
    out["before_container"] = before or None
    steps = {"browser": record.get("browser_status"), "editor": record.get("editor_status"),
             "container": record.get("container_status")}
    out["steps_ok"] = sum(1 for status in steps.values() if status == "ok")
    # A step that was attempted and failed (the browser killed by oomd, say)
    # is a result; a step that never started (tool missing) means the
    # systems did not do the same work.
    out["browser_editor_attempted"] = all(steps[k] in ("ok", "failed") for k in ("browser", "editor"))
    out["all_steps_attempted"] = all(status in ("ok", "failed") for status in steps.values())
    out["all_steps_ran"] = all(status == "ok" for status in steps.values())
    out["experimental"] = True
    if start:
        out["start"] = {k: v for k, v in start.items() if k not in ("type",)}
    return out


# ---- assembly -------------------------------------------------------------------

def parse_run(records: list[dict], host: dict | None = None) -> dict:
    host = host or {}
    facts = first(records, "facts") or {}
    probe_start = first(records, "probe_start") or {}
    greeter = first(records, "greeter_ready")
    session = first(records, "session_ready")
    counters_start = first(records, "counters", phase="start")
    counters_end = first(records, "counters", phase="end")
    cg_start = cgroup_map(first(records, "cgroups", phase="start"))
    cg_end = cgroup_map(first(records, "cgroups", phase="end"))
    samples = sorted((r for r in records if r.get("type") == "sample"), key=lambda r: num(r.get("i"), 0))
    devices_record = first(records, "devices") or {}
    devices, attribution = device_roles(devices_record.get("list", []))
    mm = first(records, "mm", phase="session") or first(records, "mm", phase="end")
    b = blobs(records)
    errors = [r for r in records if r.get("type") == "error"]
    done = first(records, "done")
    probe_cgroup = facts.get("probe_cgroup") or None

    expected_samples = int(num(facts.get("samples"), 30))
    complete = bool(counters_start and counters_end and first(records, "window_end")
                    and len(samples) == expected_samples)
    canonical = facts.get("canonical", probe_start.get("canonical")) == "yes"

    result: dict = {
        "schema": SCHEMA,
        "meta": {k: v for k, v in host.get("meta", {}).items()},
        "probe": {
            "version": facts.get("probe_version") or probe_start.get("probe_version"),
            "canonical": canonical,
            "settle_secs": num(facts.get("settle_secs")),
            "samples": expected_samples,
            "interval_secs": num(facts.get("interval_secs")),
            "config_source": facts.get("config_source"),
            "injection": facts.get("injection"),
            "fw_cfg_module_loaded": facts.get("fw_cfg_module_loaded"),
            "cgroup": probe_cgroup,
        },
        "system": {k: facts.get(k) for k in ("os_id", "os_version", "os_pretty", "kernel", "machine",
                                             "cpu_model", "ncpu", "packages", "cmdline")},
        "session": {k: (session or {}).get(k) for k in ("user", "uid", "session_type", "shell", "compositor")},
        "idle": {},
        "boot": boot_section(b, facts, greeter, session),
        "security": security_section(b, facts),
        "exposure": {"guest": listeners_section(b), "scan": host.get("scan")},
        "privacy": host.get("privacy"),
        "footprint": footprint_section(b, facts),
        "workload": workload_section(first(records, "workload"), first(records, "workload_start")),
        "host": host.get("host"),
        "clocks": host.get("clocks"),
        "errors": [e.get("reason") for e in errors] + ([f"harness: {host['failure']}"] if host.get("failure") else []),
        "done": (done or {}).get("status"),
    }
    if samples:
        result["idle"]["memory"] = memory_section(samples, first(records, "processes"), mm,
                                                  num(host.get("meta", {}).get("shape_mib")))
    if counters_start and counters_end:
        result["idle"]["cpu"] = cpu_section(counters_start, counters_end, cg_start, cg_end, samples, probe_cgroup)
        result["idle"]["pressure"] = pressure_section(counters_start, counters_end, samples)
        result["idle"]["writes"] = writes_section(devices, cg_start, cg_end, counters_start, counters_end,
                                                  probe_cgroup, attribution)

    reasons = []
    if host.get("failure"):
        reasons.append(f"harness: {host['failure']}")
    if not canonical:
        reasons.append("non-canonical window (settle/samples/interval overridden)")
    if not complete:
        reasons.append("incomplete window")
    if errors:
        reasons.append("probe errors: " + ", ".join(e.get("reason", "?") for e in errors))
    guest_steal = (result["idle"].get("cpu") or {}).get("steal_pct")
    if guest_steal is None:
        reasons.append("guest steal not measured")
    elif guest_steal > STEAL_LIMIT_PCT:
        reasons.append(f"guest steal {guest_steal}% > {STEAL_LIMIT_PCT}%")
    host_steal = (host.get("host") or {}).get("steal_pct_window")
    if host_steal is None:
        reasons.append("host steal not measured (no host /proc/stat over the window)")
    elif host_steal > STEAL_LIMIT_PCT:
        reasons.append(f"host steal {host_steal}% > {STEAL_LIMIT_PCT}%")
    accel = host.get("meta", {}).get("accel")
    if accel != "kvm":
        # HVF (a Mac) cannot report host steal and TCG is emulation: smoke only.
        reasons.append(f"accelerator is {accel or 'unrecorded'}, not KVM")
    result["validity"] = {
        "complete": complete,
        "canonical": canonical,
        "guest_steal_pct": guest_steal,
        "host_steal_pct": host_steal,
        "valid_for_claims": not reasons,
        "reasons": reasons,
    }
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("export", type=Path)
    parser.add_argument("--host", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)
    host = json.loads(args.host.read_text()) if args.host else {}
    result = parse_run(load_stream(args.export), host)
    text = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
