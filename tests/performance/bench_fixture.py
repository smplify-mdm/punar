#!/usr/bin/env python3
"""Fixture /proc, /sys and /run trees for tests/performance/bench-probe-test.sh.

    bench_fixture.py build ROOT [plain|luks]      write a guest at the moment the probe starts
    bench_fixture.py tick ROOT PHASE              advance it (the probe's BENCH_TEST_TICK hook)
    bench_fixture.py check RESULT.json SAMPLES [plain|luks]   assert the parsed result

Every counter moves by a fixed step per sample, so the expected figures are
exact: per 10 s step the CPU adds 30 busy and 10 steal ticks out of 4,000,
the disk takes 400,000 bytes of which the top-level cgroups were charged
300,000 (journald 100,000 and the probe 10,000 inside system.slice), and the
probe's cgroup uses 5,000 us of CPU.

The luks layout puts the filesystem on dm-0 (dm-crypt over vda2): every
cgroup's writes are charged on dm-0 (253:0) only, and the encrypted copies
reach vda from kcryptd charged to the root cgroup. The expected figures are
the same as the plain layout's: the device total is still vda's, and each
cgroup is attributed where it wrote. (tests/performance/bench_summarize_test.py
covers kernels that charge the clone to the same cgroup again.)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

CGROUPS = {
    "": {"cpu": 0, "wbytes": 0},
    "system.slice": {"cpu": 0, "wbytes": 0},
    "system.slice/systemd-journald.service": {"cpu": 0, "wbytes": 0},
    "system.slice/bench-probe.service": {"cpu": 0, "wbytes": 0},
    "user.slice": {"cpu": 0, "wbytes": 0},
    "user.slice/user-1000.slice": {"cpu": 0, "wbytes": 0},
    "init.scope": {"cpu": 0, "wbytes": 0},
}
STEP = {
    "": {"cpu": 0, "wbytes": 400000},
    "system.slice": {"cpu": 100000, "wbytes": 250000},
    "system.slice/systemd-journald.service": {"cpu": 20000, "wbytes": 100000},
    "system.slice/bench-probe.service": {"cpu": 5000, "wbytes": 10000},
    "user.slice": {"cpu": 200000, "wbytes": 50000},
    "user.slice/user-1000.slice": {"cpu": 200000, "wbytes": 50000},
    "init.scope": {"cpu": 1000, "wbytes": 0},
}


def write(path: Path, text: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    if mode is not None:
        os.chmod(path, mode)


def state_path(root: Path) -> Path:
    return root / "fixture-state.json"


ZONEINFO = """Node 0, zone      DMA
  per-node stats
      nr_inactive_anon 0
  pages free     3840
        boost    0
        min      8
        low      11
        high     14
        spanned  4095
        present  3998
        managed  3840
        cma      0
        protection: (0, 2911, 7863, 7863, 7863)
  pagesets
    cpu: 0
              count: 0
              high:  0
              batch: 1
Node 0, zone    DMA32
  pages free     700000
        boost    100
        min      5000
        low      6250
        high     7600
        spanned  1044480
        present  782288
        managed  745400
        cma      0
        protection: (0, 0, 4952, 4952, 4952)
Node 0, zone   Normal
  pages free     500000
        boost    0
        min      8500
        low      10625
        high     12750
        spanned  1310720
        present  1310720
        managed  1267632
        cma      0
        protection: (0, 0, 0, 0, 0)
"""
# DMA: 7863 + 14 capped at 3840 managed; DMA32: 4952 + (7600 - 100 boost);
# Normal: 0 + 12750.
TOTALRESERVE_PAGES = 3840 + 4952 + 7500 + 12750


def render(root: Path, state: dict) -> None:
    step = state["step"]
    cpu = [20 * step + 1000, 0, 10 * step + 500, 3960 * step + 100000, 0, 0, 0, 10 * step, 0, 0]
    stat = ["cpu  " + " ".join(str(v) for v in cpu)]
    for n in range(4):
        stat.append(f"cpu{n} " + " ".join(str(v // 4) for v in cpu))
    stat += [f"intr {1500 * step + 10000} 0 0", f"ctxt {3000 * step + 20000}", "btime 1700000000",
             "processes 900", "procs_running 1", "procs_blocked 0", "softirq 5000 0"]
    write(root / "proc/stat", "\n".join(stat) + "\n")
    write(root / "proc/uptime", f"{100 + 10 * step:.2f} 350.00\n")
    available = 7000000 - 1000 * (step % 3)
    write(root / "proc/meminfo", "\n".join([
        "MemTotal:        8000000 kB", "MemFree:         5000000 kB",
        f"MemAvailable:    {available} kB", "Buffers:           10000 kB",
        "Cached:          1500000 kB", "SwapCached:            0 kB",
        "Active(file):     900000 kB", "Inactive(file):   800000 kB",
        "Unevictable:      250000 kB", "Mlocked:            26000 kB",
        "SwapTotal:       4000000 kB", "SwapFree:        4000000 kB",
        "AnonPages:        330000 kB", "Shmem:              25000 kB",
        "KReclaimable:      60000 kB", "SReclaimable:       60000 kB",
        "SUnreclaim:        50000 kB", "KernelStack:        12000 kB",
        "PageTables:        15000 kB",
    ]) + "\n")
    write(root / "proc/vmstat", f"nr_free_pages 1250000\npgfault {1000 * step}\npgmajfault 3\noom_kill 0\npswpin 0\npswpout 0\n")
    write(root / "proc/loadavg", "0.00 0.01 0.05 1/200 1234\n")
    for resource in ("cpu", "memory", "io"):
        write(root / f"proc/pressure/{resource}",
              f"some avg10=0.10 avg60=0.00 avg300=0.00 total={1000 * step + 50}\n"
              f"full avg10=0.00 avg60=0.00 avg300=0.00 total={500 * step}\n")
    write(root / "proc/interrupts", "           CPU0       CPU1       CPU2       CPU3\n"
          + "".join(f"{name}: " + " ".join(str(300 * step + base) for _ in range(4)) + f"   {desc}\n"
                    for name, base, desc in (("LOC", 100, "Local timer interrupts"),
                                             ("  1", 5, "IO-APIC 1-edge i8042")))
          + "ERR:          0\n")
    luks = state.get("layout") == "luks"
    write(root / "proc/diskstats",
          f" 254       0 vda 100 0 2000 50 200 0 {781 * step + 4000} 60 0 100 110 0 0 0 0\n"
          f" 252       0 zram0 5 0 40 0 0 0 {999 * step} 0 0 0 0 0 0 0 0\n"
          + (f" 253       0 dm-0 90 0 1900 40 190 0 {700 * step + 3000} 55 0 90 100 0 0 0 0\n" if luks else ""))
    for rel, counters in CGROUPS.items():
        base = root / "sys/fs/cgroup" / rel
        cpu_us = counters["cpu"] + STEP[rel]["cpu"] * step
        wbytes = counters["wbytes"] + STEP[rel]["wbytes"] * step
        write(base / "cpu.stat", f"usage_usec {cpu_us}\nuser_usec {cpu_us // 2}\nsystem_usec {cpu_us // 2}\n")
        io = f"252:0 rbytes=0 wbytes={wbytes * 3} rios=0 wios=0 dbytes=0 dios=0\n"
        if not luks or not rel:
            io = f"254:0 rbytes=4096 wbytes={wbytes} rios=1 wios={step} dbytes=0 dios=0\n" + io
        if luks and rel:
            # Charged on dm-0, where the write entered; the encrypted clone
            # reaches vda from a kcryptd worker, charged to the root.
            io += f"253:0 rbytes=0 wbytes={wbytes} rios=0 wios={step} dbytes=0 dios=0\n"
        elif luks:
            io += f"253:0 rbytes=0 wbytes={350000 * step} rios=0 wios={step} dbytes=0 dios=0\n"
        write(base / "io.stat", io)
        write(base / "memory.stat", "anon 2097152\nfile 1048576\nkernel 524288\nshmem 0\n")
        if rel:
            write(base / "memory.current", "4194304\n")
    # The probe's cgroup: 1 MiB anon + 0.5 MiB kernel.
    write(root / "sys/fs/cgroup/system.slice/bench-probe.service/memory.stat",
          "anon 1048576\nfile 4096\nkernel 524288\nshmem 0\n")


def build(root: Path, layout: str = "plain") -> None:
    root.mkdir(parents=True, exist_ok=True)
    state = {"step": 0, "polls": 0, "layout": layout}
    state_path(root).write_text(json.dumps(state))
    render(root, state)
    write(root / "etc/os-release", 'ID=fixture\nVERSION_ID="1"\nPRETTY_NAME="Fixture OS 1"\n')
    write(root / "proc/cpuinfo", "processor\t: 0\nmodel name\t: Fixture CPU @ 3.0GHz\n")
    write(root / "proc/cmdline", "root=PARTLABEL=ROOT quiet\n")
    write(root / "proc/self/cgroup", "0::/system.slice/bench-probe.service\n")
    write(root / "proc/swaps", "Filename Type Size Used Priority\n/dev/zram0 partition 4000000 0 100\n")
    for key, value in (("min_free_kbytes", "67584"), ("swappiness", "60"), ("watermark_scale_factor", "10"),
                       ("vfs_cache_pressure", "100"), ("overcommit_memory", "0"), ("page-cluster", "0"),
                       ("watermark_boost_factor", "0")):
        write(root / f"proc/sys/vm/{key}", value + "\n")
    for key, value in (("kptr_restrict", "1"), ("dmesg_restrict", "1"), ("yama/ptrace_scope", "1"),
                       ("unprivileged_bpf_disabled", "2"), ("perf_event_paranoid", "3"),
                       ("kexec_load_disabled", "0"), ("randomize_va_space", "2")):
        write(root / f"proc/sys/kernel/{key}", value + "\n")
    write(root / "sys/kernel/mm/transparent_hugepage/enabled", "always [madvise] never\n")
    write(root / "sys/kernel/mm/transparent_hugepage/defrag", "always defer defer+madvise [madvise] never\n")
    write(root / "sys/kernel/mm/transparent_hugepage/shmem_enabled", "always within_size advise [never] deny force\n")
    write(root / "sys/kernel/security/lsm", "capability,landlock,lockdown,yama,bpf\n")
    write(root / "sys/kernel/security/lockdown", "[none] integrity confidentiality\n")
    write(root / "proc/zoneinfo", ZONEINFO)
    write(root / "sys/block/vda/dev", "254:0\n")
    if layout == "luks":
        write(root / "sys/block/dm-0/dev", "253:0\n")
        write(root / "sys/block/dm-0/slaves/vda2", "")
    write(root / "sys/block/zram0/dev", "252:0\n")
    write(root / "sys/block/zram0/disksize", "4096000000\n")
    write(root / "sys/block/zram0/comp_algorithm", "lzo [zstd]\n")
    write(root / "sys/block/zram0/mm_stat", "0 0 0 0 0 0 0 0 0\n")
    write(root / "sys/firmware/.keep", "")
    # Sessions: the greeter first; the person's session appears on the first poll.
    write(root / "run/systemd/sessions/c1", "UID=990\nUSER=greeter\nACTIVE=1\nSTATE=active\nTYPE=wayland\nCLASS=greeter\n")
    processes = {
        50: ("qs", 990, "0::/user.slice/user-990.slice/session-c1.scope", 800),
        100: ("Hyprland", 1000, "0::/user.slice/user-1000.slice/session-3.scope", 1500),
        101: ("qs", 1000, "0::/user.slice/user-1000.slice/session-3.scope", 1600),
        200: ("sshd", 0, "0::/system.slice/sshd.service", 300),
        201: ("cupsd", 0, "0::/system.slice/cups.service", 310),
    }
    for pid, (comm, uid, cgroup, start) in processes.items():
        base = root / "proc" / str(pid)
        write(base / "comm", comm + "\n")
        write(base / "status", f"Name:\t{comm}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n")
        write(base / "cgroup", cgroup + "\n")
        fields = [str(pid), f"({comm})", "S"] + ["0"] * 18 + [str(start)] + ["0"] * 30
        write(base / "stat", " ".join(fields) + "\n")
        pss = {100: 120000, 101: 98000, 50: 60000}.get(pid, 4000)
        write(base / "smaps_rollup", f"00400000-7fff [rollup]\nRss: {pss + 1000} kB\nPss: {pss} kB\n"
              f"Pss_Anon: {pss - 1000} kB\nPss_File: 1000 kB\nPss_Shmem: 0 kB\nSwapPss: 0 kB\nLocked: 0 kB\n")
        (base / "fd").mkdir(parents=True, exist_ok=True)
    os.symlink("socket:[12345]", root / "proc/200/fd/3")
    os.symlink("socket:[12346]", root / "proc/201/fd/4")
    os.symlink("socket:[12347]", root / "proc/201/fd/5")
    write(root / "proc/net/tcp",
          "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
          "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0 100 0 0 10 0\n"
          "   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0 100 0 0 10 0\n"
          "   2: 0F02000A:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 22222 1 0 100 0 0 10 0\n")
    write(root / "proc/net/udp",
          "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops\n"
          "   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   104        0 12347 2 0 0\n")
    write(root / "proc/net/tcp6", "  sl  local_address remote_address st\n")
    write(root / "proc/net/udp6", "  sl  local_address remote_address st\n")
    write(root / "usr/bin/su", "#!/bin/sh\n", 0o4755)
    write(root / "usr/bin/wall", "#!/bin/sh\n", 0o2755)
    write(root / "usr/bin/ls", "#!/bin/sh\n", 0o755)


def tick(root: Path, phase: str) -> None:
    state = json.loads(state_path(root).read_text())
    if phase == "poll":
        state["polls"] += 1
        if state["polls"] == 1:
            write(root / "run/systemd/sessions/3",
                  "UID=1000\nUSER=bench\nACTIVE=1\nSTATE=active\nTYPE=wayland\nCLASS=user\n")
    elif phase == "sample":
        state["step"] += 1
        render(root, state)
    state_path(root).write_text(json.dumps(state))


def check(result_path: Path, samples: int, layout: str = "plain") -> None:
    result = json.loads(result_path.read_text())
    failures = []

    def expect(label, actual, wanted, tolerance=1e-6):
        if actual is None or abs(actual - wanted) > tolerance:
            failures.append(f"{label}: got {actual!r}, want {wanted!r}")

    memory, cpu, writes = result["idle"]["memory"], result["idle"]["cpu"], result["idle"]["writes"]
    # MemAvailable cycles 7,000,000 / 6,999,000 / 6,998,000 kB over the samples.
    used = [8000000 - (7000000 - 1000 * (k % 3)) for k in range(samples)]
    expect("used mean MiB", memory["used_mean_mib"], round(sum(used) / len(used) / 1024, 1))
    expect("used max MiB", memory["used_max_mib"], round(max(used) / 1024, 1))
    expect("probe memory MiB", memory["probe_mean_mib"], 1.5)
    expect("window s", cpu["window_s"], 10.0 * samples)
    expect("system CPU %", cpu["system_pct"], 0.75)
    expect("guest steal %", cpu["steal_pct"], 0.25)
    expect("interrupts/s", cpu["interrupts_per_s"], 150.0)
    expect("context switches/s", cpu["ctxt_per_s"], 300.0)
    expect("probe CPU %", cpu["probe_pct"], 0.0125)
    expect("system CPU % net of probe", cpu["system_pct_net"], 0.7375)
    expect("device bytes", writes["device_bytes"], 400000.0 * samples)
    if writes["device_source"] != "cgroup-root":
        failures.append(f"device source {writes['device_source']}")
    expect("diskstats bytes", writes["diskstats_bytes"], 781 * 512.0 * samples)
    expect("journald bytes", writes["journald_bytes"], 100000.0 * samples)
    expect("top-level cgroup bytes", writes["top_level_cgroups_bytes"], 300000.0 * samples)
    expect("kernel/fs remainder", writes["kernel_fs_remainder_bytes"], 100000.0 * samples)
    expect("attributed %", writes["attributed_pct"], 75.0)
    expect("probe bytes", writes["probe_bytes"], 10000.0 * samples)
    if writes["devices"] != ["254:0"]:
        failures.append(f"physical devices {writes['devices']} (zram must be excluded)")
    wanted_attribution = ["253:0"] if layout == "luks" else ["254:0"]
    if writes["attribution_devices"] != wanted_attribution:
        failures.append(f"attribution devices {writes['attribution_devices']}, want {wanted_attribution}")
    page_kib = float(result["idle"]["memory"]["settings"]["pagesize"]) / 1024
    reserve_mib = TOTALRESERVE_PAGES * page_kib / 1024
    expect("totalreserve MiB", memory.get("totalreserve_mib"), round(reserve_mib, 1))
    expect("used minus totalreserve MiB", memory.get("used_minus_totalreserve_mean_mib"),
           round(sum(used) / len(used) / 1024 - reserve_mib, 1), tolerance=0.11)
    # meminfo: MemTotal 8,000,000 - MemFree 5,000,000 - file LRU 1,700,000 - KReclaimable 60,000 kB.
    expect("unreclaimable used MiB", memory.get("unreclaimable_used_mean_mib"), round(1240000 / 1024, 1),
           tolerance=0.11)
    available = [7000000 - 1000 * (k % 3) for k in range(samples)]
    expect("shape minus available MiB", memory.get("shape_minus_available_mean_mib"),
           round(8192 - sum(available) / len(available) / 1024, 1), tolerance=0.11)
    footprint = result["footprint"]
    if footprint.get("os_files_size") != "apparent" or footprint.get("os_files_mib") is None:
        failures.append(f"OS files {footprint.get('os_files_size')} {footprint.get('os_files_mib')}")
    if footprint.get("package_manager") != "dpkg":
        failures.append(f"package manager {footprint.get('package_manager')}")
    if memory.get("thp_mode") != "madvise":
        failures.append(f"THP mode {memory.get('thp_mode')}")
    expect("min_free_kbytes", memory.get("min_free_kbytes"), 67584)
    if memory["pss_top15"][0]["comm"] != "Hyprland":
        failures.append("PSS ranking")
    guest = result["exposure"]["guest"]
    exposed = sorted((row["proto"], row["port"], tuple(row["owners"])) for row in guest["non_loopback"])
    if exposed != [("tcp", 22, ("sshd",)), ("udp", 5353, ("cupsd",))]:
        failures.append(f"non-loopback listeners {exposed}")
    security = result["security"]
    if (security["setuid_count"], security["setgid_count"]) != (1, 1):
        failures.append(f"setuid/setgid {security['setuid_count']}/{security['setgid_count']}")
    # bench-probe.service is the harness's own and is left out.
    if security["services_analyzed"] != 2 or security["services_unsafe"] != 1:
        failures.append(f"systemd-analyze security parse {security['services_analyzed']}/{security['services_unsafe']}")
    expect("exposure sum", security.get("exposure_sum"), 15.8)
    if security["nft_input_policy"] != "drop":
        failures.append(f"nft input policy {security['nft_input_policy']}")
    boot = result["boot"]
    expect("kernel s", boot.get("kernel_s"), 1.5)
    expect("initrd s", boot.get("initrd_s"), 2.0)
    expect("userspace s", boot.get("userspace_s"), 5.0)
    expect("greeter shell s", boot.get("kernel_to_greeter_shell_s"), 8.0)
    expect("login to shell s", boot.get("login_to_shell_s"), 1.0)
    if result["session"]["user"] != "bench" or result["session"]["shell"] != "qs":
        failures.append(f"session {result['session']}")
    if result["footprint"]["packages"] != 3:
        failures.append(f"packages {result['footprint']['packages']}")
    if failures:
        print("bench-probe-test: FAIL:\n  " + "\n  ".join(failures), file=sys.stderr)
        raise SystemExit(1)


def main(argv: list[str]) -> int:
    if argv[0] == "build":
        build(Path(argv[1]), argv[2] if len(argv) > 2 else "plain")
    elif argv[0] == "tick":
        tick(Path(argv[1]), argv[2])
    elif argv[0] == "check":
        check(Path(argv[1]), int(argv[2]), argv[3] if len(argv) > 3 else "plain")
    else:
        raise SystemExit(f"unknown command {argv[0]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
