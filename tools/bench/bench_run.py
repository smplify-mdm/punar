#!/usr/bin/env python3
"""Drive one benchmark boot from outside the guest (tools/bench/README.md).

    bench_run.py onboard --base PREPARED.qcow2 --out ONBOARDED.qcow2 [--arch x86_64]
    bench_run.py warmup --disk ONBOARDED.qcow2 --out DIR [--settle 600]
    bench_run.py run --lane punar --disk ONBOARDED.qcow2 --shape 8192 --out DIR [...]
    bench_run.py install-omarchy --iso ISO --cidata CIDATA.img --secret-file F --out DISK.raw

`onboard` creates the release image's first account once, through the same
keyboard path tools/test-release-onboarding.sh proves in CI, and keeps the
result as a qcow2 overlay. `warmup` then boots that disk in place once at the
measured resolution, signs in at the greeter, stays in the session for the
settle time and shuts down cleanly, so first-login work is done before any
measured run (install-omarchy does the same for Omarchy's first session).
Every `run` then boots a fresh overlay of that disk cold, types the password
at the greeter over QMP (the release image has no autologin), follows the
in-guest probe's stream, records host clocks, host steal and host I/O wait,
captures the guest's network traffic from power-on to the end of the idle
window (and records whether tcpdump kept up), scans the guest's addresses
once the probe is done, and writes host.json and result.json.

The VM shape is fixed here so every system gets the same machine: q35 (virt
on ARM64), 4 vCPU, the requested memory, UEFI with no Secure Boot keys
enrolled, virtio disk, virtio-net, virtio-vga with no GPU acceleration
(llvmpipe) at 1920x1080, and a virtio-serial export port.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import bench_parse  # noqa: E402
import pcap_summary  # noqa: E402
import portscan  # noqa: E402
import qmp as qmplib  # noqa: E402

GUEST_MAC = "52:54:00:be:0c:01"
ONBOARDING_SCRIPT = REPO_ROOT / "tools" / "test-release-onboarding.sh"
MEASURED_RESOLUTION = "1920x1080"
# Run facts the harness sets itself. --meta may add facts but never replace
# these: the report's validity and comparability checks trust them.
RESERVED_META = frozenset({
    "lane", "shape_mib", "vcpus", "arch", "accel", "resolution", "net", "login", "inject", "run_id",
    "firmware", "qemu", "graphics", "disk_encryption", "disk_format", "probe_version",
})
# Host page cache still to be written back before a run may start (MiB).
HOST_DIRTY_LIMIT_MIB = 64

X86_FIRMWARE = [
    ("/usr/share/OVMF/OVMF_CODE_4M.fd", "/usr/share/OVMF/OVMF_VARS_4M.fd"),
    ("/usr/share/OVMF/OVMF_CODE.fd", "/usr/share/OVMF/OVMF_VARS.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.4m.fd", "/usr/share/edk2/x64/OVMF_VARS.4m.fd"),
    ("/usr/share/edk2/x64/OVMF_CODE.fd", "/usr/share/edk2/x64/OVMF_VARS.fd"),
    ("/opt/homebrew/share/qemu/edk2-x86_64-code.fd", "/opt/homebrew/share/qemu/edk2-i386-vars.fd"),
    ("/usr/local/share/qemu/edk2-x86_64-code.fd", "/usr/local/share/qemu/edk2-i386-vars.fd"),
]
ARM64_FIRMWARE = [
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
    "/usr/share/AAVMF/AAVMF_CODE.fd",
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
    "/usr/local/share/qemu/edk2-aarch64-code.fd",
]


def log(message: str) -> None:
    print(f"bench: {message}", flush=True)


class BenchFailure(Exception):
    """A run could not finish; the message says why."""


def die(message: str) -> None:
    print(f"bench: error: {message}", file=sys.stderr, flush=True)
    raise BenchFailure(message)


# ---- machine --------------------------------------------------------------------

def host_arch() -> str:
    machine = platform.machine().lower()
    return {"aarch64": "arm64", "arm64": "arm64", "amd64": "x86_64", "x86_64": "x86_64"}.get(machine, machine)


def pick_accel(arch: str) -> tuple[str, str]:
    if host_arch() == arch and os.access("/dev/kvm", os.R_OK | os.W_OK):
        return "kvm", "host"
    if platform.system() == "Darwin" and host_arch() == "arm64" and arch == "arm64":
        return "hvf", "host"
    return "tcg", "max"


def firmware(arch: str, workdir: Path) -> tuple[list[str], str]:
    if arch == "x86_64":
        code_env, vars_env = os.environ.get("PUNAR_OVMF_CODE"), os.environ.get("PUNAR_OVMF_VARS")
        pairs = [(code_env, vars_env)] if code_env and vars_env else X86_FIRMWARE
        for code, variables in pairs:
            if code and variables and Path(code).is_file() and Path(variables).is_file():
                copy = workdir / "OVMF_VARS.fd"
                shutil.copyfile(variables, copy)
                return ([
                    "-drive", f"if=pflash,format=raw,readonly=on,file={code}",
                    "-drive", f"if=pflash,format=raw,file={copy}",
                ], code)
        die("no x86_64 OVMF firmware found (Ubuntu: apt install ovmf)")
    for code in ARM64_FIRMWARE:
        if Path(code).is_file():
            return (["-bios", code], code)
    die("no AArch64 UEFI firmware found")
    raise AssertionError


class Machine:
    """One QEMU process with the harness's fixed shape."""

    def __init__(self, arch: str, disk: Path, memory_mib: int, workdir: Path, out: Path,
                 resolution: str | None = MEASURED_RESOLUTION, smp: int = 4, net: str = "user",
                 tap: str | None = None, export: Path | None = None, config: Path | None = None,
                 privacy_dump: Path | None = None, extra: list[str] | None = None,
                 no_reboot: bool = True, credentials: list[Path] | None = None,
                 user_net_options: str = "", disk_format: str = "qcow2"):
        self.arch = arch
        self.accel, cpu = pick_accel(arch)
        self.workdir = workdir
        self.qmp_path = workdir / "qmp.sock"
        fw_args, self.firmware = firmware(arch, workdir)
        binary = "qemu-system-x86_64" if arch == "x86_64" else "qemu-system-aarch64"
        self.binary = shutil.which(binary) or die(f"{binary} is required")
        rom = [] if arch == "x86_64" else ["romfile="]

        def device(name: str, *props: str) -> str:
            return ",".join([name, *props, *rom])

        args = [
            self.binary, "-name", "bench",
            "-machine", ("q35" if arch == "x86_64" else "virt,highmem=on") + f",accel={self.accel}",
            "-cpu", cpu, "-smp", str(smp), "-m", str(memory_mib),
            *fw_args,
            "-drive", f"file={disk},format={disk_format},if=none,id=benchdisk",
            "-device", device("virtio-blk-pci", "drive=benchdisk", "bootindex=1"),
            "-display", "none",
            "-serial", f"file:{out / 'serial.log'}",
            "-monitor", "none",
            "-qmp", f"unix:{self.qmp_path},server=on,wait=off",
        ]
        res = []
        if resolution:
            width, height = resolution.split("x")
            res = [f"xres={int(width)}", f"yres={int(height)}"]
        if arch == "x86_64":
            args += ["-vga", "none", "-device", ",".join(["virtio-vga", *res]),
                     "-device", "virtio-keyboard-pci", "-device", "virtio-tablet-pci"]
        else:
            args += ["-device", device("virtio-gpu-pci", *res),
                     "-device", "qemu-xhci", "-device", "usb-kbd", "-device", "usb-tablet"]
        if net == "tap":
            args += ["-netdev", f"tap,id=benchnet,ifname={tap},script=no,downscript=no"]
        else:
            args += ["-netdev", "user,id=benchnet" + user_net_options]
        args += ["-device", device("virtio-net-pci", "netdev=benchnet", f"mac={GUEST_MAC}")]
        if privacy_dump:
            args += ["-object", f"filter-dump,id=privdump,netdev=benchnet,file={privacy_dump},maxlen=65535"]
        if export:
            args += ["-device", device("virtio-serial-pci"),
                     "-chardev", f"file,id=benchexp,path={export}",
                     "-device", "virtserialport,chardev=benchexp,name=bench.export"]
        if config:
            args += ["-fw_cfg", f"name=opt/bench/config,file={config}"]
        for credential in credentials or []:
            args += ["-smbios", f"type=11,path={credential}"]
        if no_reboot:
            args.append("-no-reboot")
        args += extra or []
        self.args = args
        self.log_path = out / "qemu.log"
        self.proc: subprocess.Popen | None = None
        self.qmp: qmplib.QMP | None = None
        self.started = 0.0

    def start(self) -> None:
        log_handle = open(self.log_path, "ab")
        self.started = time.monotonic()
        self.proc = subprocess.Popen(self.args, stdout=log_handle, stderr=subprocess.STDOUT,
                                     stdin=subprocess.DEVNULL)
        self.qmp = qmplib.wait_for_socket(str(self.qmp_path), time.monotonic() + 60, self.alive)

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def elapsed(self) -> float:
        return round(time.monotonic() - self.started, 3)

    def stop(self, graceful_timeout: float = 0) -> bool:
        """Stop QEMU; with a timeout, ask the guest to power off first."""
        clean = False
        if self.alive() and graceful_timeout > 0 and self.qmp:
            try:
                self.qmp.powerdown()
            except (qmplib.QMPError, OSError):
                pass
            deadline = time.monotonic() + graceful_timeout
            while self.alive() and time.monotonic() < deadline:
                time.sleep(1)
            clean = not self.alive()
        if self.alive() and self.qmp:
            self.qmp.quit()
        if self.proc:
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self.qmp:
            self.qmp.close()
        return clean


def qemu_version(binary: str) -> str:
    try:
        return subprocess.run([binary, "--version"], capture_output=True, text=True, check=False).stdout.splitlines()[0]
    except (OSError, IndexError):
        return "unknown"


def timeouts(accel: str) -> dict:
    scale = 1 if accel in ("kvm", "hvf") else 4
    return {"boot": 300 * scale, "session": 240 * scale, "post": 900 * scale,
            "workload": 1800 * scale, "onboarding": 120 * scale, "receipt": 90 * scale,
            "desktop": 180 * scale}


# ---- host observations --------------------------------------------------------------

def host_cpu_times():
    """(total, steal, iowait) jiffies from the host's /proc/stat; None off Linux."""
    try:
        with open("/proc/stat") as handle:
            fields = handle.readline().split()
    except OSError:
        return None
    values = [int(v) for v in fields[1:9]]
    return sum(values), values[7], values[4]


def steal_pct(start, end, index: int = 1):
    if not start or not end or end[0] <= start[0]:
        return None
    return round(100.0 * (end[index] - start[index]) / (end[0] - start[0]), 4)


def host_dirty_mib():
    """Host page cache waiting to be written back (Dirty + Writeback), MiB."""
    try:
        text = Path("/proc/meminfo").read_text()
    except OSError:
        return None
    values = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        if key in ("Dirty", "Writeback"):
            values[key] = int(rest.split()[0])
    return round(sum(values.values()) / 1024, 1) if values else None


def quiesce_host(limit_mib: float = HOST_DIRTY_LIMIT_MIB, timeout: float = 300) -> dict:
    """Flush the host's page cache before a run starts.

    The first lane of a cell can follow the heaviest host I/O of the cell
    (an install, an image conversion, the probe injection). The steal gate
    catches CPU contention but not a disk still writing back gigabytes, so
    every run waits here until the host's dirty and writeback pages are
    below the limit, and records how long that took.
    """
    started = time.monotonic()
    os.sync()
    dirty = host_dirty_mib()
    while dirty is not None and dirty > limit_mib and time.monotonic() - started < timeout:
        time.sleep(2)
        os.sync()
        dirty = host_dirty_mib()
    return {"dirty_mib_at_start": dirty, "flush_wait_s": round(time.monotonic() - started, 1),
            "dirty_limit_mib": limit_mib, "flushed": dirty is None or dirty <= limit_mib}


def host_facts() -> dict:
    model = None
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        try:
            model = subprocess.run(["sysctl", "-n", "machdep.cpu.brand_string"], capture_output=True,
                                   text=True, check=False).stdout.strip() or None
        except OSError:
            pass
    return {"cpu_model": model, "nproc": os.cpu_count(), "kernel": platform.release(),
            "system": platform.system(), "runner": os.environ.get("RUNNER_NAME")}


# ---- probe stream ---------------------------------------------------------------------

class ExportTail:
    def __init__(self, path: Path):
        self.path = path
        self.offset = 0
        self.partial = b""
        self.records: list[dict] = []
        self.seen_at: dict[str, float] = {}

    def poll(self, started: float) -> None:
        if not self.path.exists():
            return
        with open(self.path, "rb") as handle:
            handle.seek(self.offset)
            chunk = handle.read()
            self.offset += len(chunk)
        data = self.partial + chunk
        lines = data.split(b"\n")
        self.partial = lines.pop()
        for raw in lines:
            try:
                record = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError:
                continue
            self.records.append(record)
            kind = record.get("type")
            if kind and kind not in self.seen_at:
                self.seen_at[kind] = round(time.monotonic() - started, 3)

    def find(self, kind: str) -> dict | None:
        return next((r for r in self.records if r.get("type") == kind), None)

    def wait(self, machine: Machine, kind: str, timeout: float) -> dict | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.poll(machine.started)
            record = self.find(kind)
            if record:
                return record
            failure = self.find("error")
            if failure:
                die(f"probe reported an error: {failure.get('reason')}")
            if not machine.alive():
                return None
            time.sleep(0.5)
        return None


# ---- secrets -----------------------------------------------------------------------------

def onboarding_credentials(path: Path = ONBOARDING_SCRIPT) -> dict:
    """The release image's CI test account, read from the script that proves it."""
    text = path.read_text()
    values = {}
    for key in ("TEST_USERNAME", "TEST_PASSWORD", "TEST_DEVICE"):
        match = re.search(rf"^{key}=(?:'([^']*)'|\"([^\"]*)\"|(\S+))$", text, re.M)
        if not match:
            die(f"{path.name} no longer defines {key}")
        values[key] = next(g for g in match.groups() if g is not None)
    return {"username": values["TEST_USERNAME"], "password": values["TEST_PASSWORD"],
            "device": values["TEST_DEVICE"], "source": str(path.relative_to(REPO_ROOT))}


def save_png(frame: Path, destination: Path) -> None:
    subprocess.run([sys.executable, str(REPO_ROOT / "tools" / "framebuffer-probe.py"), "png",
                    str(frame), str(destination)], stdout=subprocess.DEVNULL, check=False)


def relative_backing(base: Path, overlay: Path) -> str:
    return os.path.relpath(base.resolve(), overlay.resolve().parent)


def image_format(path: Path) -> str:
    info = subprocess.run(["qemu-img", "info", "-U", "--output=json", str(path)], capture_output=True,
                          text=True, check=True)
    return json.loads(info.stdout)["format"]


def make_overlay(base: Path, overlay: Path, relative: bool = False) -> None:
    backing = relative_backing(base, overlay) if relative else str(base.resolve())
    subprocess.run(["qemu-img", "create", "-q", "-f", "qcow2", "-F", image_format(base), "-b", backing,
                    str(overlay)], check=True)


def parse_meta(items: list[str]) -> dict:
    """--meta KEY=VALUE pairs; a reserved key is refused, not overwritten."""
    out = {}
    for item in items:
        key, sep, value = item.partition("=")
        if not sep or not key:
            die(f"--meta needs KEY=VALUE, got {item!r}")
        if key in RESERVED_META:
            die(f"--meta cannot set {key}: the harness records it itself")
        out[key] = value
    return out


def login(args, machine: Machine, tail, t: dict, frame: Path, out: Path, clocks: dict) -> None:
    """Get from power-on to the start of the graphical session, as a person would."""
    q = machine.qmp
    if args.login == "punar-greeter":
        secret = Path(args.secret_file).read_text().strip("\r\n") if args.secret_file \
            else onboarding_credentials()["password"]
        record = tail.wait(machine, "greeter_ready", t["boot"])
        if record is None:
            die("the greeter never became ready (is the account created? was the probe injected?)")
        clocks["greeter_record_s"] = tail.seen_at["greeter_ready"]
        qmplib.wait_stable(q, frame, 30, alive=machine.alive)
        clocks["prompt_stable_s"] = machine.elapsed()
        save_png(frame, out / "greeter.png")
        q.type_text(secret, enter=True)
        clocks["typed_s"] = machine.elapsed()
        del secret
    elif args.login == "luks-autologin":
        secret = Path(args.secret_file).read_text().strip("\r\n")
        if not qmplib.wait_stable(q, frame, t["boot"], settle=2.0, checks=3, alive=machine.alive):
            die("no stable disk-unlock prompt appeared")
        clocks["prompt_stable_s"] = machine.elapsed()
        save_png(frame, out / "unlock-prompt.png")
        q.type_text(secret, enter=True)
        clocks["typed_s"] = machine.elapsed()
        del secret
    session = tail.wait(machine, "session_ready", t["session"])
    if session is None:
        die("no graphical session within the timeout (wrong password, or no Hyprland/Quickshell)")
    clocks["session_record_s"] = tail.seen_at["session_ready"]


# ---- subcommands --------------------------------------------------------------------------

def cmd_onboard(args) -> int:
    creds = onboarding_credentials()
    out = Path(args.out)
    if out.exists():
        die(f"refusing to overwrite {out}")
    frames = Path(args.frames) if args.frames else out.parent
    frames.mkdir(parents=True, exist_ok=True)
    make_overlay(Path(args.base), out, relative=True)
    workdir = Path(tempfile.mkdtemp(prefix="bo-"))
    logdir = Path(tempfile.mkdtemp(prefix="bench-onboard-log-"))
    # Default (1280x800) resolution, the one framebuffer-probe.py is
    # calibrated for; no export port, so the injected probe stays idle.
    machine = Machine(args.arch, out, 4096, workdir, logdir, resolution=None, net="user")
    t = timeouts(machine.accel)
    frame = workdir / "frame.ppm"
    report = {"image": Path(args.base).name, "credentials_source": creds["source"], "accel": machine.accel}
    try:
        log(f"onboarding boot ({args.arch}, {machine.accel})")
        machine.start()
        q = machine.qmp
        if not qmplib.wait_state(q, frame, "onboarding", t["onboarding"], alive=machine.alive):
            die("the release onboarding surface did not appear")
        save_png(frame, frames / "onboarding-firstboot.png")
        q.type_text(creds["username"], enter=True)
        q.type_text(creds["password"], enter=True)
        q.type_text(creds["password"], enter=True)
        q.type_text(creds["device"], enter=True)
        # The receipt holds the one-time recovery code: it is recognised but
        # never saved, and its frame is overwritten at once.
        if not qmplib.wait_state(q, frame, "receipt", t["receipt"], alive=machine.alive):
            die("first-account creation did not reach its recovery receipt")
        q.send_key("ret")
        frame.unlink(missing_ok=True)
        if not qmplib.wait_state(q, frame, "desktop", t["desktop"], alive=machine.alive):
            die("first-account creation did not reach the desktop")
        save_png(frame, frames / "onboarding-desktop.png")
        report["desktop_after_s"] = machine.elapsed()
        # Let the first session write what it writes before powering off.
        time.sleep(args.settle)
        report["clean_shutdown"] = machine.stop(graceful_timeout=180)
        if not report["clean_shutdown"]:
            log("warning: the guest did not power off within 180 s; QEMU was stopped")
    finally:
        if machine.alive():
            machine.stop()
        shutil.rmtree(workdir, ignore_errors=True)
        serial = logdir / "serial.log"
        if serial.exists():
            shutil.copyfile(serial, frames / "onboarding-serial.log")
        shutil.rmtree(logdir, ignore_errors=True)
    (frames / "onboarding.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    log(f"onboarded disk: {out}")
    return 0


def start_capture(interface: str, path: Path) -> subprocess.Popen:
    # -Z root: tcpdump would otherwise drop to its own user before opening
    # the output file, which that user cannot create in the results folder.
    proc = subprocess.Popen(["sudo", "-n", "tcpdump", "-i", interface, "-n", "-U", "-s", "0", "-Z", "root",
                             "-w", str(path)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(2)
    if proc.poll() is not None:
        die("tcpdump did not start: " + proc.stderr.read().decode(errors="replace")[:300])
    return proc


TCPDUMP_COUNTERS = (
    ("captured", r"(\d+) packets? captured"),
    ("received_by_filter", r"(\d+) packets? received by filter"),
    ("dropped_by_kernel", r"(\d+) packets? dropped by kernel"),
    ("dropped_by_interface", r"(\d+) packets? dropped by interface"),
)


def capture_stats(alive_until_stop: bool, stderr: str) -> dict:
    """Whether a tcpdump capture is whole: it ran until the harness stopped it
    and neither the kernel nor the interface dropped a packet. A capture that
    died early or dropped packets under-counts what the guest sent, which
    would read as a privacy win, so the report never uses it."""
    stats: dict = {"method": "tcpdump", "alive_until_stop": alive_until_stop}
    for key, pattern in TCPDUMP_COUNTERS:
        match = re.search(pattern, stderr)
        stats[key] = int(match.group(1)) if match else None
    stats["complete"] = bool(alive_until_stop and stats["captured"] is not None
                             and not stats["dropped_by_kernel"] and not stats["dropped_by_interface"])
    return stats


def stop_capture(proc: subprocess.Popen | None) -> dict | None:
    if proc is None:
        return None
    alive = proc.poll() is None
    if alive:
        subprocess.run(["sudo", "-n", "kill", "-INT", str(proc.pid)], check=False)
        try:
            proc.wait(timeout=20)
        except subprocess.TimeoutExpired:
            subprocess.run(["sudo", "-n", "kill", "-KILL", str(proc.pid)], check=False)
            proc.wait()
    stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
    return capture_stats(alive, stderr)


def leases_address(leases: Path | None) -> str | None:
    if not leases or not leases.exists():
        return None
    for line in leases.read_text().splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1].lower() == GUEST_MAC:
            return parts[2]
    return None


def cmd_run(args) -> int:
    extra_meta = parse_meta(args.meta)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    workdir = Path(tempfile.mkdtemp(prefix="br-"))
    os.chmod(workdir, 0o700)
    overlay = workdir / "run.qcow2"
    make_overlay(Path(args.disk), overlay)
    config = workdir / "bench.conf"
    config_lines = [f"run_id={args.run_id}", f"workload={'yes' if args.workload else 'no'}"]
    if args.settle is not None:
        config_lines.append(f"settle_secs={args.settle}")
    if args.samples is not None:
        config_lines.append(f"samples={args.samples}")
    if args.interval is not None:
        config_lines.append(f"interval={args.interval}")
    config.write_text("\n".join(config_lines) + "\n")
    export = out / "export.jsonl"
    pcap = out / "privacy.pcap"
    credentials = []
    if args.inject == "credentials":
        credentials = smbios_credentials(workdir)
    quiesce = quiesce_host()
    capture = None
    capture_record = None
    if args.net == "tap":
        capture = start_capture(args.tap, pcap)
    disk_format = image_format(Path(args.disk))
    machine = Machine(args.arch, overlay, args.shape, workdir, out, resolution=args.resolution,
                      net=args.net, tap=args.tap, export=export, config=config,
                      privacy_dump=pcap if args.net == "user" else None, credentials=credentials)
    t = timeouts(machine.accel)
    settle = args.settle if args.settle is not None else 600
    window = (args.samples if args.samples is not None else 30) * (args.interval if args.interval is not None else 10)
    tail = ExportTail(export)
    clocks: dict = {}
    host_steal = {}
    meta = {
        "lane": args.lane, "shape_mib": args.shape, "vcpus": 4, "arch": args.arch,
        "accel": machine.accel, "resolution": args.resolution, "net": args.net,
        "login": args.login, "inject": args.inject, "run_id": args.run_id,
        "firmware": machine.firmware, "qemu": qemu_version(machine.binary),
        "graphics": "virtio-vga, no GPU acceleration (llvmpipe)" if args.arch == "x86_64"
                    else "virtio-gpu-pci, no GPU acceleration (llvmpipe)",
        "disk_encryption": args.disk_encryption, "disk_format": disk_format,
    }
    meta.update(extra_meta)
    frame = workdir / "frame.ppm"
    stat_start = host_cpu_times()
    failure = None
    privacy = scan = None
    try:
        log(f"run {args.run_id}: {args.lane} {args.shape} MiB ({machine.accel})")
        machine.start()
        q = machine.qmp
        login(args, machine, tail, t, frame, out, clocks)
        time.sleep(5)
        try:
            save_png(q.screendump(frame), out / "desktop.png")
        except (qmplib.QMPError, OSError):
            pass
        if tail.wait(machine, "window_start", settle + 300) is None:
            die("the idle window did not start")
        clocks["window_start_s"] = tail.seen_at["window_start"]
        host_steal["window_start"] = host_cpu_times()
        if tail.wait(machine, "window_end", window + 300) is None:
            die("the idle window did not end")
        clocks["window_end_s"] = tail.seen_at["window_end"]
        host_steal["window_end"] = host_cpu_times()
        # The privacy capture covers power-on to the end of the idle window.
        if args.net == "tap":
            capture_record = stop_capture(capture)
            capture = None
        else:
            q.object_del("privdump")
            capture_record = {"method": "qemu filter-dump", "complete": True}
        done = tail.wait(machine, "done", t["post"] + (t["workload"] if args.workload else 0))
        if done is None:
            die("the probe did not finish")
        clocks["done_s"] = tail.seen_at["done"]
        privacy = pcap_summary.summarize(pcap, GUEST_MAC) if pcap.exists() else None
        if privacy is not None:
            privacy["capture"] = capture_record
        if args.net == "tap" and args.scan:
            targets = []
            lease = leases_address(Path(args.leases) if args.leases else None)
            addresses = (privacy or {}).get("guest_addresses", {})
            for ip in ([lease] if lease else []) + addresses.get("ipv4", []):
                if ip and ip not in targets:
                    targets.append(ip)
            for ip in addresses.get("ipv6", []):
                target = f"{ip}%{args.tap}" if ip.startswith("fe80") else ip
                if target not in targets:
                    targets.append(target)
            log(f"scanning {', '.join(targets) or 'nothing (no guest address seen)'}")
            scan = portscan.scan(targets)
            clocks["scan_done_s"] = machine.elapsed()
        elif args.net != "tap":
            scan = {"schema": "punar-bench-scan/1", "complete": False,
                    "skipped": "user-mode networking has no route from the host to the guest"}
    except BenchFailure as error:
        # Every run is accounted for: a failed one still gets a result that
        # says why, and the report lists it as excluded.
        failure = str(error)
    finally:
        late = stop_capture(capture)
        if late is not None:
            # Stopped here only when the run failed before the window ended.
            late["complete"] = False
            capture_record = late
        if machine.alive():
            machine.stop()
        clocks["qemu_exit_s"] = machine.elapsed() if machine.started else None
        tail.poll(machine.started or time.monotonic())
        shutil.rmtree(workdir, ignore_errors=True)
    stat_end = host_cpu_times()
    host = host_facts()
    host["steal_pct_run"] = steal_pct(stat_start, stat_end)
    host["steal_pct_window"] = steal_pct(host_steal.get("window_start"), host_steal.get("window_end"))
    host["iowait_pct_window"] = steal_pct(host_steal.get("window_start"), host_steal.get("window_end"), index=2)
    host["quiesce"] = quiesce
    if privacy is None and pcap.exists():
        try:
            privacy = pcap_summary.summarize(pcap, GUEST_MAC)
            privacy["capture"] = capture_record
        except (OSError, ValueError):
            privacy = None
    host_doc = {"schema": "punar-bench-host/1", "meta": meta, "host": host, "clocks": clocks,
                "privacy": privacy, "scan": scan, "failure": failure}
    (out / "host.json").write_text(json.dumps(host_doc, indent=2, sort_keys=True) + "\n")
    result = bench_parse.parse_run(bench_parse.load_stream(export), host_doc)
    (out / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    validity = result["validity"]
    log(f"run {args.run_id}: used mean {result['idle'].get('memory', {}).get('used_mean_mib')} MiB; "
        f"valid for claims: {validity['valid_for_claims']} {validity['reasons']}")
    return 1 if failure else 0


def smbios_credentials(workdir: Path) -> list[Path]:
    """The probe as systemd credentials (SMBIOS type 11): no disk is touched."""
    import base64

    unit = (HERE / "bench-probe.service").read_text()
    items = {
        "systemd.extra-unit.bench-probe.service": unit.encode(),
        "systemd.unit-dropin.multi-user.target~bench-probe": b"[Unit]\nWants=bench-probe.service\n",
        "bench.probe": (HERE / "bench-probe.sh").read_bytes(),
        "bench.workload": (HERE / "workload" / "bench-workload.sh").read_bytes(),
    }
    paths = []
    for index, (name, data) in enumerate(items.items()):
        path = workdir / f"credential-{index}.txt"
        path.write_text(f"io.systemd.credential.binary:{name}={base64.b64encode(data).decode()}")
        paths.append(path)
    return paths


def cmd_warmup(args) -> int:
    """One signed-in boot of the disk itself before any measured run.

    Every measured run boots a throwaway overlay, so anything a system does
    once, on its first login (caches, first-run scripts, a wallpaper scaled
    to the screen), would otherwise be redone inside every run. This boot
    writes to the disk in place: it signs in exactly as a measured run does,
    at the measured resolution, stays in the session for --settle seconds
    (the measured settle, 600 s, by default) and powers off cleanly. Anything
    short of a clean power-off is a failure, because the next boot would
    replay a journal in every run.
    """
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    workdir = Path(tempfile.mkdtemp(prefix="bw-"))
    os.chmod(workdir, 0o700)
    config = workdir / "bench.conf"
    config.write_text("run_id=warmup\nworkload=no\n")
    export = out / "warmup.jsonl"
    disk = Path(args.disk)
    machine = Machine(args.arch, disk, args.shape, workdir, out, resolution=args.resolution,
                      net=args.net, tap=args.tap, export=export, config=config,
                      disk_format=image_format(disk))
    t = timeouts(machine.accel)
    tail = ExportTail(export)
    clocks: dict = {}
    report = {"disk": disk.name, "login": args.login, "resolution": args.resolution, "shape_mib": args.shape,
              "settle_s": args.settle, "accel": machine.accel, "net": args.net}
    failure = None
    try:
        log(f"warm-up boot of {disk.name} ({machine.accel}, {args.resolution})")
        machine.start()
        login(args, machine, tail, t, workdir / "frame.ppm", workdir, clocks)
        time.sleep(args.settle)
        report["clean_shutdown"] = machine.stop(graceful_timeout=300)
        if not report["clean_shutdown"]:
            die("the guest did not power off within 300 s of an ACPI power-down")
    except BenchFailure as error:
        failure = str(error)
    finally:
        if machine.alive():
            machine.stop()
        report["qemu_exit_s"] = machine.elapsed() if machine.started else None
        shutil.rmtree(workdir, ignore_errors=True)
    report["clocks"] = clocks
    report["failure"] = failure
    (out / "warmup.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 1 if failure else 0


def cmd_install_omarchy(args) -> int:
    """Unattended Omarchy install from its ISO and a CIDATA drive (owner-gated lane).

    The target is a sparse raw file, so it can be injected through a loop
    device without a second full-size copy. After the installer's reboot the
    disk passphrase is typed, SDDM signs the person in, and the first
    session is held for --settle seconds at the measured resolution before a
    clean power-off over SSH: the same first-login warm-up `warmup` gives
    Punar (Omarchy binds its power key to a menu, so ACPI cannot power it
    off). restore-stock.sh removes SSH afterwards.
    """
    if os.environ.get("BENCH_OMARCHY_APPROVED") != "yes":
        die("the Omarchy lane needs the owner's approval (tools/bench/README.md); BENCH_OMARCHY_APPROVED is not 'yes'")
    out = Path(args.out)
    if out.exists():
        die(f"refusing to overwrite {out}")
    subprocess.run(["qemu-img", "create", "-q", "-f", "raw", str(out), "40G"], check=True)
    workdir = Path(tempfile.mkdtemp(prefix="bi-"))
    logdir = Path(args.logs)
    logdir.mkdir(parents=True, exist_ok=True)
    extra = [
        "-drive", f"file={args.iso},media=cdrom,if=none,format=raw,id=benchiso",
        "-device", "ide-cd,drive=benchiso,bootindex=2",
        "-device", "qemu-xhci,id=benchusb",
        "-drive", f"file={args.cidata},format=raw,if=none,id=benchcidata",
        "-device", "usb-storage,bus=benchusb.0,drive=benchcidata",
    ]
    # The installer reboots itself into the installed system, so no -no-reboot.
    machine = Machine("x86_64", out, args.shape, workdir, logdir, resolution=MEASURED_RESOLUTION, net="user",
                      user_net_options=",hostfwd=tcp:127.0.0.1:2322-:22", extra=extra, no_reboot=False,
                      disk_format="raw")
    ssh = ["ssh", "-i", args.ssh_key, "-p", "2322", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=5", "-o", "BatchMode=yes",
           f"{args.user}@127.0.0.1"]
    report = {"iso": Path(args.iso).name}
    try:
        machine.start()
        deadline = time.monotonic() + args.timeout
        frame = workdir / "frame.ppm"
        rebooted = False
        typed_unlock = False
        while time.monotonic() < deadline:
            if not machine.alive():
                die("QEMU exited during the install")
            if subprocess.run(ssh + ["true"], capture_output=True, check=False).returncode == 0:
                break
            # The installer's own reboot shows up as a RESET event; the
            # encrypted disk then asks for its passphrase before sshd starts.
            if any(e.get("event") == "RESET" for e in machine.qmp.poll_events()):
                rebooted = True
                report["installer_reboot_s"] = machine.elapsed()
            if rebooted and not typed_unlock and qmplib.wait_stable(
                    machine.qmp, frame, 120, settle=2.0, checks=3, alive=machine.alive):
                secret = Path(args.secret_file).read_text().strip("\r\n")
                machine.qmp.type_text(secret, enter=True)
                del secret
                typed_unlock = True
                report["unlock_typed_s"] = machine.elapsed()
            time.sleep(10)
        else:
            die("the install did not finish within the timeout")
        report["install_to_ssh_s"] = machine.elapsed()
        # The first desktop session: wait for Hyprland, then hold it for the
        # same settle a measured run gets before its window.
        session_deadline = time.monotonic() + 600
        while time.monotonic() < session_deadline:
            if subprocess.run(ssh + ["pgrep", "-u", args.user, "-x", "Hyprland"], capture_output=True,
                              check=False).returncode == 0:
                report["desktop_after_s"] = machine.elapsed()
                break
            time.sleep(5)
        else:
            die("no Hyprland session for the person within 600 s of SSH answering")
        time.sleep(args.settle)
        report["warmup_settle_s"] = args.settle
        timing = subprocess.run(ssh + ["cat", "/var/log/omarchy-install-timing.json"], capture_output=True,
                                text=True, check=False)
        if timing.returncode == 0:
            (logdir / "omarchy-install-timing.json").write_text(timing.stdout)
        version = subprocess.run(ssh + ["pacman", "-Q", "omarchy"], capture_output=True, text=True, check=False)
        report["omarchy_package"] = version.stdout.strip()
        secret = Path(args.secret_file).read_text().strip("\r\n")
        subprocess.run(ssh + ["sudo", "-S", "systemctl", "poweroff"], input=secret + "\n", text=True,
                       capture_output=True, check=False)
        del secret
        end = time.monotonic() + 300
        while machine.alive() and time.monotonic() < end:
            time.sleep(1)
        report["clean_shutdown"] = not machine.alive()
        if not report["clean_shutdown"]:
            die("the installed system did not power off within 300 s")
    finally:
        if machine.alive():
            machine.stop()
        shutil.rmtree(workdir, ignore_errors=True)
    (logdir / "install.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


def _terminate(_signum, _frame):
    raise SystemExit(143)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)

    onboard = sub.add_parser("onboard", help="create the release image's first account once")
    onboard.add_argument("--base", required=True)
    onboard.add_argument("--out", required=True)
    onboard.add_argument("--arch", default="x86_64", choices=("x86_64", "arm64"))
    onboard.add_argument("--frames")
    onboard.add_argument("--settle", type=int, default=30)

    warm = sub.add_parser("warmup", help="one signed-in boot of the disk in place before measured runs")
    warm.add_argument("--disk", required=True)
    warm.add_argument("--out", required=True)
    warm.add_argument("--arch", default="x86_64", choices=("x86_64", "arm64"))
    warm.add_argument("--shape", type=int, default=8192)
    warm.add_argument("--resolution", default=MEASURED_RESOLUTION)
    warm.add_argument("--net", default="user", choices=("user", "tap"))
    warm.add_argument("--tap", default="benchtap0")
    warm.add_argument("--login", default="punar-greeter", choices=("punar-greeter", "luks-autologin"))
    warm.add_argument("--secret-file", help="file holding the password or passphrase to type")
    warm.add_argument("--settle", type=int, default=600, help="seconds in the session before powering off")

    run = sub.add_parser("run", help="one measured boot")
    run.add_argument("--lane", required=True)
    run.add_argument("--disk", required=True)
    run.add_argument("--shape", type=int, required=True, help="guest memory in MiB")
    run.add_argument("--out", required=True)
    run.add_argument("--run-id", required=True)
    run.add_argument("--arch", default="x86_64", choices=("x86_64", "arm64"))
    run.add_argument("--resolution", default=MEASURED_RESOLUTION)
    run.add_argument("--net", default="user", choices=("user", "tap"))
    run.add_argument("--tap", default="benchtap0")
    run.add_argument("--leases")
    run.add_argument("--scan", action=argparse.BooleanOptionalAction, default=True)
    run.add_argument("--login", default="punar-greeter", choices=("punar-greeter", "luks-autologin", "none"))
    run.add_argument("--secret-file", help="file holding the password or passphrase to type")
    run.add_argument("--disk-encryption", default="none")
    run.add_argument("--inject", default="offline", choices=("offline", "credentials"))
    run.add_argument("--workload", action=argparse.BooleanOptionalAction, default=False)
    run.add_argument("--settle", type=int, help="non-canonical: shorter settle (smoke tests only)")
    run.add_argument("--samples", type=int, help="non-canonical")
    run.add_argument("--interval", type=int, help="non-canonical")
    run.add_argument("--meta", action="append", default=[], help="KEY=VALUE recorded in the result")

    install = sub.add_parser("install-omarchy", help="unattended Omarchy install (owner-gated)")
    install.add_argument("--iso", required=True)
    install.add_argument("--cidata", required=True)
    install.add_argument("--secret-file", required=True)
    install.add_argument("--ssh-key", required=True)
    install.add_argument("--user", default="bench")
    install.add_argument("--shape", type=int, default=8192)
    install.add_argument("--timeout", type=int, default=2400)
    install.add_argument("--settle", type=int, default=600, help="seconds in the first session before powering off")
    install.add_argument("--out", required=True)
    install.add_argument("--logs", required=True)

    args = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, _terminate)
    try:
        if args.command == "onboard":
            return cmd_onboard(args)
        if args.command == "warmup":
            return cmd_warmup(args)
        if args.command == "run":
            return cmd_run(args)
        return cmd_install_omarchy(args)
    except BenchFailure:
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
