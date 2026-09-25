#!/usr/bin/env python3
"""A small QMP client for the benchmark harness (tools/bench/README.md).

Keystrokes, screen dumps, power control and frame-state detection over one
QMP socket. Secrets are only ever read from a file or standard input and
typed; they never appear in argv, logs or saved frames.

The screen states are tools/framebuffer-probe.py's (run as a program, so its
thresholds live in one place) and the keyboard map is tools/vm-type.py's.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


framebuffer = _load("framebuffer_probe", REPO_ROOT / "tools" / "framebuffer-probe.py")
keymap = _load("vm_type", REPO_ROOT / "tools" / "vm-type.py")


class QMPError(RuntimeError):
    pass


class QMP:
    """One QMP connection (unix socket path or host:port)."""

    def __init__(self, address: str, timeout: float = 10.0):
        if ":" in address and not address.startswith("/"):
            host, port = address.rsplit(":", 1)
            self.sock = socket.create_connection((host, int(port)), timeout=timeout)
        else:
            self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect(address)
        self.stream = self.sock.makefile("rwb")
        self.events: list[dict] = []
        greeting = self._read()
        if "QMP" not in greeting:
            raise QMPError("not a QMP greeting")
        self.command("qmp_capabilities")

    def _read(self) -> dict:
        line = self.stream.readline()
        if not line:
            raise QMPError("QMP connection closed")
        return json.loads(line)

    def command(self, name: str, **arguments) -> object:
        payload: dict = {"execute": name}
        if arguments:
            payload["arguments"] = arguments
        self.stream.write((json.dumps(payload) + "\n").encode())
        self.stream.flush()
        while True:
            reply = self._read()
            if "event" in reply:
                self.events.append(reply)
                continue
            if "error" in reply:
                raise QMPError(f"{name}: {reply['error'].get('desc', reply['error'])}")
            return reply.get("return")

    def hmp(self, command_line: str) -> str:
        return str(self.command("human-monitor-command", **{"command-line": command_line}))

    def send_key(self, key: str, hold_ms: int = 50) -> None:
        self.hmp(f"sendkey {key} {hold_ms}")

    def type_text(self, text: str, delay: float = 0.08, enter: bool = False) -> None:
        keys = [keymap.key_for(character) for character in text]
        if None in keys:
            # Refuse before the first key, so a partial secret never lands.
            raise QMPError("text contains a character the keyboard map cannot type")
        if enter:
            keys.append("ret")
        for key in keys:
            self.send_key(key)
            time.sleep(delay)

    def screendump(self, path: Path) -> Path:
        path = Path(path)
        path.unlink(missing_ok=True)
        self.command("screendump", filename=str(path))
        for _ in range(50):
            if path.exists() and path.stat().st_size > 0:
                break
            time.sleep(0.05)
        return path

    def powerdown(self) -> None:
        self.command("system_powerdown")

    def quit(self) -> None:
        try:
            self.command("quit")
        except (QMPError, OSError):
            pass

    def poll_events(self) -> list[dict]:
        """Events QEMU sent since the last call (RESET, SHUTDOWN, ...)."""
        self.command("query-status")
        events, self.events = self.events, []
        return events

    def object_del(self, object_id: str) -> None:
        self.command("object-del", id=object_id)

    def close(self) -> None:
        try:
            self.stream.close()
            self.sock.close()
        except OSError:
            pass


def wait_for_socket(address: str, deadline: float, alive=lambda: True) -> QMP:
    last = None
    while time.monotonic() < deadline:
        if not alive():
            raise QMPError("QEMU exited before QMP was ready")
        try:
            return QMP(address)
        except (OSError, QMPError) as error:
            last = error
            time.sleep(0.1)
    raise QMPError(f"QMP did not become ready: {last}")


def frame_digest(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def frame_is_black(path: Path, threshold: int = 16) -> bool:
    width, height, pixels = framebuffer.read_ppm(Path(path))
    step = max(1, len(pixels) // (3 * 4096)) * 3
    return all(pixels[i] < threshold for i in range(0, len(pixels), step))


def classify(path: Path, state: str) -> bool:
    """True when tools/framebuffer-probe.py says the frame is in `state`.

    The classifier runs as its own program, so its thresholds live in one
    place. "prelogin" is its "onboarding" state: a centred card with no
    desktop bar, which is also what the password greeter shows.
    """
    wanted = "onboarding" if state == "prelogin" else state
    if wanted not in ("onboarding", "receipt", "desktop"):
        raise ValueError(state)
    result = subprocess.run(
        [sys.executable, str(REPO_ROOT / "tools" / "framebuffer-probe.py"), wanted, str(path)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    return result.returncode == 0


def wait_state(qmp: QMP, frame: Path, state: str, timeout: float, interval: float = 2.0,
               alive=lambda: True) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not alive():
            return False
        try:
            if classify(qmp.screendump(frame), state):
                return True
        except (OSError, ValueError, QMPError):
            pass
        time.sleep(interval)
    return False


def wait_stable(qmp: QMP, frame: Path, timeout: float, settle: float = 1.0, checks: int = 2,
                alive=lambda: True, not_black: bool = True) -> bool:
    """Wait until consecutive screen dumps `settle` seconds apart are identical."""
    deadline = time.monotonic() + timeout
    previous = None
    same = 0
    while time.monotonic() < deadline:
        if not alive():
            return False
        try:
            path = qmp.screendump(frame)
            digest = frame_digest(path)
            black = frame_is_black(path) if not_black else False
        except (OSError, ValueError, QMPError):
            digest, black = None, True
        if digest is not None and not black and digest == previous:
            same += 1
            if same >= checks - 1:
                return True
        else:
            same = 0
        previous = digest
        time.sleep(settle)
    return False


def read_secret(source: str) -> str:
    if source == "-":
        return sys.stdin.read().strip("\r\n")
    return Path(source).read_text().strip("\r\n")


def main(argv: list[str]) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--qmp", required=True, help="unix socket path or host:port")
    sub = parser.add_subparsers(dest="action", required=True)
    type_parser = sub.add_parser("type", help="type a secret read from a file or '-' (stdin)")
    type_parser.add_argument("--from", dest="source", required=True)
    type_parser.add_argument("--enter", action="store_true")
    key_parser = sub.add_parser("key")
    key_parser.add_argument("keys", nargs="+")
    dump_parser = sub.add_parser("screendump")
    dump_parser.add_argument("path", type=Path)
    state_parser = sub.add_parser("wait-state")
    state_parser.add_argument("state", choices=("prelogin", "onboarding", "receipt", "desktop"))
    state_parser.add_argument("--frame", type=Path, required=True)
    state_parser.add_argument("--timeout", type=float, default=120)
    stable_parser = sub.add_parser("wait-stable")
    stable_parser.add_argument("--frame", type=Path, required=True)
    stable_parser.add_argument("--timeout", type=float, default=120)
    sub.add_parser("powerdown")
    sub.add_parser("quit")
    args = parser.parse_args(argv)

    qmp = QMP(args.qmp)
    try:
        if args.action == "type":
            qmp.type_text(read_secret(args.source), enter=args.enter)
        elif args.action == "key":
            for key in args.keys:
                qmp.send_key(key)
                time.sleep(0.08)
        elif args.action == "screendump":
            qmp.screendump(args.path)
        elif args.action == "wait-state":
            return 0 if wait_state(qmp, args.frame, args.state, args.timeout) else 1
        elif args.action == "wait-stable":
            return 0 if wait_stable(qmp, args.frame, args.timeout) else 1
        elif args.action == "powerdown":
            qmp.powerdown()
        elif args.action == "quit":
            qmp.quit()
    finally:
        qmp.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
