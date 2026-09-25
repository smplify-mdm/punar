#!/usr/bin/env python3
"""Press keys in a running desktop gate VM when the guest asks for them.

tools/boot-test.sh starts this beside QEMU in desktop mode. The in-guest
keys check (os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/
keys-check.sh) prints `PUNAR_QMP_KEYS <id> <name> [numbers...]` on the
serial console; this reads the serial log, and for each new request sends
the named sequence as real input events over QEMU's QMP socket
(`input-send-event`), so the guest sees a keyboard and a pointer, not an IPC
call. The guest then checks the effect itself.

Only the sequences named in SEQUENCES exist. A request for anything else is
logged and ignored: the guest can ask for keys, never choose arbitrary ones,
and nothing it prints reaches a shell on this host. Numbers are only ever
pointer coordinates, clamped to QEMU's absolute range.

    qmp-keys.py <qmp-socket> <serial-log> <stop-file> <log>

Exits when <stop-file> contains PUNAR_EXPORT_END or QEMU goes away.
"""
import json
import os
import re
import socket
import sys
import time

REQUEST = re.compile(r"PUNAR_QMP_KEYS (\d{1,4}) ([a-z0-9-]{1,24})((?: -?\d{1,6}){0,4})\s*$")
ABS_MAX = 32767


def key(name, down):
    return {"type": "key", "data": {"down": down, "key": {"type": "qcode", "data": name}}}


def chord(*names):
    """Press names in order, release in reverse: one chord."""
    return [[key(n, True)] for n in names] + [[key(n, False)] for n in reversed(names)]


def typed(text):
    steps = []
    for ch in text:
        steps += [[key(ch, True)], [key(ch, False)]]
    return steps


def punar_wheel(button):
    """One notch of the wheel with the Punar key held."""
    return [[key("meta_l", True)],
            [{"type": "btn", "data": {"down": True, "button": button}}],
            [{"type": "btn", "data": {"down": False, "button": button}}],
            [key("meta_l", False)]]


def drag(button, x1, y1, x2, y2):
    def at(x, y):
        return [{"type": "abs", "data": {"axis": "x", "value": max(0, min(ABS_MAX, x))}},
                {"type": "abs", "data": {"axis": "y", "value": max(0, min(ABS_MAX, y))}}]
    steps = [at(x1, y1), [key("meta_l", True)], [{"type": "btn", "data": {"down": True, "button": button}}]]
    for i in range(1, 9):
        steps.append(at(x1 + (x2 - x1) * i // 8, y1 + (y2 - y1) * i // 8))
    steps += [[{"type": "btn", "data": {"down": False, "button": button}}], [key("meta_l", False)]]
    return steps


SEQUENCES = {
    # Types "ok" and Return into the focused probe window: the handshake
    # that proves this driver is reaching the guest's keyboard at all.
    "ping": lambda: typed("ok") + chord("ret"),
    "punar-return": lambda: chord("meta_l", "ret"),
    "alt-tab": lambda: chord("alt", "tab"),
    # Alt held across two Tabs, then released: the third window.
    "alt-tab-tab": lambda: [[key("alt", True)]] + chord("tab") + chord("tab") + [[key("alt", False)]],
    # grp:alts_toggle: both Alt keys together switch the layout.
    "alts": lambda: chord("alt", "alt_r"),
    # On the Russian layout these Latin keys type "привет".
    "cyrillic": lambda: typed("ghbdtn") + chord("ret"),
    "punar-0": lambda: chord("meta_l", "0"),
    "punar-1": lambda: chord("meta_l", "1"),
    # The 2 key: under AZERTY it types é, and the workspace bind still fires.
    "punar-2": lambda: chord("meta_l", "2"),
    "punar-f1": lambda: chord("meta_l", "f1"),
    # The Mac-style clipboard keys, then Return on its own.
    "punar-c": lambda: chord("meta_l", "c"),
    "punar-v": lambda: chord("meta_l", "v"),
    "return": lambda: chord("ret"),
    "punar-ctrl-t": lambda: chord("meta_l", "ctrl", "t"),
    "punar-alt-2": lambda: chord("meta_l", "alt", "2"),
    "punar-m": lambda: chord("meta_l", "m"),
    "punar-o": lambda: chord("meta_l", "o"),
    # The rest of the window grammar: swap right, toggle the split, the
    # file manager, next workspace, and the workspace wheel.
    "punar-alt-l": lambda: chord("meta_l", "alt", "l"),
    "punar-d": lambda: chord("meta_l", "d"),
    "punar-e": lambda: chord("meta_l", "e"),
    "punar-ctrl-tab": lambda: chord("meta_l", "ctrl", "tab"),
    "punar-wheel-down": lambda: punar_wheel("wheel-down"),
    "drag": lambda x1, y1, x2, y2: drag("left", x1, y1, x2, y2),
    "rdrag": lambda x1, y1, x2, y2: drag("right", x1, y1, x2, y2),
}


class Qmp:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.connect(path)
        self.buf = b""
        self.read()  # greeting
        self.command({"execute": "qmp_capabilities"})

    def read(self):
        while b"\n" not in self.buf:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise ConnectionError("QMP closed")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return json.loads(line)

    def command(self, message):
        self.sock.sendall(json.dumps(message).encode() + b"\n")
        while True:
            reply = self.read()
            if "return" in reply or "error" in reply:
                return reply


def main():
    qmp_path, serial_path, stop_path, log_path = sys.argv[1:5]
    log = open(log_path, "a", buffering=1)
    for _ in range(600):
        if os.path.exists(qmp_path):
            break
        time.sleep(0.5)
    try:
        qmp = Qmp(qmp_path)
    except OSError as error:
        log.write(f"qmp: could not connect: {error}\n")
        return 0
    log.write("qmp: connected\n")
    done = set()
    offset = 0
    while True:
        try:
            with open(stop_path, "rb") as stop:
                if b"PUNAR_EXPORT_END" in stop.read():
                    log.write("qmp: export finished; stopping\n")
                    return 0
        except FileNotFoundError:
            pass
        try:
            with open(serial_path, "rb") as serial:
                serial.seek(offset)
                data = serial.read()
                offset += len(data)
        except FileNotFoundError:
            data = b""
        for raw in data.decode("utf-8", "replace").splitlines():
            match = REQUEST.search(raw)
            if not match:
                continue
            request_id, name = match.group(1), match.group(2)
            numbers = [int(n) for n in match.group(3).split()]
            if request_id in done:
                continue
            done.add(request_id)
            sequence = SEQUENCES.get(name)
            if sequence is None:
                log.write(f"qmp: {request_id} {name}: not an allowed sequence; ignored\n")
                continue
            try:
                steps = sequence(*numbers)
            except TypeError:
                log.write(f"qmp: {request_id} {name}: wrong arguments {numbers}; ignored\n")
                continue
            try:
                for events in steps:
                    reply = qmp.command({"execute": "input-send-event", "arguments": {"events": events}})
                    if "error" in reply:
                        log.write(f"qmp: {request_id} {name}: {reply['error']}\n")
                        break
                    time.sleep(0.04)
            except (OSError, ConnectionError) as error:
                log.write(f"qmp: {request_id} {name}: QEMU went away ({error})\n")
                return 0
            log.write(f"qmp: {request_id} {name} {numbers}: sent {len(steps)} steps\n")
        time.sleep(0.25)


if __name__ == "__main__":
    sys.exit(main())
