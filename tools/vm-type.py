#!/usr/bin/env python3
"""Type standard input into the running local Punar demo VM's keyboard.

    pbpaste | tools/vm-type.py --enter

QEMU's Cocoa window has no clipboard sharing with the guest, so a long
value — an enrollment code, a URL — would otherwise have to be typed by
hand. This reads the text from stdin (never argv, which is world-readable),
sends it as key presses over the demo launcher's localhost-only QMP socket,
and never echoes it. Only printable ASCII that a US keyboard can produce is
accepted; anything else is refused before a single key is sent, so a
partial secret never lands in a prompt.
"""
import argparse
import json
import os
import socket
import sys
import time

SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equal", "{": "bracket_left",
    "}": "bracket_right", "|": "backslash", ":": "semicolon", '"': "apostrophe",
    "<": "comma", ">": "dot", "?": "slash", "~": "grave_accent",
}
PLAIN = {
    "-": "minus", "=": "equal", "[": "bracket_left", "]": "bracket_right",
    "\\": "backslash", ";": "semicolon", "'": "apostrophe", ",": "comma",
    ".": "dot", "/": "slash", "`": "grave_accent", " ": "spc",
}


def key_for(char):
    if "a" <= char <= "z" or "0" <= char <= "9":
        return char
    if "A" <= char <= "Z":
        return "shift-" + char.lower()
    if char in PLAIN:
        return PLAIN[char]
    if char in SHIFTED:
        return "shift-" + SHIFTED[char]
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--enter", action="store_true", help="press Enter after the text")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PUNAR_QMP_PORT", "4445")))
    parser.add_argument("--delay", type=float, default=0.03, help="seconds between keys")
    args = parser.parse_args()

    text = sys.stdin.read().strip("\r\n")
    keys = [key_for(c) for c in text]
    if not text:
        print("vm-type: nothing on standard input; nothing was typed", file=sys.stderr)
        return 2
    if None in keys:
        print("vm-type: the text contains characters this keyboard map cannot type; nothing was typed", file=sys.stderr)
        return 2
    if args.enter:
        keys.append("ret")

    try:
        conn = socket.create_connection(("127.0.0.1", args.port), timeout=5)
    except OSError as error:
        print(f"vm-type: no demo VM monitor on 127.0.0.1:{args.port} ({error}); nothing was typed", file=sys.stderr)
        return 1
    stream = conn.makefile("rwb")

    def request(payload):
        stream.write((json.dumps(payload) + "\n").encode())
        stream.flush()
        while True:
            line = stream.readline()
            if not line:
                raise RuntimeError("the VM monitor closed the connection")
            reply = json.loads(line)
            if "return" in reply or "error" in reply:
                return reply

    stream.readline()  # greeting
    request({"execute": "qmp_capabilities"})
    for key in keys:
        reply = request({"execute": "human-monitor-command",
                         "arguments": {"command-line": f"sendkey {key}"}})
        if "error" in reply:
            print("vm-type: the VM refused a key press; typing stopped", file=sys.stderr)
            return 1
        time.sleep(args.delay)
    conn.close()
    print(f"vm-type: typed {len(text)} characters{' and Enter' if args.enter else ''}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
