#!/usr/bin/env python3
"""Emit a deterministic, content-addressed manifest for one filesystem tree."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def kind(mode: int) -> str:
    if stat.S_ISREG(mode):
        return "file"
    if stat.S_ISDIR(mode):
        return "directory"
    if stat.S_ISLNK(mode):
        return "symlink"
    if stat.S_ISBLK(mode):
        return "block"
    if stat.S_ISCHR(mode):
        return "character"
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    raise ValueError(f"unsupported inode type: {mode:o}")


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: tree_manifest.py ROOT OUTPUT", file=sys.stderr)
        return 2

    root = Path(sys.argv[1]).resolve(strict=True)
    output = Path(sys.argv[2])
    if not root.is_dir():
        print(f"error: tree root is not a directory: {root}", file=sys.stderr)
        return 2

    entries: list[dict[str, object]] = []
    paths = [root]
    paths.extend(sorted(root.rglob("*"), key=lambda item: os.fsencode(str(item.relative_to(root)))))
    for path in paths:
        metadata = path.lstat()
        relative = path.relative_to(root)
        name = "/" if relative == Path(".") else "/" + relative.as_posix()
        entry: dict[str, object] = {
            "path": name,
            "type": kind(metadata.st_mode),
            "mode": f"{stat.S_IMODE(metadata.st_mode):04o}",
            "uid": metadata.st_uid,
            "gid": metadata.st_gid,
        }
        if stat.S_ISREG(metadata.st_mode):
            entry["size_bytes"] = metadata.st_size
            entry["sha256"] = digest(path)
        elif stat.S_ISLNK(metadata.st_mode):
            entry["target"] = os.readlink(path)
        elif stat.S_ISBLK(metadata.st_mode) or stat.S_ISCHR(metadata.st_mode):
            entry["device_major"] = os.major(metadata.st_rdev)
            entry["device_minor"] = os.minor(metadata.st_rdev)
        entries.append(entry)

    document = {"schema_version": 1, "entries": entries}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(document, stream, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
