#!/usr/bin/env python3
"""Remove the harness's secrets from files before they are uploaded (tools/bench/README.md).

    scrub.py DIR... [--secret-file FILE]... [--punar-test-password]

The repository is public, so its workflow artifacts can be downloaded by
anyone signed in to GitHub. Nothing the harness writes is meant to contain a
secret (keys are typed from files, the greeter frame is saved before typing,
the recovery receipt is never saved), but consoles and logs are written by
the systems under test, so every text file under DIR is checked anyway and
each occurrence of a secret is replaced by "[redacted]". The secrets are the
Omarchy lane's throwaway passphrase (--secret-file) and the release image's
CI test password (--punar-test-password, read from
tools/test-release-onboarding.sh). Binary captures and images are skipped:
the raw packet captures are uploaded only on request and only for 3 days.

Prints what it replaced (file names and counts, never the secret) and exits 0.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKIP_SUFFIXES = {".pcap", ".png", ".ppm", ".qcow2", ".raw", ".img", ".iso", ".fd"}
MARK = b"[redacted]"


def scrub(directories: list[Path], secrets: list[bytes]) -> dict[str, int]:
    secrets = [s for s in secrets if len(s) >= 6]
    replaced: dict[str, int] = {}
    for directory in directories:
        if not directory.exists():
            continue
        for path in sorted(p for p in directory.rglob("*") if p.is_file() and not p.is_symlink()):
            if path.suffix.lower() in SKIP_SUFFIXES:
                continue
            data = path.read_bytes()
            count = sum(data.count(secret) for secret in secrets)
            if count:
                for secret in secrets:
                    data = data.replace(secret, MARK)
                path.write_bytes(data)
                replaced[str(path)] = count
    return replaced


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directories", nargs="+", type=Path)
    parser.add_argument("--secret-file", action="append", default=[], type=Path)
    parser.add_argument("--punar-test-password", action="store_true")
    args = parser.parse_args(argv)
    secrets = []
    for path in args.secret_file:
        if path.exists():
            secrets.append(path.read_bytes().strip(b"\r\n"))
    if args.punar_test_password:
        sys.path.insert(0, str(HERE))
        import bench_run  # noqa: E402

        secrets.append(bench_run.onboarding_credentials()["password"].encode())
    replaced = scrub(args.directories, secrets)
    for path, count in replaced.items():
        print(f"scrub: {path}: {count} occurrence(s) redacted")
    print(f"scrub: {len(replaced)} file(s) changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
