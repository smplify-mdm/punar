#!/usr/bin/env bash
# Exercise the deterministic root-tree manifest used for installer I04.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MANIFEST_TOOL="${REPO_ROOT}/tools/tree_manifest.py"
WORK="$(mktemp -d)"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

ROOT="${WORK}/root"
mkdir -p "${ROOT}/etc" "${ROOT}/usr/bin" "${ROOT}/empty"
printf 'punar\n' > "${ROOT}/etc/os-release"
printf '#!/bin/sh\nexit 0\n' > "${ROOT}/usr/bin/punar-probe"
chmod 0755 "${ROOT}/usr/bin/punar-probe"
ln -s ../etc/os-release "${ROOT}/release-link"

python3 "${MANIFEST_TOOL}" "${ROOT}" "${WORK}/one.json"
python3 "${MANIFEST_TOOL}" "${ROOT}" "${WORK}/two.json"
cmp "${WORK}/one.json" "${WORK}/two.json"

python3 - "${WORK}/one.json" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    document = json.load(stream)

assert document["schema_version"] == 1
entries = {entry["path"]: entry for entry in document["entries"]}

assert entries["/usr/bin/punar-probe"]["type"] == "file"
assert entries["/usr/bin/punar-probe"]["mode"] == "0755"
assert len(entries["/usr/bin/punar-probe"]["sha256"]) == 64
assert entries["/release-link"]["path"] == "/release-link"
assert entries["/release-link"]["target"] == "../etc/os-release"
assert entries["/release-link"]["type"] == "symlink"
assert len(entries["/release-link"]["mode"]) == 4
assert entries["/empty"]["type"] == "directory"
PY

printf 'changed\n' >> "${ROOT}/etc/os-release"
python3 "${MANIFEST_TOOL}" "${ROOT}" "${WORK}/changed.json"
if cmp -s "${WORK}/one.json" "${WORK}/changed.json"; then
    echo 'tree-manifest-test: FAIL: content mutation did not change the manifest' >&2
    exit 1
fi

chmod 0700 "${ROOT}/empty"
python3 "${MANIFEST_TOOL}" "${ROOT}" "${WORK}/mode-changed.json"
if cmp -s "${WORK}/changed.json" "${WORK}/mode-changed.json"; then
    echo 'tree-manifest-test: FAIL: mode mutation did not change the manifest' >&2
    exit 1
fi

echo 'tree-manifest-test: PASS'
