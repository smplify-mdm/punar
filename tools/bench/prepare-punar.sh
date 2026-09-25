#!/usr/bin/env bash
# Prepare the Punar release image for benchmark runs (tools/bench/README.md).
#
#   tools/bench/prepare-punar.sh RELEASE.qcow2 OUT_DIR
#
# 1. Convert the release qcow2 to a sparse raw copy, so the probe can be
#    injected through a loop device (no nbd module needed on CI runners).
# 2. Inject the probe into its PUNAR-ROOT-A slot (inject-probe.sh, as root).
# 3. Convert back to a compressed qcow2: OUT_DIR/prepared.qcow2.
# 4. Boot it once to create the release image's first account through the
#    onboarding screens, keeping the result as a small overlay:
#    OUT_DIR/onboarded.qcow2 (its backing file is referenced relatively, so
#    the pair can be moved together).
#
# Every run then boots a fresh overlay of onboarded.qcow2. The original
# release image is never modified.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE="${1:-}"
OUT="${2:-}"
ARCH="${BENCH_ARCH:-x86_64}"

die() {
    echo "prepare-punar: $*" >&2
    exit 1
}

[ -f "${RELEASE}" ] || die "usage: prepare-punar.sh RELEASE.qcow2 OUT_DIR"
[ -n "${OUT}" ] || die "usage: prepare-punar.sh RELEASE.qcow2 OUT_DIR"
[ ! -e "${OUT}/prepared.qcow2" ] || die "${OUT}/prepared.qcow2 already exists"
mkdir -p "${OUT}"
for tool in qemu-img python3 sha256sum; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} is required"
done

raw="${OUT}/prepared.raw"
trap 'rm -f "${raw}"' EXIT
echo "==> sparse raw copy of $(basename "${RELEASE}")"
qemu-img convert -f qcow2 -O raw "${RELEASE}" "${raw}"
echo "==> inject the probe"
sudo -n "${HERE}/inject-probe.sh" --image "${raw}" --partlabel PUNAR-ROOT-A \
    --record "${OUT}/injection.json"
echo "==> compressed qcow2"
qemu-img convert -f raw -O qcow2 -c "${raw}" "${OUT}/prepared.qcow2"
rm -f "${raw}"
echo "==> first account through the onboarding screens"
python3 "${HERE}/bench_run.py" onboard --arch "${ARCH}" --base "${OUT}/prepared.qcow2" \
    --out "${OUT}/onboarded.qcow2" --frames "${OUT}/onboarding"

python3 - "${OUT}" "${RELEASE}" <<'PY'
import hashlib, json, os, sys
out, release = sys.argv[1], sys.argv[2]

def sha(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()

record = {
    "schema": "punar-bench-prepare/1",
    "release_image": os.path.basename(release),
    "release_image_sha256": sha(release),
    "prepared_sha256": sha(os.path.join(out, "prepared.qcow2")),
    "onboarded_sha256": sha(os.path.join(out, "onboarded.qcow2")),
    "source_run_id": os.environ.get("BENCH_SOURCE_RUN_ID", ""),
    "source_commit": os.environ.get("BENCH_SOURCE_COMMIT", ""),
}
with open(os.path.join(out, "prepare.json"), "w") as handle:
    json.dump(record, handle, indent=2, sort_keys=True)
    handle.write("\n")
print(json.dumps(record, indent=2))
PY
