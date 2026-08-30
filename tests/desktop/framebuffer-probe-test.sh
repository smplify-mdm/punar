#!/bin/sh
set -eu

REPO_ROOT=$(cd -- "$(dirname "$0")/../.." && pwd)
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/punar-framebuffer-probe.XXXXXX")
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

python3 - "${TEST_ROOT}" <<'PY'
from pathlib import Path
import sys

root = Path(sys.argv[1])
width, height = 640, 400


def write(name, painter):
    pixels = bytearray([18, 22, 35]) * (width * height)
    for y in range(height):
        for x in range(width):
            color = painter(x, y)
            if color is None:
                continue
            offset = (y * width + x) * 3
            pixels[offset:offset + 3] = bytes(color)
    (root / name).write_bytes(
        f"P6\n{width} {height}\n255\n".encode("ascii") + pixels
    )


def onboarding(x, y):
    if 448 <= x < 544 and 326 <= y < 362:
        return (38, 112, 35)
    if 32 <= x < 608 and 80 <= y < 375:
        return (245, 244, 241)
    return None


write("onboarding.ppm", onboarding)
write(
    "receipt.ppm",
    lambda x, y: (245, 244, 241) if 32 <= x < 608 and 80 <= y < 375 else None,
)
write(
    "desktop.ppm",
    # Match the real shell's 30/800 (3.75%) top-bar geometry closely. A
    # broader synthetic bar would conceal regressions in the probe window.
    lambda x, y: (246, 245, 242) if y < 15 else None,
)
(root / "invalid.ppm").write_text("not a framebuffer", encoding="utf-8")
PY

PROBE="${REPO_ROOT}/tools/framebuffer-probe.py"
python3 "${PROBE}" onboarding "${TEST_ROOT}/onboarding.ppm" >/dev/null
if python3 "${PROBE}" receipt "${TEST_ROOT}/onboarding.ppm" >/dev/null; then
    echo "unfinished onboarding was misclassified as the recovery receipt" >&2
    exit 1
fi
python3 "${PROBE}" receipt "${TEST_ROOT}/receipt.ppm" >/dev/null
if python3 "${PROBE}" desktop "${TEST_ROOT}/onboarding.ppm" >/dev/null; then
    echo "onboarding fixture was misclassified as the desktop" >&2
    exit 1
fi
python3 "${PROBE}" desktop "${TEST_ROOT}/desktop.ppm" >/dev/null
if python3 "${PROBE}" onboarding "${TEST_ROOT}/desktop.ppm" >/dev/null; then
    echo "desktop fixture was misclassified as onboarding" >&2
    exit 1
fi
python3 "${PROBE}" png "${TEST_ROOT}/desktop.ppm" "${TEST_ROOT}/desktop.png" >/dev/null
python3 - "${TEST_ROOT}/desktop.png" <<'PY'
from pathlib import Path
import sys

assert Path(sys.argv[1]).read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
PY
if python3 "${PROBE}" info "${TEST_ROOT}/invalid.ppm" >/dev/null 2>&1; then
    echo "framebuffer probe accepted malformed PPM" >&2
    exit 1
fi

echo PUNAR_FRAMEBUFFER_PROBE_TEST_OK
