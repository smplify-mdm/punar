#!/usr/bin/env bash
# Fast source-tree contract for M11's browser entry point and generated
# compositor rule. Keep failures here ahead of the ~50 minute VM exercise.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WEBAPPS="${REPO_ROOT}/crates/punarctl/src/webapps.rs"
DAEMON_WEBAPPS="${REPO_ROOT}/crates/punard/src/webapps.rs"
SESSION="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/session.sh"
HYPR_CONFIG="${REPO_ROOT}/os/modules/desktop/hypr/hyprland.lua"
M11_CHECK="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/m11-check.sh"
ICON_B64="${REPO_ROOT}/browser/integration/fixtures/notes/icon.png.b64"

contains() {
    local file="$1"
    local literal="$2"
    if ! grep -Fq -- "${literal}" "${file}"; then
        printf 'FAIL %s does not contain %s\n' "${file}" "${literal}" >&2
        exit 1
    fi
}

refuses() {
    local file="$1"
    local literal="$2"
    if grep -Fq -- "${literal}" "${file}"; then
        printf 'FAIL %s still contains %s\n' "${file}" "${literal}" >&2
        exit 1
    fi
}

# Punar is Wayland-only. The less-specific hint chose X11 from the system
# exercise even though the Wayland socket and environment were both valid.
contains "${WEBAPPS}" '"--ozone-platform=wayland"'
refuses "${WEBAPPS}" '"--ozone-platform-hint=auto"'

# Hyprland 0.56's Lua provider rejects `keyword source`. The root-derived,
# user-owned fragment must itself be Lua and changes must reload a clean rule
# set so an uninstalled app cannot retain an old live rule.
contains "${SESSION}" 'punar-webapps.lua'
refuses "${SESSION}" 'punar-webapps.conf'
contains "${HYPR_CONFIG}" 'dofile(webAppRules)'
refuses "${HYPR_CONFIG}" 'hyprctl keyword'
contains "${WEBAPPS}" 'join("hypr/punar-webapps.lua")'
contains "${WEBAPPS}" '.arg("reload")'
refuses "${WEBAPPS}" '.args(["keyword", "source"])'
contains "${DAEMON_WEBAPPS}" 'hl.window_rule({{ name = \"punar-webapp-{}\"'

# The compiled CLI also contains the independent native-vendor sandbox
# vocabulary. Scanning arbitrary binary strings is not a browser invariant;
# the dry-run and live Chromium argv checks below this source gate are.
refuses "${M11_CHECK}" 'for path in /usr/bin/punarctl'
contains "${M11_CHECK}" "'.descriptor.current_state == \"drifted\"'"

# Decode and validate every PNG chunk here. `file(1)` accepts images whose
# stored CRC is corrupt, which made the strict in-guest manifest fail only
# after a complete image build and boot.
python3 - "${ICON_B64}" <<'PY'
import base64
import binascii
import struct
import sys

encoded = open(sys.argv[1], "rb").read().strip()
try:
    image = base64.b64decode(encoded, validate=True)
except binascii.Error as error:
    raise SystemExit(f"FAIL fixture icon is not strict base64: {error}")

if image[:8] != b"\x89PNG\r\n\x1a\n":
    raise SystemExit("FAIL fixture icon has no PNG signature")

offset = 8
chunks = []
while offset < len(image):
    if offset + 12 > len(image):
        raise SystemExit("FAIL fixture icon has a truncated PNG chunk")
    size = struct.unpack(">I", image[offset : offset + 4])[0]
    end = offset + 12 + size
    if end > len(image):
        raise SystemExit("FAIL fixture icon chunk exceeds the file")
    kind = image[offset + 4 : offset + 8]
    payload = image[offset + 8 : offset + 8 + size]
    expected = struct.unpack(">I", image[offset + 8 + size : end])[0]
    actual = binascii.crc32(kind + payload) & 0xFFFFFFFF
    if actual != expected:
        raise SystemExit(
            f"FAIL fixture icon {kind.decode('ascii', 'replace')} CRC "
            f"is {expected:08x}, expected {actual:08x}"
        )
    chunks.append(kind)
    offset = end

if offset != len(image) or chunks[:1] != [b"IHDR"] or chunks[-1:] != [b"IEND"]:
    raise SystemExit("FAIL fixture icon has an invalid PNG chunk envelope")
print("ok   browser fixture is strict base64 with valid PNG chunk checksums")
PY

printf 'Browser integration source contract clean\n'
