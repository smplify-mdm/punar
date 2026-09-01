#!/usr/bin/env bash
# Keep the native-vendor OAuth broker narrow and present on both image arches.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/vendor-sandbox-bin/xdg-open"
X86_PROFILE="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.conf"
ARM_PROFILE="${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.conf"

fail() {
    echo "vendor-sandbox-contract-test: FAIL: $*" >&2
    exit 1
}

contains() {
    local file=$1 text=$2
    grep -Fq -- "${text}" "${file}" || fail "${file#"${REPO_ROOT}/"} is missing: ${text}"
}

[ -x "${BRIDGE}" ] || fail "the portal bridge is not executable"
contains "${X86_PROFILE}" '         xdg-dbus-proxy'
contains "${ARM_PROFILE}" '         xdg-dbus-proxy'
contains "${BRIDGE}" 'org.freedesktop.portal.Desktop'
contains "${BRIDGE}" 'org.freedesktop.portal.OpenURI'
contains "${BRIDGE}" 'https://*|http://*'

# These inputs must be rejected before any D-Bus connection is attempted.
for uri in 'claude://login/code' 'file:///etc/passwd' '/home/user/document'; do
    set +e
    "${BRIDGE}" "${uri}"
    status=$?
    set -e
    [ "${status}" -eq 64 ] || fail "unsafe URI returned ${status}: ${uri}"
done

echo 'vendor-sandbox-contract-test: PASS'
