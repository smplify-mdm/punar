#!/usr/bin/env bash
# Keep the native-vendor OAuth broker narrow and present on both image arches.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BRIDGE="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/vendor-sandbox-bin/xdg-open"
X86_PROFILE="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.conf"
ARM_PROFILE="${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.conf"
HYPR_LUA="${REPO_ROOT}/os/modules/desktop/hypr/hyprland.lua"
HYPR_LEGACY="${REPO_ROOT}/os/modules/desktop/hypr/hyprland.conf"
SESSION="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/session.sh"
USER_ENVIRONMENT="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/environment.d/60-punar-applications.conf"
PUNARCTL="${REPO_ROOT}/crates/punarctl/src/main.rs"

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
contains "${X86_PROFILE}" '         xdg-desktop-portal-gtk'
contains "${ARM_PROFILE}" '         xdg-desktop-portal-gtk'
contains "${BRIDGE}" 'org.freedesktop.portal.Desktop'
contains "${BRIDGE}" 'org.freedesktop.portal.OpenURI'
contains "${BRIDGE}" 'https://*|http://*'
contains "${HYPR_LUA}" 'XDG_CONFIG_DIRS XDG_DATA_DIRS'
contains "${HYPR_LEGACY}" 'XDG_CONFIG_DIRS XDG_DATA_DIRS'
contains "${SESSION}" 'dbus-update-activation-environment --systemd XDG_CONFIG_DIRS XDG_DATA_DIRS'
contains "${USER_ENVIRONMENT}" 'XDG_CONFIG_DIRS=/etc/xdg:/var/lib/punar-applications/config'
contains "${PUNARCTL}" '"vendor-session"'
contains "${PUNARCTL}" 'VENDOR_SESSION_SOCKET'
contains "${PUNARCTL}" 'std::fs::Permissions::from_mode(0o600)'
contains "${PUNARCTL}" 'validate_callback_schemes(schemes, &uris)'
contains "${PUNARCTL}" 'relays.push(spawn_vendor_instance(executable, &uri_refs)?)'

# These inputs must be rejected before any D-Bus connection is attempted.
for uri in 'claude://login/code' 'file:///etc/passwd' '/home/user/document'; do
    set +e
    "${BRIDGE}" "${uri}"
    status=$?
    set -e
    [ "${status}" -eq 64 ] || fail "unsafe URI returned ${status}: ${uri}"
done

echo 'vendor-sandbox-contract-test: PASS'
