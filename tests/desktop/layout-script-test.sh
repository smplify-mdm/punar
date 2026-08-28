#!/bin/sh
# Fast contract proof for Hyprland's native Lua layout-switching path.
set -eu

REPO_ROOT="$(cd -- "$(dirname "$0")/../.." && pwd)"
HELPER="${REPO_ROOT}/os/modules/desktop/hypr/punar-layout.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/punar-layout-script-test.XXXXXX")"
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

mkdir -p "${TEST_ROOT}/bin" "${TEST_ROOT}/runtime" "${TEST_ROOT}/state"
cat > "${TEST_ROOT}/bin/hyprctl" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" > "${PUNAR_TEST_HYPRCTL_LOG}"
EOF
chmod 0755 "${TEST_ROOT}/bin/hyprctl"

PUNAR_TEST_HYPRCTL_LOG="${TEST_ROOT}/hyprctl.log"
XDG_RUNTIME_DIR="${TEST_ROOT}/runtime"
XDG_STATE_HOME="${TEST_ROOT}/state"
HOME="${TEST_ROOT}/home"
PATH="${TEST_ROOT}/bin:${PATH}"
export PUNAR_TEST_HYPRCTL_LOG XDG_RUNTIME_DIR XDG_STATE_HOME HOME PATH

assert_preset() {
    preset="$1"
    expected="$2"
    rm -f "${PUNAR_TEST_HYPRCTL_LOG}"
    "${HELPER}" "${preset}"
    actual="$(cat "${PUNAR_TEST_HYPRCTL_LOG}")"
    [ "${actual}" = "eval ${expected}" ] || {
        printf 'FAIL %s: expected native eval %s, got %s\n' \
            "${preset}" "${expected}" "${actual}" >&2
        exit 1
    }
    [ "$(cat "${XDG_RUNTIME_DIR}/punar/layout-preset")" = "${preset}" ] || {
        printf 'FAIL %s: preset cache was not updated\n' "${preset}" >&2
        exit 1
    }
    printf 'ok   %s uses native Lua eval\n' "${preset}"
}

assert_preset balanced 'hl.config({ general = { layout = "dwindle" }, dwindle = { default_split_ratio = 1.0, preserve_split = true } })'
assert_preset columns 'hl.config({ general = { layout = "scrolling" }, scrolling = { column_width = 0.5, direction = "right", fullscreen_on_one_column = true } })'
assert_preset rows 'hl.config({ general = { layout = "master" }, master = { orientation = "top", mfact = 0.5 } })'
assert_preset focus 'hl.config({ general = { layout = "master" }, master = { orientation = "left", mfact = 0.72 } })'
assert_preset stack 'hl.config({ general = { layout = "monocle" } })'

"${HELPER}" balanced
"${HELPER}" next
[ "$(cat "${XDG_RUNTIME_DIR}/punar/layout-preset")" = columns ]
"${HELPER}" prev
[ "$(cat "${XDG_RUNTIME_DIR}/punar/layout-preset")" = balanced ]
printf 'ok   next/prev preserve the preset cycle\n'
