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
# `hyprctl -j activeworkspace` is a read: answer workspace 3. Everything else
# is logged (the last call wins, which is what each assertion reads).
if [ "$1" = -j ]; then
    printf '{"id":3,"name":"3"}\n'
    exit 0
fi
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

# --- per-workspace presets (SMP-1405 WP-02) ----------------------------------
STORE="${XDG_STATE_HOME}/punar/workspace-layouts.json"

assert_rule() {
    expected="$1"
    shift
    rm -f "${PUNAR_TEST_HYPRCTL_LOG}"
    "${HELPER}" "$@"
    actual="$(cat "${PUNAR_TEST_HYPRCTL_LOG}")"
    [ "${actual}" = "eval ${expected}" ] || {
        printf 'FAIL %s: expected eval %s, got %s\n' "$*" "${expected}" "${actual}" >&2
        exit 1
    }
}

store_value() { jq -r --arg ws "$1" '.workspaces[$ws] // "none"' "${STORE}"; }

"${HELPER}" balanced
assert_rule 'hl.workspace_rule({ workspace = "3", layout = "scrolling" })' --workspace 3 columns
[ "$(store_value 3)" = columns ] || { echo "FAIL workspace 3 was not stored as columns" >&2; exit 1; }
[ "$(cat "${XDG_RUNTIME_DIR}/punar/layout-preset")" = balanced ] || {
    echo "FAIL a workspace preset moved the session's preset" >&2; exit 1; }
printf 'ok   a workspace takes its own preset as one hl.workspace_rule, stored\n'

assert_rule 'hl.workspace_rule({ workspace = "3", layout = "master", layout_opts = { orientation = "top" } })' \
    --workspace active next
[ "$(store_value 3)" = rows ] || { echo "FAIL active next did not cycle workspace 3 to rows" >&2; exit 1; }
printf 'ok   PUNAR+period cycles the focused workspace from its own preset\n'

assert_rule 'hl.workspace_rule({ workspace = "5", layout = "monocle" })' --workspace 5 prev
[ "$(store_value 5)" = stack ] || { echo "FAIL workspace 5 did not start from the session preset" >&2; exit 1; }
printf 'ok   a workspace without its own preset cycles from the session preset\n'

assert_rule 'hl.workspace_rule({ workspace = "3", layout = "dwindle" })' --workspace 3 default
[ "$(store_value 3)" = none ] || { echo "FAIL default did not forget workspace 3" >&2; exit 1; }
[ "$(store_value 5)" = stack ] || { echo "FAIL default forgot another workspace" >&2; exit 1; }
printf 'ok   default hands a workspace back to the session preset and forgets it\n'

for bad in "--workspace 0 columns" "--workspace x columns" "--workspace 3 restore" \
            "--workspace 3" "--workspace 12345 columns" "--workspace -3 columns"; do
    # shellcheck disable=SC2086 # the words are the argv under test
    if "${HELPER}" ${bad} 2>/dev/null; then
        printf 'FAIL punar-layout.sh %s was accepted\n' "${bad}" >&2
        exit 1
    fi
done
printf 'ok   only a workspace number or active, and only a preset, are accepted\n'

# A hand-edited store names nothing but numbers and presets, and restore puts
# every valid one back in one eval after the session preset.
printf '%s\n' '{"version":1,"workspaces":{"3":"stack","5":"rows","x":"stack","7":"evil"}}' > "${STORE}"
rm -f "${PUNAR_TEST_HYPRCTL_LOG}"
"${HELPER}" restore
actual="$(cat "${PUNAR_TEST_HYPRCTL_LOG}")"
expected='eval hl.workspace_rule({ workspace = "3", layout = "monocle" }); hl.workspace_rule({ workspace = "5", layout = "master", layout_opts = { orientation = "top" } }); '
[ "${actual}" = "${expected}" ] || {
    printf 'FAIL restore re-applied %s\n' "${actual}" >&2
    exit 1
}
printf 'ok   restore re-applies every valid stored workspace preset, and only those\n'
