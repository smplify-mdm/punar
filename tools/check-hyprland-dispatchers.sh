#!/usr/bin/env bash
# Hyprland 0.56 removed the legacy dispatcher command grammar. A legacy call
# still parses as IPC, but returns an error at runtime, so static QML/config
# checks do not catch it. Product QML must route dynamic workspace values
# through HyprlandActions; shell checks may call only an explicit hl.dsp Lua
# expression. This gate is intentionally allow-list shaped.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

failed=0

search_qml_calls() {
    if command -v rg >/dev/null 2>&1; then
        rg -n '^[[:space:]]*Hyprland\.dispatch\(' shell/punar-shell -g '*.qml'
    else
        grep -RInE --include='*.qml' \
            '^[[:space:]]*Hyprland\.dispatch\(' shell/punar-shell
    fi
}

search_script_calls() {
    if command -v rg >/dev/null 2>&1; then
        rg -n \
            '^[[:space:]]*(if[[:space:]]+)?(exec[[:space:]]+)?hyprctl[[:space:]]+dispatch' \
            os/modules/desktop/hypr \
            os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar \
            -g '*.sh'
    else
        grep -RInE --include='*.sh' \
            '^[[:space:]]*(if[[:space:]]+)?(exec[[:space:]]+)?hyprctl[[:space:]]+dispatch' \
            os/modules/desktop/hypr \
            os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar
    fi
}

exclude_matches() {
    local pattern="$1"
    if command -v rg >/dev/null 2>&1; then
        rg -v "${pattern}"
    else
        grep -Ev "${pattern}"
    fi
}

qml_calls="$(search_qml_calls || true)"
qml_bad="$(printf '%s\n' "${qml_calls}" \
    | exclude_matches '^shell/punar-shell/Services/HyprlandActions\.qml:.*Hyprland\.dispatch\(("hl\.dsp\.|expression \+)' \
    || true)"
if [ -n "${qml_bad}" ]; then
    echo "error: direct or legacy Hyprland.dispatch call outside HyprlandActions:" >&2
    printf '%s\n' "${qml_bad}" >&2
    failed=1
fi

script_calls="$(search_script_calls || true)"
script_bad="$(printf '%s\n' "${script_calls}" \
    | exclude_matches 'hyprctl[[:space:]]+dispatch[[:space:]]+"hl\.dsp\.' \
    || true)"
if [ -n "${script_bad}" ]; then
    echo "error: hyprctl dispatch must receive an explicit hl.dsp Lua expression:" >&2
    printf '%s\n' "${script_bad}" >&2
    failed=1
fi

if [ "${failed}" -ne 0 ]; then
    exit 1
fi

if [ -z "${qml_calls}" ] || [ -z "${script_calls}" ]; then
    echo "error: dispatcher gate is vacuous (expected both QML and shell calls)" >&2
    exit 1
fi

printf 'Hyprland dispatcher contract clean (%s QML bridge calls, %s shell calls)\n' \
    "$(printf '%s\n' "${qml_calls}" | wc -l | tr -d ' ')" \
    "$(printf '%s\n' "${script_calls}" | wc -l | tr -d ' ')"
