#!/usr/bin/env bash
# Hyprland 0.56 removed the legacy dispatcher command grammar. A legacy call
# still parses as IPC, but returns an error at runtime, so static QML/config
# checks do not catch it. Every dispatcher Punar sends must be an explicit
# hl.dsp Lua expression, wherever it is sent from:
#   - QML: Hyprland.dispatch only inside HyprlandActions, and any
#     ["hyprctl", "dispatch", ...] process argv (the greeter's exit, for one);
#   - shell scripts: `hyprctl dispatch "hl.dsp.…"`;
#   - Rust: punarctl reaches the request socket itself (crates/punarctl/src/
#     hypr.rs), and the GUI routes through punarctl, so a literal handed to
#     hypr::dispatch must be hl.dsp too.
# This gate is intentionally allow-list shaped.
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

search_qml_argv_calls() {
    grep -RInE --include='*.qml' \
        '"(/usr/bin/)?hyprctl",[[:space:]]*"dispatch"' shell/punar-shell || true
}

search_rust_calls() {
    grep -RInE --include='*.rs' '(^|[^A-Za-z0-9_])dispatch\(' crates/punarctl/src \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|pub fn dispatch\()' || true
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

qml_argv_calls="$(search_qml_argv_calls)"
qml_argv_bad="$(printf '%s\n' "${qml_argv_calls}" \
    | grep -vE '"(/usr/bin/)?hyprctl",[[:space:]]*"dispatch",[[:space:]]*"hl\.dsp\.' \
    | grep -v '^$' || true)"
if [ -n "${qml_argv_bad}" ]; then
    echo "error: a QML process runs hyprctl dispatch without an explicit hl.dsp Lua expression:" >&2
    printf '%s\n' "${qml_argv_bad}" >&2
    failed=1
fi

rust_calls="$(search_rust_calls)"
rust_bad="$(printf '%s\n' "${rust_calls}" \
    | grep -E 'dispatch\("' \
    | grep -vE 'dispatch\("hl\.dsp\.' || true)"
if [ -n "${rust_bad}" ]; then
    echo "error: punarctl dispatches a literal that is not an hl.dsp Lua expression:" >&2
    printf '%s\n' "${rust_bad}" >&2
    failed=1
fi
# Expressions punarctl formats before dispatching must start as hl.dsp too.
rust_format_bad="$(grep -RInE --include='*.rs' -A1 'hypr::dispatch\(&format!\($' crates/punarctl/src \
    | grep -E '^[^:]+-[0-9]+-[[:space:]]*r?"' \
    | grep -vE '^[^:]+-[0-9]+-[[:space:]]*r?"hl\.dsp\.' || true)"
if [ -n "${rust_format_bad}" ]; then
    echo "error: punarctl formats a dispatcher that is not an hl.dsp Lua expression:" >&2
    printf '%s\n' "${rust_format_bad}" >&2
    failed=1
fi

if [ "${failed}" -ne 0 ]; then
    exit 1
fi

count() { printf '%s\n' "$1" | grep -c . || true; }
bridge_n="$(( $(count "${qml_calls}") + $(count "${rust_calls}") ))"
if [ "${bridge_n}" -eq 0 ] || [ -z "${script_calls}" ]; then
    echo "error: dispatcher gate is vacuous (expected GUI-side calls in QML or punarctl, and shell calls)" >&2
    exit 1
fi

printf 'Hyprland dispatcher contract clean (%s QML bridge, %s QML argv, %s punarctl, %s shell calls)\n' \
    "$(count "${qml_calls}")" "$(count "${qml_argv_calls}")" \
    "$(count "${rust_calls}")" "$(count "${script_calls}")"
