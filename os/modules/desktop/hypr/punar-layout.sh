#!/bin/sh
# ────────────────────────────────────────────────────────────────────────────
# PUNAR · LAYOUT PRESETS — spec §13.5, decisions in
# docs/development/milestone-2.md §4 (followed verbatim), plus per-workspace
# presets (SMP-1405 WP-02).
#
# Install path:   /usr/lib/punar/punar-layout.sh   (staged by the image
#                 build from os/modules/desktop/hypr/punar-layout.sh — the
#                 source of truth, like the .conf files beside it).
#
# Usage:          punar-layout.sh <balanced|columns|rows|focus|stack|next|prev|restore>
#                 punar-layout.sh --workspace <N|active> <balanced|columns|rows|focus|stack|next|prev|default>
#
# ONE `hyprctl eval` of native Lua per invocation.
#   Global: one `hl.config` table — every preset sets general.layout plus
#   all of its algorithm keys, so applying a preset is deterministic
#   (independent of the previous preset) and idempotent. Hyprland 0.55
#   removed live `hyprctl keyword general:layout` updates; eval is the
#   supported Lua configuration path and re-tiles windows immediately.
#   Per workspace: one `hl.workspace_rule` naming the preset's algorithm
#   (and the master orientation, as `layout_opts`), which outranks the
#   global preset on that workspace only. `default` gives a workspace back
#   to the global preset.
#
# Consumers: the compositor binds (PUNAR+comma/period → the active
# workspace's prev/next), the command center (exec, by preset name), session
# start and every config reload (restore), CI (m2-exercise.sh), and
# `punarctl layout`.
#
# State:
#   cache  ${XDG_RUNTIME_DIR:-/run/user/$uid}/punar/layout-preset — one
#          word, the GLOBAL preset, written after every successful global
#          apply; read by next/prev and by the shell's workspace store.
#   store  ${XDG_STATE_HOME:-~/.local/state}/punar/workspace-layouts.json —
#          {"version":1,"workspaces":{"3":"columns"}}, written by THIS
#          script only (the shell's workspaces.json keeps one writer), with
#          jq, atomically. Every id and preset is validated when read, so a
#          hand edit can name nothing but a workspace number and one of the
#          five presets.
#   restore reads layoutPreset from ~/.local/state/punar/workspaces.json
#          (written by punar-shell only — milestone-2.md §6) via jq
#          (in the image package set); missing/invalid → balanced. Then it
#          re-applies every stored workspace preset.
#
# Budgets: one-shot process, no daemon, no polling (PERFORMANCE_BUDGETS).
# POSIX sh; shellcheck-clean (koalaman/shellcheck v0.11.0).
# ────────────────────────────────────────────────────────────────────────────
set -eu

RUN_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/punar"
CACHE="${RUN_DIR}/layout-preset"
STATE_DIR="${XDG_STATE_HOME:-${HOME}/.local/state}/punar"
STATE_FILE="${STATE_DIR}/workspaces.json"
WS_STORE="${STATE_DIR}/workspace-layouts.json"

usage() {
    echo "usage: punar-layout.sh <balanced|columns|rows|focus|stack|next|prev|restore>" >&2
    echo "       punar-layout.sh --workspace <N|active> <balanced|columns|rows|focus|stack|next|prev|default>" >&2
    exit 2
}

is_preset() {
    case "$1" in
        balanced|columns|rows|focus|stack) return 0 ;;
        *) return 1 ;;
    esac
}

# A workspace number: 1-9999, no leading zero. Special workspaces have their
# own names and never take a preset.
is_workspace_id() {
    case "$1" in
        ''|0*|*[!0-9]*) return 1 ;;
    esac
    [ "${#1}" -le 4 ]
}

# Preset → native Lua config (mapping fixed by milestone-2.md §4 and verified
# against the pinned Hyprland 0.56.2-1 runtime).
config_for() {
    case "$1" in
        balanced)
            echo 'hl.config({ general = { layout = "dwindle" }, dwindle = { default_split_ratio = 1.0, preserve_split = true } })' ;;
        columns)
            echo 'hl.config({ general = { layout = "scrolling" }, scrolling = { column_width = 0.5, direction = "right", fullscreen_on_one_column = true } })' ;;
        rows)
            echo 'hl.config({ general = { layout = "master" }, master = { orientation = "top", mfact = 0.5 } })' ;;
        focus)
            echo 'hl.config({ general = { layout = "master" }, master = { orientation = "left", mfact = 0.72 } })' ;;
        stack)
            echo 'hl.config({ general = { layout = "monocle" } })' ;;
        *)
            return 1 ;;
    esac
}

# Preset → one workspace's rule. `layout_opts` carries the master
# orientation (Hyprland 0.56's workspace-rule field); the ratio and the
# scrolling column width stay the session's, since the workspace rule has no
# field for them.
rule_for() {
    ws="$1"
    case "$2" in
        balanced) printf 'hl.workspace_rule({ workspace = "%s", layout = "dwindle" })' "${ws}" ;;
        columns)  printf 'hl.workspace_rule({ workspace = "%s", layout = "scrolling" })' "${ws}" ;;
        rows)     printf 'hl.workspace_rule({ workspace = "%s", layout = "master", layout_opts = { orientation = "top" } })' "${ws}" ;;
        focus)    printf 'hl.workspace_rule({ workspace = "%s", layout = "master", layout_opts = { orientation = "left" } })' "${ws}" ;;
        stack)    printf 'hl.workspace_rule({ workspace = "%s", layout = "monocle" })' "${ws}" ;;
        *) return 1 ;;
    esac
}

# Cycle order (milestone-2.md §4): balanced → columns → rows → focus →
# stack → (wrap). Explicit tables — no list iteration, no arithmetic.
next_of() {
    case "$1" in
        balanced) echo columns ;;
        columns)  echo rows ;;
        rows)     echo focus ;;
        focus)    echo stack ;;
        stack)    echo balanced ;;
    esac
}

prev_of() {
    case "$1" in
        balanced) echo stack ;;
        columns)  echo balanced ;;
        rows)     echo columns ;;
        focus)    echo rows ;;
        stack)    echo focus ;;
    esac
}

# The cached preset if valid, else balanced (the M1 default feel — also
# the honest answer right after boot, before any preset was chosen).
current_preset() {
    cur="$(cat "${CACHE}" 2>/dev/null || true)"
    if is_preset "${cur}"; then
        echo "${cur}"
    else
        echo balanced
    fi
}

apply() {
    preset="$1"
    config="$(config_for "${preset}")" || usage
    hyprctl eval "${config}" >/dev/null
    mkdir -p "${RUN_DIR}"
    printf '%s\n' "${preset}" >"${CACHE}"
}

# ---- per workspace ---------------------------------------------------------

# The stored preset of one workspace, or nothing.
workspace_preset() {
    [ -r "${WS_STORE}" ] && command -v jq >/dev/null 2>&1 || return 0
    saved="$(jq -r --arg ws "$1" '.workspaces[$ws] // empty' "${WS_STORE}" 2>/dev/null || true)"
    if is_preset "${saved}"; then
        echo "${saved}"
    fi
}

# Record (or with an empty preset, forget) one workspace's preset. Atomic:
# jq writes a temporary beside the store and mv replaces it.
store_workspace() {
    ws="$1"
    preset="$2"
    command -v jq >/dev/null 2>&1 || return 0
    mkdir -p "${STATE_DIR}"
    current='{"version":1,"workspaces":{}}'
    if [ -r "${WS_STORE}" ] && jq -e '.version == 1 and (.workspaces | type) == "object"' "${WS_STORE}" >/dev/null 2>&1; then
        current="$(cat "${WS_STORE}")"
    fi
    tmp="${WS_STORE}.$$"
    if [ -n "${preset}" ]; then
        printf '%s' "${current}" \
            | jq --arg ws "${ws}" --arg preset "${preset}" '.workspaces[$ws] = $preset' >"${tmp}"
    else
        printf '%s' "${current}" | jq --arg ws "${ws}" 'del(.workspaces[$ws])' >"${tmp}"
    fi
    mv -f "${tmp}" "${WS_STORE}"
}

# `active` → the focused workspace's number, from the compositor itself.
resolve_workspace() {
    if [ "$1" = active ]; then
        hyprctl -j activeworkspace 2>/dev/null | jq -r '.id // empty' 2>/dev/null || true
    else
        echo "$1"
    fi
}

apply_workspace() {
    ws="$1"
    verb="$2"
    current="$(workspace_preset "${ws}")"
    [ -n "${current}" ] || current="$(current_preset)"
    case "${verb}" in
        next) preset="$(next_of "${current}")" ;;
        prev) preset="$(prev_of "${current}")" ;;
        default) preset="" ;;
        *) preset="${verb}" ;;
    esac
    if [ -z "${preset}" ]; then
        # Back to the session's preset: a rule naming the global algorithm
        # (a live rule cannot be deleted), then forget the workspace.
        rule="$(rule_for "${ws}" "$(current_preset)")"
        hyprctl eval "${rule}" >/dev/null
        store_workspace "${ws}" ""
        return 0
    fi
    is_preset "${preset}" || usage
    rule="$(rule_for "${ws}" "${preset}")"
    hyprctl eval "${rule}" >/dev/null
    store_workspace "${ws}" "${preset}"
}

# Every stored workspace preset as one line of Lua statements ("" when
# there is none): one eval, one line, whatever hyprctl does with newlines.
stored_rules() {
    [ -r "${WS_STORE}" ] && command -v jq >/dev/null 2>&1 || return 0
    jq -r '.workspaces // {} | to_entries[] | "\(.key) \(.value)"' "${WS_STORE}" 2>/dev/null \
        | while read -r ws preset; do
            if is_workspace_id "${ws}" && is_preset "${preset}"; then
                rule_for "${ws}" "${preset}"
                printf '; '
            fi
        done
}

restore() {
    preset=balanced
    if [ -r "${STATE_FILE}" ] && command -v jq >/dev/null 2>&1; then
        saved="$(jq -r '.layoutPreset // empty' "${STATE_FILE}" 2>/dev/null || true)"
        if is_preset "${saved}"; then
            preset="${saved}"
        fi
    fi
    # The runtime cache outranks the store after a reload: it is the preset
    # this session chose most recently.
    cached="$(cat "${CACHE}" 2>/dev/null || true)"
    if is_preset "${cached}"; then
        preset="${cached}"
    fi
    apply "${preset}"
    rules="$(stored_rules)"
    if [ -n "${rules}" ]; then
        hyprctl eval "${rules}" >/dev/null
    fi
}

if [ "${1-}" = "--workspace" ]; then
    [ "$#" -eq 3 ] || usage
    target="$(resolve_workspace "$2")"
    is_workspace_id "${target}" || usage
    case "$3" in
        balanced|columns|rows|focus|stack|next|prev|default) apply_workspace "${target}" "$3" ;;
        *) usage ;;
    esac
    exit 0
fi

case "${1-}" in
    balanced|columns|rows|focus|stack) apply "$1" ;;
    next) apply "$(next_of "$(current_preset)")" ;;
    prev) apply "$(prev_of "$(current_preset)")" ;;
    restore) restore ;;
    *) usage ;;
esac
