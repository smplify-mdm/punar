#!/bin/sh
# ────────────────────────────────────────────────────────────────────────────
# PUNAR · LAYOUT PRESETS — spec §13.5, decisions in
# docs/development/milestone-2.md §4 (followed verbatim).
#
# Install path:   /usr/lib/punar/punar-layout.sh   (staged by the image
#                 build from os/modules/desktop/hypr/punar-layout.sh — the
#                 source of truth, like the .conf files beside it).
#
# Usage:          punar-layout.sh <balanced|columns|rows|focus|stack|next|prev|restore>
#
# ONE `hyprctl --batch` of `keyword` commands per invocation — every preset
# sets general:layout plus all of its algorithm keys, so applying a preset
# is deterministic (independent of the previous preset) and idempotent.
# `general:layout` live-refreshes (REFRESH_LAYOUTS, verified milestone-2.md
# §1.3), so windows re-tile immediately.
#
# Consumers: the compositor binds (SUPER+comma/period → prev/next), the
# command center (exec, by preset name), session start (exec-once restore),
# CI (m2-exercise.sh). Presets are GLOBAL in M2; grid is not shipped
# (0.56.2 has no native grid algorithm — milestone-2.md §2).
#
# State:
#   cache  ${XDG_RUNTIME_DIR:-/run/user/$uid}/punar/layout-preset — one
#          word, written after every successful apply; read by next/prev
#          and by the shell's bar chip (no compositor query needed).
#   restore reads layoutPreset from ~/.local/state/punar/workspaces.json
#          (written by punar-shell only — milestone-2.md §6) via jq
#          (in the image package set); missing/invalid → balanced.
#
# Budgets: one-shot process, no daemon, no polling (PERFORMANCE_BUDGETS).
# POSIX sh; shellcheck-clean (koalaman/shellcheck v0.11.0).
# ────────────────────────────────────────────────────────────────────────────
set -eu

RUN_DIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/punar"
CACHE="${RUN_DIR}/layout-preset"
STATE_FILE="${XDG_STATE_HOME:-${HOME}/.local/state}/punar/workspaces.json"

usage() {
    echo "usage: punar-layout.sh <balanced|columns|rows|focus|stack|next|prev|restore>" >&2
    exit 2
}

is_preset() {
    case "$1" in
        balanced|columns|rows|focus|stack) return 0 ;;
        *) return 1 ;;
    esac
}

# Preset → keyword batch (mapping fixed by milestone-2.md §4; all keywords
# verified against hyprland 0.56.2-1). Semicolon-joined for `hyprctl
# --batch` ([[BATCH]] handler, verified §1.3).
batch_for() {
    case "$1" in
        balanced)
            echo "keyword general:layout dwindle; keyword dwindle:default_split_ratio 1.0; keyword dwindle:preserve_split 1" ;;
        columns)
            echo "keyword general:layout scrolling; keyword scrolling:column_width 0.5; keyword scrolling:direction right; keyword scrolling:fullscreen_on_one_column 1" ;;
        rows)
            echo "keyword general:layout master; keyword master:orientation top; keyword master:mfact 0.5" ;;
        focus)
            echo "keyword general:layout master; keyword master:orientation left; keyword master:mfact 0.72" ;;
        stack)
            echo "keyword general:layout monocle" ;;
        *)
            return 1 ;;
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
    batch="$(batch_for "${preset}")" || usage
    hyprctl --batch "${batch}" >/dev/null
    mkdir -p "${RUN_DIR}"
    printf '%s\n' "${preset}" >"${CACHE}"
}

restore() {
    preset=balanced
    if [ -r "${STATE_FILE}" ] && command -v jq >/dev/null 2>&1; then
        saved="$(jq -r '.layoutPreset // empty' "${STATE_FILE}" 2>/dev/null || true)"
        if is_preset "${saved}"; then
            preset="${saved}"
        fi
    fi
    apply "${preset}"
}

case "${1-}" in
    balanced|columns|rows|focus|stack) apply "$1" ;;
    next) apply "$(next_of "$(current_preset)")" ;;
    prev) apply "$(prev_of "$(current_preset)")" ;;
    restore) restore ;;
    *) usage ;;
esac
