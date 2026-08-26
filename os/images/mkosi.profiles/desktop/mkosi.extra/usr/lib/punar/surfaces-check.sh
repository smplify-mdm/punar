#!/bin/sh
# Punar desktop-surfaces in-VM exercise.
#
# WHY THIS EXISTS. The thirteen shell surfaces landed gated by qmllint (34
# files, 0 warnings) and `hyprland --config ok`. Both are STATIC: they prove
# the QML parses and the config loads, and neither proves a single surface
# opens on a running machine. A typo in an IpcHandler target, a binding loop
# that throws at show() time, a Theme token that resolves to undefined and
# renders an invisible panel — every one of those passes qmllint and fails the
# user. This script is the difference between "it builds" and "you can use it".
#
# Runs as User=punar (the punar-m2-check.service pattern) because every
# assertion here is user-session scoped: the shell's IPC socket, the Hyprland
# instance, and the browser all live in the user session, not root's.
#
# ALWAYS exits 0. The verdict is the final line of
# /run/punar/surfaces-report.txt (PUNAR_SURFACES_OK / PUNAR_SURFACES_FAIL) and
# tools/boot-test.sh hard-fails on FAIL or on a missing/truncated report — the
# m8 lesson (a check that produces no report must never pass as a warning).
#
# DELIBERATELY NOT EXERCISED, and why — spec 1.22 requires naming these rather
# than leaving a reader to assume coverage:
#   * lock -> unlock. The lock IpcHandler exposes lock() and state() only;
#     submit() is a root-level function and is NOT reachable over IPC. Locking
#     here would strand the CI session with no programmatic way out and every
#     later assertion would fail for the wrong reason. Group 8 asserts the
#     lockout RISK instead: that the PAM stack the lock screen resolves to
#     actually exists on this machine, which is the failure that would make a
#     real lock unopenable.
#   * Visual correctness. state() reports whether a surface is open, not
#     whether it is legible. Contrast is gated separately by
#     Theme/ThemeContrast.qml against the same theme bytes the image ships.
#
# Predicate functions below are invoked indirectly through `wait_for <secs>
# <fn> [args]` — shellcheck cannot see that (the m2-check.sh precedent).
# File-wide: this directive precedes the first command.
# shellcheck disable=SC2329
set -u

REPORT=/run/punar/surfaces-report.txt
FAILED=0
SHELL_CMD="qs -p /usr/share/punar/shell"

mkdir -p /run/punar
: > "${REPORT}"

note() { printf '%s\n' "$*" >> "${REPORT}"; }

check_eq() {
    if [ "$2" = "$3" ]; then
        note "ok   $1 = $3"
    else
        note "FAIL $1 (expected '$2', got '$3')"
        FAILED=1
    fi
}

wait_for() {
    wf_secs="$1"; shift; wf_i=0
    while [ "${wf_i}" -lt "${wf_secs}" ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        wf_i=$((wf_i + 1)); sleep 1
    done
    return 1
}

finish() {
    if [ "${FAILED}" -eq 0 ]; then
        note "PUNAR_SURFACES_OK"
    else
        note "PUNAR_SURFACES_FAIL"
    fi
    cat "${REPORT}"
    exit 0
}

note "# Punar desktop-surfaces exercise — $(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- session env discovery (m2-check.sh pattern) -----------------------------
XDG_RUNTIME_DIR="/run/user/$(id -u)"
export XDG_RUNTIME_DIR

HIS=""
for d in "${XDG_RUNTIME_DIR}/hypr/"*/; do
    [ -d "${d}" ] || continue
    HIS="$(basename "${d}")"; break
done
if [ -z "${HIS}" ]; then
    note "FAIL no Hyprland instance under ${XDG_RUNTIME_DIR}/hypr"
    FAILED=1; finish
fi
HYPRLAND_INSTANCE_SIGNATURE="${HIS}"
export HYPRLAND_INSTANCE_SIGNATURE

WAYLAND_DISPLAY=""
for s in "${XDG_RUNTIME_DIR}"/wayland-*; do
    case "${s}" in
        *.lock) ;;
        *) [ -e "${s}" ] && WAYLAND_DISPLAY="$(basename "${s}")" && break ;;
    esac
done
export WAYLAND_DISPLAY
note "# instance=${HIS} wayland=${WAYLAND_DISPLAY:-none} uid=$(id -u) user=$(id -un)"

# --- group 1: the shell answers at all ---------------------------------------
ipc() { ${SHELL_CMD} ipc call "$@" 2>/dev/null; }
sstate() { ipc "$1" state | tr -d '[:space:]"'; }

shell_alive() { ${SHELL_CMD} ipc call bar state >/dev/null 2>&1; }
t_open()   { [ "$(sstate "$1")" = "open" ]; }
t_closed() { [ "$(sstate "$1")" = "closed" ]; }

# Whether the compositor has an actual mapped layer-shell surface with this
# namespace. This is the EXACT signal that a surface really put a window on
# screen, and it is independent of the shell's own state(): every surface
# declares WlrLayershell.namespace ("punar-commandcenter" and so on) while its
# window is bound to `visible: root.windowVisible`, a DIFFERENT property from
# the `root.open` that state() reports. The gap between those two is real —
# the first run of this exercise photographed the command centre as an empty
# desktop while state() said "open", because grim fired after the flag flipped
# and before the compositor had mapped and painted anything.
#
# jq walks the whole document rather than assuming the output/level nesting,
# which differs by monitor count.
layer_mapped() {
    hyprctl -j layers 2>/dev/null \
        | jq -e --arg ns "$1" '[.. | objects | select(has("namespace")) | .namespace] | index($ns) != null' \
        >/dev/null 2>&1
}
layer_gone() { ! layer_mapped "$1"; }
if ! wait_for 90 shell_alive; then
    note "FAIL punar-shell IPC not answering within 90s (no surface can be tested)"
    FAILED=1; finish
fi
note "ok   punar-shell IPC answering"

# --- group 2: every unconditionally-openable surface opens AND closes --------
# The biconditional matters in both directions. Asserting only that open()
# reports "open" would pass for a surface whose state() is hardcoded; asserting
# the close leg too means the value has to actually track the surface.
# The empty-desktop baseline every per-surface capture is measured against:
# taken with nothing open, so a surface whose frame is no bigger than this one
# is visibly suspicious in the report.
BASELINE_BYTES=""
if grim /run/punar/surfaces-baseline.png 2>/dev/null; then
    BASELINE_BYTES="$(wc -c < /run/punar/surfaces-baseline.png | tr -d ' ')"
    note "info empty-desktop baseline captured (${BASELINE_BYTES} bytes)"
else
    note "info empty-desktop baseline unavailable (grim failed)"
fi

for t in commandcenter systemcontrol notifications shortcuts aipanel overview approval; do
    before="$(sstate "${t}")"
    check_eq "${t}.state before open" "closed" "${before}"

    ipc "${t}" open >/dev/null 2>&1
    if wait_for 15 t_open "${t}"; then
        note "ok   ${t}.open -> open"
    else
        note "FAIL ${t}.open did not reach state=open within 15s (got '$(sstate "${t}")')"
        FAILED=1
    fi

    # The surface must have a MAPPED WINDOW, not merely a flag set. state()
    # reads root.open; the window is bound to root.windowVisible. Asserting the
    # compositor's own layer list closes that gap.
    if wait_for 15 layer_mapped "punar-${t}"; then
        note "ok   ${t} mapped a layer-shell surface (punar-${t})"
    else
        note "FAIL ${t} reports open but the compositor has no punar-${t} layer — the flag is set and nothing is on screen"
        FAILED=1
    fi

    # A surface that reports open and draws nothing looks identical from here,
    # and state() cannot tell the difference. grim is the cheapest evidence
    # that pixels exist, and it gives a human something to look at without
    # booting anything (the punar-m2.png precedent). A failed capture is not
    # an assertion failure — grim has its own reasons to fail and the surface
    # contract is what is being tested — but the file's SIZE is recorded, so
    # a suspiciously tiny frame is visible in the report.
    if grim "/run/punar/surfaces-${t}.png" 2>/dev/null; then
        shot_bytes="$(wc -c < "/run/punar/surfaces-${t}.png" | tr -d ' ')"
        # Compared against the empty-desktop baseline captured before this
        # loop. A frame no larger than an empty desktop is the signature of a
        # surface that mapped a window and painted nothing into it — stated as
        # a size relation because the image ships no image tooling to diff
        # pixels with, and labelled INFO because PNG size is a proxy, not
        # proof. The layer assertion above is the load-bearing one.
        if [ -n "${BASELINE_BYTES}" ] && [ "${shot_bytes}" -le "${BASELINE_BYTES}" ]; then
            note "info ${t} captured ${shot_bytes} bytes — NOT larger than the empty-desktop baseline (${BASELINE_BYTES}); the frame may be blank"
        else
            note "info ${t} captured ${shot_bytes} bytes (baseline ${BASELINE_BYTES:-unknown})"
        fi
    else
        note "info ${t} screenshot unavailable (grim failed; not an assertion)"
    fi

    ipc "${t}" close >/dev/null 2>&1
    if wait_for 15 t_closed "${t}"; then
        note "ok   ${t}.close -> closed"
    else
        note "FAIL ${t}.close did not reach state=closed within 15s (got '$(sstate "${t}")')"
        FAILED=1
    fi

    # And the window must actually go away. A surface that reports closed while
    # its layer stays mapped is still taking the screen — and, for the overlays
    # that request WlrKeyboardFocus.Exclusive, still holding the keyboard.
    if wait_for 15 layer_gone "punar-${t}"; then
        note "ok   ${t} unmapped its layer-shell surface"
    else
        note "FAIL ${t} reports closed but punar-${t} is still mapped"
        FAILED=1
    fi
done

# --- group 3: the alert stack refuses to render an empty shelf ---------------
# alerts.open() hides itself when there are zero cards, by design. That is the
# invariant, not an omission: an alert surface that opened empty would be a
# card shelf claiming attention with nothing on it. Asserted only when the
# stack IS empty, so this never fights M10's fixtures.
acards="$(ipc alerts state | tr -d '[:space:]"')"
if [ "${acards}" = "closed" ]; then
    ipc alerts open >/dev/null 2>&1
    sleep 2
    check_eq "alerts.open with an empty stack stays closed" "closed" "$(sstate alerts)"
else
    note "ok   alerts stack non-empty (state='${acards}') — empty-shelf invariant not applicable"
fi

# --- group 4: the theme system resolved REAL documents, not the fallback -----
# theme.status and theme.list return JSON. Asserting "the response is
# non-empty" — or counting whitespace-split tokens — passes for literally any
# output including an error object, which is the stale-placeholder class this
# repo already paid for once (docs/development/checks-conventions.md). Both
# are parsed with jq and asserted on their meaning.
# Same asynchrony caution as the catalog below: the palette is loaded from a
# file, so a status read taken the instant the shell answers can legitimately
# still show the fallback. Poll for the settled value and fail only if it never
# resolves — which is the actual defect, and is what the wait bounds.
theme_resolved() {
    ipc theme status > /run/punar/surfaces-theme.json 2>/dev/null
    jq -e '(.resolved // "") != "" and (.resolved != "built-in fallback palette")' \
        /run/punar/surfaces-theme.json >/dev/null 2>&1
}
wait_for 30 theme_resolved || true
if jq -e . /run/punar/surfaces-theme.json >/dev/null 2>&1; then
    note "ok   theme.status returns parseable JSON"

    active="$(jq -r '.active // ""' /run/punar/surfaces-theme.json)"
    if [ -n "${active}" ]; then
        note "ok   theme.status names an active theme ('${active}')"
    else
        note "FAIL theme.status reports no active theme"
        FAILED=1
    fi

    # THE assertion in this group. Theme.qml falls back to a built-in paper
    # palette when it resolves no theme document, and it does so SILENTLY —
    # the desktop looks themed while no theme is selectable and every shipped
    # theme is unreachable. That is the exact failure the staging step in
    # container-build.sh exists to prevent, so it is asserted on the running
    # machine rather than trusted.
    resolved="$(jq -r '.resolved // ""' /run/punar/surfaces-theme.json)"
    case "${resolved}" in
        ""|"built-in fallback palette")
            note "FAIL theme resolved the BUILT-IN FALLBACK palette ('${resolved}') — no shipped theme document was found; the desktop looks themed but no theme is selectable"
            FAILED=1
            ;;
        *)
            note "ok   theme resolved a shipped document (${resolved})"
            ;;
    esac
else
    note "FAIL theme.status did not return parseable JSON"
    FAILED=1
fi

# The catalog must hold every theme document the image actually ships —
# asserted as a relation between the shell and the filesystem, so adding or
# removing a theme keeps the check honest with no edit here.
# theme.list is ASYNCHRONOUS on its first call. ensureCatalog() kicks four
# FolderListModels and returns immediately, so the first answer legitimately
# carries ready=false with an empty/partial catalog — Theme.qml says so at the
# catalogReady declaration ("Call it again"). Asserting the first response
# would fail on a perfectly healthy machine, so poll for ready and let the
# assertions below judge the settled catalog.
catalog_ready() {
    ipc theme list > /run/punar/surfaces-themes.json 2>/dev/null
    jq -e '.ready == true' /run/punar/surfaces-themes.json >/dev/null 2>&1
}
if wait_for 30 catalog_ready; then
    note "ok   theme catalog settled (ready=true)"
else
    note "FAIL theme catalog never reported ready=true within 30s"
    FAILED=1
fi
on_disk="$(find /usr/share/punar/theme/themes -name '*.theme.json' 2>/dev/null | wc -l | tr -d ' ')"
if jq -e . /run/punar/surfaces-themes.json >/dev/null 2>&1; then
    in_catalog="$(jq -r '.themes | length' /run/punar/surfaces-themes.json)"
    check_eq "themes in catalog == *.theme.json on disk (${on_disk})" "${on_disk}" "${in_catalog}"
    if [ "${on_disk}" -eq 0 ] 2>/dev/null; then
        note "FAIL no *.theme.json under /usr/share/punar/theme/themes — the staging step shipped no themes, and the equality above is vacuous"
        FAILED=1
    fi
else
    note "FAIL theme.list did not return parseable JSON"
    FAILED=1
fi

bar_state="$(ipc bar state | tr -d '[:space:]"')"
case "${bar_state}" in
    focused|idle) note "ok   bar.state answers a defined value ('${bar_state}')" ;;
    *) note "FAIL bar.state returned '${bar_state}' (expected 'focused' or 'idle')"
       FAILED=1 ;;
esac

# --- group 5: the browser is a NATIVE WAYLAND client, with our flags ---------
# This is the assertion that proves /etc/chromium-flags.conf was found, parsed
# and applied — not that it exists. The launcher silently SKIPS any line with
# unbalanced quotes, so a file that is present and readable can still apply
# nothing at all; only the running process settles it.
#
# It also proves the flags reach a launch path that is NOT the keybind. The
# exec below is a bare `chromium` with no arguments, exactly as the packaged
# chromium.desktop and xdg-open invoke it. Before this file existed the ozone
# hint lived on the SUPER+B bind alone and this assertion would have failed.
chromium_client() {
    hyprctl -j clients 2>/dev/null \
        | jq -e '[ .[] | select(.class | ascii_downcase | test("chromium")) ] | length >= 1'
}
hyprctl dispatch exec chromium >/dev/null 2>&1
if wait_for 180 chromium_client; then
    note "ok   chromium window appeared"

    is_xwayland="$(hyprctl -j clients 2>/dev/null \
        | jq -r '[ .[] | select(.class | ascii_downcase | test("chromium")) ][0].xwayland')"
    check_eq "chromium client is native Wayland (xwayland=false)" "false" "${is_xwayland}"

    # The flags file reached the process. Read the browser's own argv rather
    # than the config file: /proc/<pid>/cmdline is what actually happened.
    cpid="$(hyprctl -j clients 2>/dev/null \
        | jq -r '[ .[] | select(.class | ascii_downcase | test("chromium")) ][0].pid')"
    if [ -n "${cpid}" ] && [ -r "/proc/${cpid}/cmdline" ]; then
        cargs="$(tr '\0' ' ' < "/proc/${cpid}/cmdline")"
        for flag in --no-first-run --no-default-browser-check; do
            case " ${cargs} " in
                *" ${flag} "*) note "ok   chromium argv carries ${flag}" ;;
                *) note "FAIL chromium argv missing ${flag} — /etc/chromium-flags.conf was not applied"
                   FAILED=1 ;;
            esac
        done
        printf '%s\n' "${cargs}" > /run/punar/surfaces-chromium-argv.txt
    else
        note "FAIL could not read chromium argv (pid='${cpid}')"
        FAILED=1
    fi

    # THE MENUBAR TRACKS WHAT IS RUNNING. With a browser on screen and
    # focused, the bar's left zone must name it. This is asserted as a
    # relation between two independent readings of the live session — what
    # Hyprland says is focused, and what the bar says it is naming — so it
    # cannot pass by rendering a constant, and it fails if the bar stops
    # following focus.
    hyprctl dispatch focuswindow "class:^([Cc]hromium.*)$" >/dev/null 2>&1
    bar_names_focus() {
        hy="$(hyprctl -j activewindow 2>/dev/null | jq -r '.class // ""' | tr '[:upper:]' '[:lower:]')"
        br="$(ipc bar app | tr -d '[:space:]"' | tr '[:upper:]' '[:lower:]')"
        [ -n "${hy}" ] && [ -n "${br}" ] && [ "${hy}" = "${br}" ]
    }
    if wait_for 20 bar_names_focus; then
        note "ok   the menubar names the focused window ($(ipc bar app | tr -d '[:space:]\"'))"
    else
        note "FAIL menubar/focus disagree — hyprland says '$(hyprctl -j activewindow 2>/dev/null | jq -r '.class // ""')', bar says '$(ipc bar app | tr -d '[:space:]\"')'"
        FAILED=1
    fi

    # Leave the session as we found it — later groups and the idle-RAM sample
    # must not inherit a browser.
    [ -n "${cpid}" ] && kill "${cpid}" 2>/dev/null
    no_chromium() { ! chromium_client; }
    if wait_for 60 no_chromium; then
        note "ok   chromium closed, session restored"
        # The other half of the relation: with nothing focused the bar names
        # nothing, so the left zone never leaves a stale application standing
        # after its window is gone.
        bar_empty() { [ -z "$(ipc bar app | tr -d '[:space:]\"')" ]; }
        if wait_for 20 bar_empty; then
            note "ok   the menubar names nothing once the window is gone"
        else
            note "FAIL the menubar still names '$(ipc bar app | tr -d '[:space:]\"')' after its window closed"
            FAILED=1
        fi
    else
        note "FAIL chromium still present after kill — later measurements are polluted"
        FAILED=1
    fi
else
    # Distinguish "never started" from "started and died", because they are
    # different bugs and the window's absence looks identical from here.
    if pgrep -u "$(id -un)" -f 'chromium' >/dev/null 2>&1; then
        note "FAIL chromium process is running but mapped no window within 180s (renderer or GPU-init stall?)"
        pgrep -u "$(id -un)" -af 'chromium' > /run/punar/surfaces-chromium-procs.txt 2>/dev/null || true
    else
        note "FAIL no chromium window within 180s and NO chromium process — it never started or exited immediately"
    fi
    FAILED=1
fi

# --- group 6: the SYSTEM can open a link, not just a human ------------------
# xdg-open is what a notification action, a terminal URL activation or the
# command center's "open" verb calls. Both halves are asserted because either
# alone is satisfiable while links stay broken: the tool has to exist, and it
# has to resolve to a handler.
if command -v xdg-open >/dev/null 2>&1; then
    note "ok   xdg-open present"
else
    note "FAIL xdg-open absent — no application can ask the system to open a URL"
    FAILED=1
fi

for scheme in x-scheme-handler/https x-scheme-handler/http text/html; do
    handler="$(xdg-mime query default "${scheme}" 2>/dev/null | tr -d '[:space:]')"
    check_eq "default handler for ${scheme}" "chromium.desktop" "${handler}"
done

# The handler must name a desktop entry that EXISTS. xdg-open fails through a
# dangling handler silently, which looks identical to having no default at all.
if [ -f /usr/share/applications/chromium.desktop ]; then
    note "ok   chromium.desktop present at /usr/share/applications"
else
    note "FAIL chromium.desktop missing — the default handler is dangling"
    FAILED=1
fi

# --- group 7: UNMANAGED-FIRST — no org chrome on an unenrolled device -------
# DESIGN_LANGUAGE.md section 8: enrollment adds chrome, it never restructures a
# surface. Chromium reads enterprise policy from /etc/chromium/policies/; a
# managed policy present here would make the browser's own menu say "Managed by
# your organization" on a device that was never enrolled — the same defect
# class as the M5 policy.d/ai directory created on every device.
#
# Written as a conditional on the DEVICE's enrollment state rather than as a
# flat "this path is empty", so it survives Milestone 11 shipping managed
# policy for devices that genuinely are enrolled.
enrolled=no
if [ -f /var/lib/punar/enrollment.json ]; then
    if jq -e '.state == "enrolled"' /var/lib/punar/enrollment.json >/dev/null 2>&1; then
        enrolled=yes
    fi
fi
managed_count=0
if [ -d /etc/chromium/policies/managed ]; then
    managed_count="$(find /etc/chromium/policies/managed -type f 2>/dev/null | wc -l | tr -d ' ')"
fi
note "# enrolled=${enrolled} managed_policy_files=${managed_count}"
if [ "${enrolled}" = "no" ]; then
    check_eq "unenrolled device carries no chromium managed policy" "0" "${managed_count}"
else
    note "ok   device enrolled — managed policy is permitted (${managed_count} file(s))"
fi

# --- group 8: the lock screen cannot lock the user out ----------------------
# Not a lock/unlock round trip: submit() is unreachable over IPC (see header).
# The asserted failure is the one that actually strands a user — Lock.qml probes
# /etc/pam.d/punar-lock and falls back to "login", so whichever it resolves to
# must exist, or the passphrase can never be verified and the session is a
# one-way door.
lock_state="$(ipc lock state | tr -d '[:space:]"')"
check_eq "lock.state while unlocked" "unlocked" "${lock_state}"

if [ -f /etc/pam.d/punar-lock ]; then
    resolved=punar-lock
else
    resolved=login
fi
if [ -f "/etc/pam.d/${resolved}" ]; then
    note "ok   lock screen PAM stack '${resolved}' exists at /etc/pam.d/${resolved}"
else
    note "FAIL lock screen resolves to PAM stack '${resolved}' which does not exist — locking would be a one-way door"
    FAILED=1
fi

# --- artifacts --------------------------------------------------------------
hyprctl -j clients > /run/punar/surfaces-clients.json 2>/dev/null || true

finish
