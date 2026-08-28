#!/bin/sh
# Punar desktop-surfaces in-VM exercise.
#
# WHY THIS EXISTS. The shell surfaces landed gated by qmllint and
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
sresidency() { ipc "$1" residency | tr -d '[:space:]"'; }

shell_alive() { ${SHELL_CMD} ipc call bar state >/dev/null 2>&1; }
t_open()   { [ "$(sstate "$1")" = "open" ]; }
t_closed() { [ "$(sstate "$1")" = "closed" ]; }
t_unloaded() { [ "$(sresidency "$1")" = "unloaded" ]; }

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

systemcontrol_models_ready() {
    ipc systemcontrol model compliance > /run/punar/surfaces-systemcontrol-drift.json 2>/dev/null
    ipc systemcontrol model firewall > /run/punar/surfaces-systemcontrol-firewall.json 2>/dev/null
    ipc systemcontrol model applications > /run/punar/surfaces-systemcontrol-applications.json 2>/dev/null
    jq -e '.title == "Drift"
        and (.sub | startswith("Security ·"))
        and .pill.label == "Overall · Matches"' \
        /run/punar/surfaces-systemcontrol-drift.json >/dev/null 2>&1 \
        && jq -e '.explains | length > 0
            and all(.[]; .stateKey == "Drift" and .compliance == "Matches")' \
            /run/punar/surfaces-systemcontrol-firewall.json >/dev/null 2>&1 \
        && jq -e '.title == "Applications"
            and (.sub | contains(" installed · ") and contains(" available · catalog "))
            and any(.rows[]; .tag == "Installed")
            and ([.rows[] | select(.tag == "Available") | .name] | sort
                == ["Discord", "Element", "Firefox", "Slack", "Spotify", "Telegram"])
            and any(.actions[]; .hotkey == "O" and .kind == "applicationBrowser")' \
            /run/punar/surfaces-systemcontrol-applications.json >/dev/null 2>&1
}

if ! wait_for 90 shell_alive; then
    note "FAIL punar-shell IPC not answering within 90s (no surface can be tested)"
    FAILED=1; finish
fi
note "ok   punar-shell IPC answering"

# --- group 2: every unconditionally-openable surface opens AND closes --------
# The biconditional matters in both directions. Asserting only that open()
# reports "open" would pass for a surface whose state() is hardcoded; asserting
# the close leg too means the value has to actually track the surface.
# One empty-desktop frame kept as context for a human reading the artifacts.
# The ASSERTION each surface is held to uses its own before/after pair taken
# around that surface's open, not this one.
# The real bindings are Hyprland `exec` actions whose command is the same
# `qs ... ipc call <surface> toggle` used below.  Re-enter that path through
# Hyprland rather than calling the surface directly.  The checker adds one
# `hyprctl dispatch` client that a physical key does not; measure that control
# round trip five times and record the largest observed cost instead of hiding
# it in the surface number.
dispatch_probe_max_ms=0
dispatch_probe_i=0
while [ "${dispatch_probe_i}" -lt 5 ]; do
    dispatch_probe_start_ms="$(date +%s%3N)"
    hyprctl dispatch "hl.dsp.exec_cmd('true')" >/dev/null 2>&1
    dispatch_probe_ms="$(($(date +%s%3N) - dispatch_probe_start_ms))"
    if [ "${dispatch_probe_ms}" -gt "${dispatch_probe_max_ms}" ]; then
        dispatch_probe_max_ms="${dispatch_probe_ms}"
    fi
    dispatch_probe_i=$((dispatch_probe_i + 1))
done
# Let the five no-op shells leave the scheduler before the first measurement.
sleep 1

{
    echo "# Surface-open latency in the CI VM under KVM, milliseconds."
    echo "# Path: checker -> Hyprland exec -> configured qs IPC toggle -> show()"
    echo "#       -> Hyprland openlayer -> Quickshell socket2 rawEvent."
    echo "# dispatch_ms = checker starts Hyprland dispatch -> show() begins."
    echo "# shell_map_ms = show() begins -> shell receives openlayer; both timestamps"
    echo "#                come from Date.now() inside the long-lived shell."
    echo "# total_ms = dispatch_ms + shell_map_ms."
    echo "# No polling client or process runs inside shell_map_ms. Its clock"
    echo "# quantization uncertainty is <2 ms (two 1 ms timestamps)."
    echo "# dispatch_ms and total_ms include one checker-only hyprctl client."
    echo "# Largest observed hyprctl dispatch round trip in 5 probes: ${dispatch_probe_max_ms} ms."
    printf '# surface\tdispatch_ms\tshell_map_ms\ttotal_ms\n'
} > /run/punar/surfaces-latency.txt

BASELINE_BYTES=""
if grim /run/punar/surfaces-baseline.png 2>/dev/null; then
    BASELINE_BYTES="$(wc -c < /run/punar/surfaces-baseline.png | tr -d ' ')"
    note "info empty-desktop reference captured (${BASELINE_BYTES} bytes)"
fi

# `approval` is deliberately NOT in this list and is asserted conditionally in
# group 2b: it is a GATE, not a panel, and "unconditionally-openable" is simply
# false for it.
for t in commandcenter systemcontrol notifications shortcuts aipanel overview; do
    before="$(sstate "${t}")"
    check_eq "${t}.state before open" "closed" "${before}"
    check_eq "${t}.residency before open" "unloaded" "$(sresidency "${t}")"

    # Capture the actual desktop BEFORE the trigger. The timing path waits one
    # second without polling so its measurement cannot be perturbed; taking
    # this frame after that wait would capture an already-settled surface and
    # then compare it with itself, falsely calling a static panel blank.
    before_sha=""
    if grim "/run/punar/surfaces-${t}-before.png" 2>/dev/null; then
        before_sha="$(sha256sum "/run/punar/surfaces-${t}-before.png" | cut -d' ' -f1)"
    else
        note "info ${t} pre-open screenshot unavailable (grim failed; paint not asserted)"
    fi

    # HOW FAST DOES IT FEEL.  Start before asking Hyprland to execute the
    # surface's configured command.  show() and the compositor's openlayer
    # event are timestamped inside punar-shell by SurfaceTiming, so the
    # checker does not poll — or spawn anything — inside the surface interval.
    t_start_ms="$(date +%s%3N)"
    hyprctl dispatch "hl.dsp.exec_cmd('${SHELL_CMD} ipc call ${t} toggle')" >/dev/null 2>&1

    # A healthy surface maps well inside this second.  Waiting once keeps the
    # timing interval free of checker processes.  The slow-path waits below
    # preserve the functional 15-second assertion, but no latency is inferred
    # from those poll times: the shell's two event timestamps remain the only
    # timing source.
    sleep 1
    state_after="$(sstate "${t}")"
    if [ "${state_after}" = "open" ]; then
        note "ok   ${t}.toggle through Hyprland -> open"
    elif wait_for 14 t_open "${t}"; then
        note "ok   ${t}.toggle through Hyprland -> open after the 1s measurement window"
    else
        note "FAIL ${t}.toggle through Hyprland did not reach state=open (got '${state_after}')"
        FAILED=1
    fi
    check_eq "${t}.residency while open" "resident" "$(sresidency "${t}")"

    # The surface must have a MAPPED WINDOW, not merely a flag set. state()
    # reads root.open; the window is bound to root.windowVisible. Asserting the
    # compositor's own layer list closes that gap.
    if layer_mapped "punar-${t}" || wait_for 14 layer_mapped "punar-${t}"; then
        note "ok   ${t} mapped a layer-shell surface (punar-${t})"
    else
        note "FAIL ${t} reports open but the compositor has no punar-${t} layer — the flag is set and nothing is on screen"
        FAILED=1
    fi

    timing="$(ipc "${t}" latency | tr -d '[:space:]\"')"
    case "${timing}" in
        *','*)
            opened_at_ms="${timing%%,*}"
            mapped_at_ms="${timing#*,}"
            case "${opened_at_ms}" in
                ''|*[!0-9]*) timestamps_valid=no ;;
                *) timestamps_valid=yes ;;
            esac
            case "${mapped_at_ms}" in
                ''|*[!0-9]*) timestamps_valid=no ;;
            esac
            case "${timestamps_valid}" in
                no)
                    note "FAIL ${t}.latency returned malformed timestamps '${timing}'"
                    FAILED=1
                    ;;
                yes)
                    dispatch_ms="$((opened_at_ms - t_start_ms))"
                    shell_map_ms="$((mapped_at_ms - opened_at_ms))"
                    total_ms="$((mapped_at_ms - t_start_ms))"
                    if [ "${dispatch_ms}" -lt 0 ] || [ "${shell_map_ms}" -lt 0 ]; then
                        note "FAIL ${t}.latency clocks ran backwards ('${timing}', trigger ${t_start_ms})"
                        FAILED=1
                    else
                        note "ok   ${t} Hyprland-to-layer path ${total_ms} ms (${dispatch_ms} dispatch + ${shell_map_ms} shell-to-map)"
                        printf '%s\t%s\t%s\t%s\n' "${t}" "${dispatch_ms}" "${shell_map_ms}" "${total_ms}" >> /run/punar/surfaces-latency.txt
                    fi
                    ;;
            esac
            ;;
        *)
            note "FAIL ${t}.latency has no internal openlayer sample (got '${timing}')"
            FAILED=1
            ;;
    esac

    # A surface that reports open and draws nothing looks identical from here,
    # and state() cannot tell the difference. grim is the cheapest evidence
    # that pixels exist, and it gives a human something to look at without
    # booting anything (the punar-m2.png precedent). A failed capture is not
    # an assertion failure — grim has its own reasons to fail and the surface
    # contract is what is being tested — but the file's SIZE is recorded, so
    # a suspiciously tiny frame is visible in the report.
    # THE SURFACE MUST PAINT, not merely map. A mapped layer is not pixels:
    # these panels declare `color: "transparent"` and animate their content in
    # over the 300 ms token curve, so a capture taken the instant the layer
    # appears composites to EXACTLY the bare desktop. The first green run
    # proved it — four of six surfaces came back byte-identical to the
    # empty-desktop baseline while every layer assertion passed.
    #
    # The baseline is retaken immediately before each surface rather than once
    # per run, so the only thing that can differ between the two frames is this
    # surface. (A minute rolling over in the clock would otherwise be enough to
    # make an unpainted frame look painted.)
    painted=""
    if [ -n "${before_sha}" ]; then
        pi=0
        while [ "${pi}" -lt 15 ]; do
            sleep 1
            pi=$((pi + 1))
            grim "/run/punar/surfaces-${t}.png" 2>/dev/null || break
            after_sha="$(sha256sum "/run/punar/surfaces-${t}.png" | cut -d' ' -f1)"
            if [ "${after_sha}" != "${before_sha}" ]; then
                painted="yes"
                break
            fi
        done
        rm -f "/run/punar/surfaces-${t}-before.png"
        if [ -n "${painted}" ]; then
            note "ok   ${t} painted pixels ($(wc -c < "/run/punar/surfaces-${t}.png" | tr -d ' ') bytes after ${pi}s, frame differs from the desktop behind it)"
        else
            note "FAIL ${t} mapped a layer but the screen never changed in 15s — the surface is on screen and blank"
            FAILED=1
        fi
    fi

    # DESIGN_LANGUAGE §8.1, proved on the running personal device rather than
    # inferred from source: no Organization furniture or enrollment prompt;
    # the useful primitives remain under Security, and both the summary and
    # the real capability card translate the unchanged wire value to
    # DRIFT/MATCHES.
    if [ "${t}" = "systemcontrol" ]; then
        ipc systemcontrol rail > /run/punar/surfaces-systemcontrol-rail.json 2>/dev/null
        if jq -e '
            (length > 0)
            and (all(.[]; .section != "Organization" and .id != "enrollment"))
            and (any(.[]; .id == "compliance" and .name == "Drift" and .section == "Security"))
            and (any(.[]; .id == "policies" and .name == "Policy" and .section == "Security"))
            and (any(.[]; .id == "privilege" and .section == "Security"))
            and (any(.[]; .id == "applications" and .name == "Applications" and .section == "System"))
        ' /run/punar/surfaces-systemcontrol-rail.json >/dev/null 2>&1; then
            note "ok   personal System Control keeps unmanaged-first placement and exposes Applications under System"
        else
            note "FAIL personal System Control rail violates unmanaged-first placement"
            FAILED=1
        fi

        if wait_for 30 systemcontrol_models_ready; then
            note "ok   personal System Control renders DRIFT/MATCHES and the live installed/signed-catalog Applications model"
        else
            note "FAIL personal System Control did not render its live compliance and Applications models"
            FAILED=1
        fi
    fi

    # The dedicated application library is an on-demand mode of Command
    # Center, not a second resident store process. Exercise its typed IPC
    # entry and export a frame so CI proves the responsive browse component
    # actually instantiated with the signed six-app catalog.
    if [ "${t}" = "commandcenter" ]; then
        browse_result="$(ipc commandcenter applications | tr -d '\r\n\"')"
        check_eq "command center opens the application library" "applications" "${browse_result}"
        check_eq "application library reports its distinct state" "applications" "$(sstate commandcenter)"
        sleep 1
        if grim /run/punar/surfaces-applications.png 2>/dev/null; then
            note "ok   application library frame captured ($(wc -c < /run/punar/surfaces-applications.png | tr -d ' ') bytes)"
        else
            note "info application library screenshot unavailable (grim failed; not an assertion)"
        fi
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
    if wait_for 15 t_unloaded "${t}"; then
        note "ok   ${t} released its object tree after close"
    else
        note "FAIL ${t} closed but remained $(sresidency "${t}")"
        FAILED=1
    fi
done

# --- group 2b: the approval gate needs a contract to draw --------------------
# This overlay draws exactly one thing — punard's pending contract — and its own
# control loop closes it the moment the queue empties:
#     if (root.open && Approvals.pendingCount === 0) root.dismiss();
# so with nothing pending, an `open` is answered by a close. That is the design,
# not a defect. An overlay that stayed open would hold
# WlrKeyboardFocus.Exclusive over a fullscreen scrim to draw a card with no
# record behind it — head "Approval · none", the sentence "This requester wants
# to set  to .", "Expires 0:00" — a fabricated contract on the one surface whose
# entire job is to be unspoofable. Group 3's empty-shelf rule, one surface
# stricter.
#
# Keyed on the QUEUE rather than on the surface's own state, because this
# overlay exposes `pending` AND `selected` and the precondition can therefore be
# asserted instead of assumed. `selected` is read because pending == 0 is not
# the overlay's only guard: punard retains recently-resolved records so a
# verdict stays readable, and a selected-but-resolved card is a legitimate open
# with an empty queue.
apending="$(ipc approval pending | tr -d '[:space:]"')"
aselected="$(ipc approval selected | tr -d '[:space:]"')"
check_eq "approval.state before open" "closed" "$(sstate approval)"
case "${apending}" in
    ''|*[!0-9]*)
        note "FAIL approval.pending returned '${apending}' (expected a count) — the gate's own queue probe is broken"
        FAILED=1
        ;;
    0)
        if [ -n "${aselected}" ]; then
            note "ok   approval queue empty but a resolved card is still selected ('${aselected}') — empty-gate invariant not applicable"
        else
            ipc approval open >/dev/null 2>&1
            sleep 2
            check_eq "approval.open with an empty queue stays closed (a gate with no contract is not drawn)" \
                "closed" "$(sstate approval)"
            # The load-bearing leg: a flag reading closed while punar-approval
            # is mapped would be a fullscreen overlay holding the keyboard.
            if wait_for 15 layer_gone punar-approval; then
                note "ok   approval mapped no layer-shell surface with an empty queue"
            else
                note "FAIL approval reports closed but punar-approval is mapped — a fullscreen overlay is on screen with nothing pending"
                FAILED=1
            fi
            check_eq "approval.open with an empty queue invents no contract (pending)" \
                "0" "$(ipc approval pending | tr -d '[:space:]"')"
            check_eq "approval.open with an empty queue invents no contract (selected)" \
                "" "$(ipc approval selected | tr -d '[:space:]"')"
            note "info no approval screenshot: a photograph of the bare desktop filed as surfaces-approval.png is misleading evidence"
        fi
        ;;
    *)
        ipc approval open >/dev/null 2>&1
        if wait_for 15 t_open approval; then
            note "ok   approval.open -> open (${apending} pending)"
        else
            note "FAIL approval.open did not reach state=open within 15s with ${apending} pending (got '$(sstate approval)')"
            FAILED=1
        fi
        if wait_for 15 layer_mapped punar-approval; then
            note "ok   approval mapped a layer-shell surface (punar-approval)"
        else
            note "FAIL approval reports open but the compositor has no punar-approval layer"
            FAILED=1
        fi
        # Same paint assertion as the loop: a mapped layer is not pixels.
        apainted=""
        if grim /run/punar/surfaces-approval-before.png 2>/dev/null; then
            abefore="$(sha256sum /run/punar/surfaces-approval-before.png | cut -d' ' -f1)"
            api=0
            while [ "${api}" -lt 15 ]; do
                sleep 1
                api=$((api + 1))
                grim /run/punar/surfaces-approval.png 2>/dev/null || break
                aafter="$(sha256sum /run/punar/surfaces-approval.png | cut -d' ' -f1)"
                if [ "${aafter}" != "${abefore}" ]; then
                    apainted="yes"
                    break
                fi
            done
            rm -f /run/punar/surfaces-approval-before.png
            if [ -n "${apainted}" ]; then
                note "ok   approval painted pixels ($(wc -c < /run/punar/surfaces-approval.png | tr -d ' ') bytes after ${api}s)"
            else
                note "FAIL approval mapped a layer but the screen never changed in 15s — a gate is on screen and blank"
                FAILED=1
            fi
        else
            note "info approval screenshot unavailable (grim failed; not an assertion)"
        fi
        ipc approval close >/dev/null 2>&1
        if wait_for 15 t_closed approval; then
            note "ok   approval.close -> closed"
        else
            note "FAIL approval.close did not reach state=closed within 15s (got '$(sstate approval)')"
            FAILED=1
        fi
        if wait_for 15 layer_gone punar-approval; then
            note "ok   approval unmapped its layer-shell surface"
        else
            note "FAIL approval reports closed but punar-approval is still mapped"
            FAILED=1
        fi
        # Dismissal is not denial: closing the gate must resolve nothing.
        check_eq "approval.close resolved nothing: the queue is unchanged" \
            "${apending}" "$(ipc approval pending | tr -d '[:space:]"')"
        ;;
esac

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

# Wallpaper is a finite typed preference, not merely an image that happened to
# copy into the rootfs. Prove the live shell owns the expected catalog, starts
# on the inviting default, can switch to the vector fallback, and restores the
# default through the same atomic preference path the command center uses.
ipc wallpaper state > /run/punar/surfaces-wallpaper-state.json 2>/dev/null
if jq -e '.active == "stillpoint" and .writable == true' \
        /run/punar/surfaces-wallpaper-state.json >/dev/null 2>&1; then
    note "ok   wallpaper starts on writable Stillpoint default"
else
    note "FAIL wallpaper state is not the writable Stillpoint default"
    FAILED=1
fi

ipc wallpaper list > /run/punar/surfaces-wallpapers.json 2>/dev/null
if jq -e '.default == "stillpoint"
        and (.wallpapers | length) == 5
        and ([.wallpapers[].id] | sort) == (["daybreak", "earthrise", "field", "stillpoint", "winterline"] | sort)' \
        /run/punar/surfaces-wallpapers.json >/dev/null 2>&1; then
    note "ok   wallpaper catalog exposes the five shipped choices"
else
    note "FAIL wallpaper catalog does not expose exactly daybreak/earthrise/field/stillpoint/winterline"
    FAILED=1
fi

wallpaper_asset() {
    wa_name="$1"
    wa_expected="$2"
    wa_path="/usr/share/punar/shell/Wallpaper/assets/${wa_name}.jpg"
    wa_actual="$(sha256sum "${wa_path}" 2>/dev/null | cut -d' ' -f1)"
    wa_info="$(file -b "${wa_path}" 2>/dev/null || true)"
    if [ "${wa_actual}" = "${wa_expected}" ] \
            && printf '%s\n' "${wa_info}" | grep -Eq '3840[[:space:]]?x[[:space:]]?2400'; then
        note "ok   ${wa_name} is the attributed 3840x2400 shipped asset"
    else
        note "FAIL ${wa_name} asset is missing, altered, or not 3840x2400 (sha='${wa_actual}', file='${wa_info}')"
        FAILED=1
    fi
}

wallpaper_asset daybreak 4aa5af32a22ead3930bab5b9b24e1a8c899ba13268e0e58acd94c96251905c18
wallpaper_asset winterline 04aab01c53774d96d336ef0d15d235e10d9f1194ee7409615f7956615b5759f1
wallpaper_asset earthrise f5a6fb900ec98de5acdcd817728fcadfba18a700949e9b474c9f58c71a4f182f
wallpaper_asset stillpoint 6313a086a8eddb5b8f113edc50b4d7c1656b433c0e7fdb3c7cd97d90d65439e0
if [ -f /usr/share/punar/shell/Wallpaper/SOURCES.md ]; then
    note "ok   wallpaper source and licence manifest ships beside the assets"
else
    note "FAIL Wallpaper/SOURCES.md missing — licensed assets have no shipped attribution"
    FAILED=1
fi

ipc wallpaper set field > /run/punar/surfaces-wallpaper-set.json 2>/dev/null
if jq -e '.applied == true and .active == "field"' \
        /run/punar/surfaces-wallpaper-set.json >/dev/null 2>&1; then
    note "ok   wallpaper.set commits the Field vector preference"
else
    note "FAIL wallpaper.set field was not applied"
    FAILED=1
fi

ipc wallpaper reset > /run/punar/surfaces-wallpaper-reset.json 2>/dev/null
if jq -e '.applied == true and .active == "stillpoint" and .source == "shipped default"' \
        /run/punar/surfaces-wallpaper-reset.json >/dev/null 2>&1; then
    note "ok   wallpaper.reset restores the shipped Stillpoint default"
else
    note "FAIL wallpaper.reset did not restore the shipped Stillpoint default"
    FAILED=1
fi

wallpaper_row="$(ipc commandcenter query wallpaper | tr -d '\r\n\"')"
check_eq "command center exposes wallpaper as a typed action" \
    "wallpaper · SetWallpaper(stillpoint) · current" "${wallpaper_row}"
ipc commandcenter close >/dev/null 2>&1

bar_state="$(ipc bar state | tr -d '[:space:]"')"
case "${bar_state}" in
    focused|idle) note "ok   bar.state answers a defined value ('${bar_state}')" ;;
    *) note "FAIL bar.state returned '${bar_state}' (expected 'focused' or 'idle')"
       FAILED=1 ;;
esac

# --- group 5: people can FIND, OPEN, and CLOSE an installed application -------
# This is the ordinary desktop loop, driven through the same product surfaces
# and compositor actions a person uses.  A direct `chromium` exec followed by
# `kill $pid` used to prove browser packaging while leaving the actual app
# launcher and close-window affordance unexercised.
#
# First prove discoverability: the live command-centre model must resolve an
# installed freedesktop entry to a typed Launch action. Then press its selected
# row through commandcenter.run (the IPC equivalent of Enter), wait for a real
# mapped window, and finally close that focused window through Hyprland's
# native close action — the action bound to PUNAR+Q and rendered by the live
# shortcuts surface. Lua-native binds intentionally expose `__lua` plus an
# opaque callback id through `hyprctl binds`; their stable runtime contract is
# the key and human description, while actual close behavior is proven below.
launch_row="$(ipc commandcenter query chromium | tr -d '\r\n\"')"
check_eq "command center finds installed Chromium" "app · Launch(chromium)" "${launch_row}"

launch_result="$(ipc commandcenter run | tr -d '\r\n\"')"
check_eq "command center invokes the selected installed app" "app · Launch(chromium)" "${launch_result}"

# The live binding table is the discoverable source of truth; require the
# close action to be present there rather than trusting a config-file grep.
if hyprctl binds -j 2>/dev/null \
        | jq -e 'any(.[]; .key == "Q" and .dispatcher == "__lua" and .description == "Close window")' \
        >/dev/null 2>&1; then
    note "ok   live Lua shortcuts expose PUNAR+Q as Close window"
else
    note "FAIL live Lua shortcuts do not expose Q / __lua / Close window"
    FAILED=1
fi

# The browser must also be a NATIVE WAYLAND client, with our flags. This is
# the assertion that proves /etc/chromium-flags.conf was found, parsed
# and applied — not that it exists. The launcher silently SKIPS any line with
# unbalanced quotes, so a file that is present and readable can still apply
# nothing at all; only the running process settles it.
#
# It also proves the flags reach a launch path that is NOT the browser keybind.
# DesktopEntry.execute() uses packaged chromium.desktop, exactly as xdg-open
# does. Before this file existed the ozone hint lived on the PUNAR+B bind alone
# and this assertion would have failed.
chromium_client() {
    hyprctl -j clients 2>/dev/null \
        | jq -e '[ .[] | select(.class | ascii_downcase | test("chromium")) ] | length >= 1'
}
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
    hyprctl dispatch "hl.dsp.focus({ window = 'class:^([Cc]hromium.*)$' })" >/dev/null 2>&1
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

    # The ordinary close and emergency force-quit paths are deliberately not
    # the same action. The live table must expose a window-actions surface —
    # never an unguarded Force quit description — and that surface must
    # snapshot the focused browser before it enables its controls. Hyprland's
    # Lua provider deliberately reports callback dispatchers as `__lua`, so
    # the opaque callback id is not treated as inspectable command text.
    if hyprctl binds -j 2>/dev/null \
            | jq -e 'any(.[]; .key == "Q" and .description == "Window actions"
                and .dispatcher == "__lua")
                and all(.[]; .key != "Q" or .description != "Force quit")' \
            >/dev/null 2>&1; then
        note "ok   live Lua shortcuts expose guarded Window actions (no direct Force quit bind)"
    else
        note "FAIL live Lua shortcuts do not expose the guarded Window actions surface"
        FAILED=1
    fi

    ipc windowactions open >/dev/null 2>&1
    window_actions_ready() { [ "$(sstate windowactions)" = "ready" ]; }
    if wait_for 20 window_actions_ready && layer_mapped punar-window-actions; then
        note "ok   window actions mapped and snapshotted the focused Chromium window"
    else
        note "FAIL window actions did not reach ready with a mapped layer surface (state='$(sstate windowactions)')"
        FAILED=1
    fi
    ipc windowactions close >/dev/null 2>&1
    if wait_for 20 t_unloaded windowactions; then
        note "ok   window actions unloads after dismissal"
    else
        note "FAIL window actions retained its layer after dismissal"
        FAILED=1
    fi

    # Close it as the person does. The focus operation is typed and bounded;
    # PUNAR+Q asks the active client to close rather than terminating it.
    hyprctl dispatch "hl.dsp.focus({ window = 'class:^([Cc]hromium.*)$' })" >/dev/null 2>&1
    hyprctl dispatch "hl.dsp.window.close()" >/dev/null 2>&1
    no_chromium() { ! chromium_client; }
    if wait_for 60 no_chromium; then
        note "ok   PUNAR+Q close action removed the focused Chromium window"
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
        note "FAIL Chromium window still present after the close dispatcher — later measurements are polluted"
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
