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

# A developer-first image must prove its baseline tools execute for the
# ordinary desktop user. Merely naming `git` in mkosi.conf is insufficient:
# a packaging regression, broken loader, or PATH mistake would still leave AI
# coding tools claiming Git is unavailable after boot.
if command -v git >/dev/null 2>&1; then
    git_version="$(git --version 2>/dev/null || true)"
    case "${git_version}" in
        "git version "*) note "ok   developer baseline Git is usable (${git_version})" ;;
        *)
            note "FAIL Git is on PATH but did not report a usable version (got '${git_version}')"
            FAILED=1
            ;;
    esac
else
    note "FAIL developer baseline Git is not available on the desktop PATH"
    FAILED=1
fi

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
        && jq -e --slurpfile catalog /usr/share/punar/catalog/catalog.json '.title == "Applications"
            # The summary is user-facing state, not decoration. Prove each
            # advertised count against the live rows and the version against
            # the signed catalog. This intentionally follows the richer
            # native/web/available wording rather than the retired aggregate
            # "installed" label.
            and ((.sub | capture("^System · (?<native>[0-9]+) native · (?<web>[0-9]+) web apps · (?<available>[0-9]+) available · catalog (?<version>[^ ]+)$")) as $summary
                | (($summary.native | tonumber) == ([.rows[] | select(.tag == "Installed")] | length))
                and (($summary.web | tonumber) == ([.rows[] | select(.action.kind == "webApplication")] | length))
                and (($summary.available | tonumber) == ([.rows[] | select(.tag == "Available")] | length))
                and ($summary.version == $catalog[0].catalogVersion))
            and any(.rows[]; .tag == "Installed")
            # Every catalog product must be represented by either its
            # installed row or its available row. Derive this from the signed
            # image catalog: pinning the original eight names made the gate
            # report a healthy expanded developer catalog as a UI failure.
            and ([.rows[].name] as $shown
                | all($catalog[0].apps[].name; . as $name
                    | $shown | index($name) != null))
            and ([.rows[] | select(.tag == "Available") | .name] as $available
                | all($available[]; . as $name
                    | any($catalog[0].apps[]; .name == $name)))
            # Package-owned helper launchers are implementation details, not
            # products. Prove the running image filters the exact known ids
            # while retaining the useful hardware viewer under a plain name.
            and (all(.rows[] | select(.tag == "Installed");
                .action.entry.id as $id
                | (["footclient", "foot-server", "thunar-settings",
                  "thunar-bulk-rename", "xfce4-about", "bssh", "bvnc",
                  "avahi-discover"] | index($id)) == null))
            and all(.rows[] | select(.tag == "Installed"
                and .action.entry.id == "lstopo"
                ); .name == "Hardware Information")
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
for t in commandcenter systemcontrol notifications shortcuts aipanel overview session; do
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
    # actually instantiated with the signed eight-app catalog.
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
if jq -e '.active == "daybreak" and .writable == true' \
        /run/punar/surfaces-wallpaper-state.json >/dev/null 2>&1; then
    note "ok   wallpaper starts on the writable Daybreak default"
else
    note "FAIL wallpaper state is not the writable Daybreak default"
    FAILED=1
fi

ipc wallpaper list > /run/punar/surfaces-wallpapers.json 2>/dev/null
if jq -e '.default == "daybreak"
        and (.wallpapers | length) == 10
        and ([.wallpapers[].id] | sort) == (["crater-lake", "daybreak", "earthrise", "field", "grand-canyon", "rainier", "stillpoint", "winterline", "yosemite", "zion"] | sort)' \
        /run/punar/surfaces-wallpapers.json >/dev/null 2>&1; then
    note "ok   wallpaper catalog exposes the ten shipped choices"
else
    note "FAIL wallpaper catalog does not expose exactly the four rasters, Field and the five topographic plates"
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

# A plate is a TEMPLATE, not a raster, so its invariants differ from a JPEG's:
# it must carry all three substitutions (or a theme switch cannot colour it) and
# no <text> (or it renders wrong before fonts load). The digest catches drift the
# same way the raster check does.
wallpaper_plate() {
    wp_name="$1"
    wp_expected="$2"
    wp_path="/usr/share/punar/shell/Wallpaper/plates/${wp_name}.svg.in"
    wp_actual="$(sha256sum "${wp_path}" 2>/dev/null | cut -d' ' -f1)"
    if [ "${wp_actual}" != "${wp_expected}" ]; then
        note "FAIL ${wp_name} plate is missing or altered (sha='${wp_actual}')"
        FAILED=1
        return
    fi
    for wp_token in __FIELD__ __HAIRLINE__ __EMPHASIS__; do
        if ! grep -qF "${wp_token}" "${wp_path}"; then
            note "FAIL ${wp_name} plate is missing the ${wp_token} substitution"
            FAILED=1
            return
        fi
    done
    # From <svg onward only. The plate's header comment explains that it carries
    # no text element, and scanning the whole file matched that sentence — a
    # check that fails because the file says it does not do the thing.
    if sed -n '/<svg/,$p' "${wp_path}" | grep -qE '<text[ >/]'; then
        note "FAIL ${wp_name} plate carries a text element; it must render before fonts load"
        FAILED=1
        return
    fi
    note "ok   ${wp_name} plate is the shipped three-substitution template"
}

wallpaper_plate yosemite 368d7ed76c911387ed032698c3906b17a63b71012db13eff71ba54c584bee198
wallpaper_plate grand-canyon 50d2b675bd4bf68146388cd9cf22e610067233294ba4561fe70075c69d7d6aa5
wallpaper_plate rainier de3d8b85b249b75ac93d011709d20cc4bdd74602d79b779833d08b64cebfd304
wallpaper_plate crater-lake 57235e8bb858d5ed2daf6b418a084d14fd30288ca382535c13dcd958887d56a7
wallpaper_plate zion 73e21fcac910732c2d311f31adb924270098b977bde2f3e3286ec25261064369

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
if jq -e '.applied == true and .active == "daybreak" and .source == "shipped default"' \
        /run/punar/surfaces-wallpaper-reset.json >/dev/null 2>&1; then
    note "ok   wallpaper.reset restores the shipped Daybreak default"
else
    note "FAIL wallpaper.reset did not restore the shipped Daybreak default"
    FAILED=1
fi

wallpaper_row="$(ipc commandcenter query wallpaper | tr -d '\r\n\"')"
check_eq "command center exposes wallpaper as a typed action" \
    "wallpaper · SetWallpaper(daybreak) · current" "${wallpaper_row}"
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
launch_row="$(ipc commandcenter query browser | tr -d '\r\n\"')"
check_eq "command center finds the generic Browser" "app · Launch(punar-browser)" "${launch_row}"

launch_result="$(ipc commandcenter run | tr -d '\r\n\"')"
check_eq "command center invokes the selected installed app" "app · Launch(punar-browser)" "${launch_result}"

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

# The browser must also be a NATIVE WAYLAND client with the closed Punar argv.
# Read the live process because a desktop file can exist while pointing at a
# stale or bypass launcher. This path is the generic Browser entry used by the
# command center, xdg-open and PUNAR+B; all three reach the same builder.
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
                *) note "FAIL chromium argv missing ${flag} — closed browser defaults were not applied"
                   FAILED=1 ;;
            esac
        done
        case " ${cargs} " in
            *" /usr/lib/chromium/chromium "*) note "ok   browser bypasses mutable distribution flag wrappers" ;;
            *) note "FAIL browser did not execute the fixed Chromium binary path"
               FAILED=1 ;;
        esac
        printf '%s\n' "${cargs}" > /run/punar/surfaces-chromium-argv.txt
    else
        note "FAIL could not read chromium argv (pid='${cpid}')"
        FAILED=1
    fi

    # THE MENUBAR TRACKS WHAT IS RUNNING. With a browser on screen and
    # focused, the bar's left zone must name it. This is asserted as a
    # relation between two independent readings of the live session — the
    # stable technical class Hyprland reports and the generic product role the
    # bar maps it to — so it cannot pass by rendering a constant, and it fails
    # if the bar stops following focus.
    hyprctl dispatch "hl.dsp.focus({ window = 'class:^([Cc]hromium.*)$' })" >/dev/null 2>&1
    bar_names_focus() {
        hy="$(hyprctl -j activewindow 2>/dev/null | jq -r '.class // ""' | tr '[:upper:]' '[:lower:]')"
        br="$(ipc bar app | tr -d '[:space:]"' | tr '[:upper:]' '[:lower:]')"
        case "${hy}" in
            *chromium*) [ "${br}" = "browser" ] ;;
            *) return 1 ;;
        esac
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

# A graphical editor, a terminal editor, and the file manager are product
# paths, not merely packages in the image. Exercise the same command-center
# query + Enter route used above so a broken Terminal=true adapter or desktop
# entry cannot pass the image build unnoticed.
geany_row="$(ipc commandcenter query geany | tr -d '\r\n\"')"
check_eq "command center finds the graphical text editor" "app · Application(geany) · installed · open" "${geany_row}"
geany_result="$(ipc commandcenter run | tr -d '\r\n\"')"
check_eq "command center launches the graphical text editor" "app · Application(geany) · installed · open" "${geany_result}"
geany_client() {
    hyprctl -j clients 2>/dev/null \
        | jq -e 'any(.[]; .class | ascii_downcase | test("geany"))'
}
if wait_for 90 geany_client; then
    note "ok   graphical text editor window appeared"

    # Selecting an application is also task switching. Put the existing
    # editor on workspace 8, leave it for workspace 9, then select Geany
    # through Command Center a second time. The shell must focus the existing
    # toplevel (which switches workspaces) and must not spawn a duplicate.
    geany_address="$(hyprctl -j clients 2>/dev/null \
        | jq -r '[.[] | select(.class | ascii_downcase | test("geany"))][0].address // ""')"
    geany_pid="$(hyprctl -j clients 2>/dev/null \
        | jq -r '[.[] | select(.class | ascii_downcase | test("geany"))][0].pid // 0')"
    hyprctl dispatch "hl.dsp.focus({ window = 'address:${geany_address}' })" >/dev/null 2>&1 || true
    hyprctl dispatch "hl.dsp.window.move({ workspace = '8' })" >/dev/null 2>&1 || true
    hyprctl dispatch "hl.dsp.focus({ workspace = '9' })" >/dev/null 2>&1 || true

    geany_moved() {
        hyprctl -j clients 2>/dev/null \
            | jq -e --arg address "${geany_address}" \
                'any(.[]; .address == $address and .workspace.id == 8)' \
                >/dev/null 2>&1
    }
    if wait_for 20 geany_moved; then
        note "ok   existing editor isolated on workspace 8 before app selection"
    else
        note "FAIL could not place the existing editor on workspace 8"
        FAILED=1
    fi

    geany_switch_row="$(ipc commandcenter query geany | tr -d '\r\n\"')"
    check_eq "installed editor remains an open action" \
        "app · Application(geany) · installed · open" "${geany_switch_row}"
    geany_switch_result="$(ipc commandcenter run | tr -d '\r\n\"')"
    check_eq "selecting an open editor invokes its installed-app action" \
        "app · Application(geany) · installed · open" "${geany_switch_result}"

    geany_focused_without_duplicate() {
        active_workspace="$(hyprctl -j activeworkspace 2>/dev/null | jq -r '.id // 0')"
        client_state="$(hyprctl -j clients 2>/dev/null \
            | jq -r --arg address "${geany_address}" --argjson pid "${geany_pid}" \
                '[.[] | select(.class | ascii_downcase | test("geany"))] as $apps
                 | [($apps | length),
                    (any($apps[]; .address == $address and .pid == $pid)),
                    (any($apps[]; .address == $address and .workspace.id == 8))]
                 | @tsv')"
        [ "${active_workspace}" = "8" ] \
            && [ "${client_state}" = "$(printf '1\ttrue\ttrue')" ]
    }
    if wait_for 30 geany_focused_without_duplicate; then
        note "ok   selecting an open app switched to workspace 8 without launching a duplicate"
    else
        note "FAIL selecting an open app did not focus its workspace exactly once"
        hyprctl -j clients > /run/punar/surfaces-geany-focus-failure.json 2>/dev/null || true
        FAILED=1
    fi

    hyprctl dispatch "hl.dsp.window.close({ window = 'address:${geany_address}' })" >/dev/null 2>&1 || true
    hyprctl dispatch "hl.dsp.focus({ workspace = '1' })" >/dev/null 2>&1 || true
else
    note "FAIL Geany was selected in Command Center but no editor window appeared"
    FAILED=1
fi

foot_count() {
    hyprctl -j clients 2>/dev/null \
        | jq '[.[] | select(.class | ascii_downcase | test("foot"))] | length'
}
foot_before="$(foot_count)"
nvim_row="$(ipc commandcenter query nvim | tr -d '\r\n\"')"
check_eq "command center finds Neovim as a terminal editor" "app · Application(nvim) · installed · open" "${nvim_row}"
nvim_result="$(ipc commandcenter run | tr -d '\r\n\"')"
check_eq "command center routes Neovim through a terminal" "app · Application(nvim) · installed · open" "${nvim_result}"
nvim_client() {
    [ "$(foot_count)" -gt "${foot_before}" ]
}
if wait_for 90 nvim_client; then
    note "ok   Neovim opened in a new Foot window"
    hyprctl dispatch "hl.dsp.focus({ window = 'class:^(foot|Foot)$' })" >/dev/null 2>&1 || true
    hyprctl dispatch "hl.dsp.window.close()" >/dev/null 2>&1 || true
else
    note "FAIL Neovim was selected in Command Center but no terminal window appeared"
    FAILED=1
fi

files_row="$(ipc commandcenter query thunar | tr -d '\r\n\"')"
check_eq "command center finds the file manager" "app · Application(thunar) · installed · open" "${files_row}"
files_result="$(ipc commandcenter run | tr -d '\r\n\"')"
check_eq "command center launches the file manager" "app · Application(thunar) · installed · open" "${files_result}"
files_client() {
    hyprctl -j clients 2>/dev/null \
        | jq -e 'any(.[]; .class | ascii_downcase | test("thunar"))'
}
if wait_for 90 files_client; then
    note "ok   Files window appeared"
    hyprctl dispatch "hl.dsp.focus({ window = 'class:^(thunar|Thunar)$' })" >/dev/null 2>&1 || true
    hyprctl dispatch "hl.dsp.window.close()" >/dev/null 2>&1 || true
else
    note "FAIL Files was selected in Command Center but no file-manager window appeared"
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

# URI activation can be delegated to a D-Bus-activated portal.  That service
# inherits the systemd user manager's environment, not Hyprland's process
# environment.  The mutable application desktop entries and scheme defaults
# therefore have to be imported into the manager or an installed Claude app
# leaves its OAuth callback in the browser.
user_environment="$(systemctl --user show-environment 2>/dev/null)"
if printf '%s\n' "${user_environment}" \
    | grep -Fq 'XDG_DATA_DIRS=' \
    && printf '%s\n' "${user_environment}" \
        | grep -F 'XDG_DATA_DIRS=' \
        | grep -Fq '/var/lib/punar-applications'; then
    note "ok   user manager sees the mutable application data root"
else
    note "FAIL user manager cannot see the mutable application data root"
    FAILED=1
fi
if printf '%s\n' "${user_environment}" \
    | grep -Fq 'XDG_CONFIG_DIRS=' \
    && printf '%s\n' "${user_environment}" \
        | grep -F 'XDG_CONFIG_DIRS=' \
        | grep -Fq '/var/lib/punar-applications/config'; then
    note "ok   user manager sees the mutable application handler defaults"
else
    note "FAIL user manager cannot see the mutable application handler defaults"
    FAILED=1
fi

for scheme in x-scheme-handler/https x-scheme-handler/http text/html; do
    handler="$(xdg-mime query default "${scheme}" 2>/dev/null | tr -d '[:space:]')"
    check_eq "default handler for ${scheme}" "punar-browser.desktop" "${handler}"
done

directory_handler="$(xdg-mime query default inode/directory 2>/dev/null | tr -d '[:space:]')"
check_eq "default handler for directories" "thunar.desktop" "${directory_handler}"

# The handler must name a desktop entry that EXISTS. xdg-open fails through a
# dangling handler silently, which looks identical to having no default at all.
if [ -f /usr/local/share/applications/punar-browser.desktop ]; then
    note "ok   punar-browser.desktop present at /usr/local/share/applications"
else
    note "FAIL punar-browser.desktop missing — the default handler is dangling"
    FAILED=1
fi
if [ -f /usr/local/share/applications/chromium.desktop ] \
        && grep -Fxq 'NoDisplay=true' /usr/local/share/applications/chromium.desktop \
        && grep -Fxq 'Exec=punarctl web-apps browse %U' /usr/local/share/applications/chromium.desktop; then
    note "ok   vendor Chromium desktop id is hidden and routes through Punar"
else
    note "FAIL vendor Chromium desktop id is not safely shadowed"
    FAILED=1
fi

for entry in geany.desktop nvim.desktop thunar.desktop; do
    if [ -f "/usr/share/applications/${entry}" ]; then
        note "ok   ${entry} present at /usr/share/applications"
    else
        note "FAIL ${entry} missing — Command Center would expose a dead product path"
        FAILED=1
    fi
done

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

# --- group 8b: a correct passphrase actually unlocks the session ------------
#
# THE HOLE THIS CLOSES. Group 8 above asserts that the lock's PAM stack FILE
# exists, and its own comment admitted the rest: "not a lock/unlock round trip:
# submit() is unreachable over IPC". So nothing had ever proven the single
# property the lock screen exists for — that the right passphrase gets you back
# in. A session that could never be unlocked passed every gate in this file.
# The owner found that by living with it, which is the worst way to find it.
#
# `lock submit` reaches the ordinary PAM conversation and exists only where
# /usr/lib/punar/lock-exercise.allow does — this image. check-release-image.sh
# A15 fails the build if that marker reaches a release tree.
#
# WHAT THIS GATE DOES NOT COVER, stated because the gap is the interesting part.
# This image's `punar` account is created with useradd + chpasswd, so its
# password lives in /etc/shadow. A real machine's account does NOT: onboarding
# writes a systemd userdb record (punar-onboard identity.rs) and there is no
# /etc/shadow entry at all. pam_unix resolves those through different paths —
# unix_chkpwd against files here, nss-systemd against userdb there — so a green
# result below proves the lock surface, its PAM stack and the round trip, and
# says NOTHING about whether a userdb-backed account can be unlocked.
#
# That distinction is not academic: it is the remaining live hypothesis for the
# owner's machine, where the greeter (root, pam_exec plus pam_unix) accepts the
# password and this surface (unprivileged, pam_unix alone) rejects it. Closing
# that needs a dev session user that is itself a userdb account, which is a
# larger change to this image than this gate.
#
# The dev user's password is set by mkosi.profiles/dev/mkosi.postinst.chroot.
lock_password="punar"
lock_wrong="definitely-not-the-passphrase"

ipc lock lock >/dev/null 2>&1
lock_waited=0
while [ "${lock_waited}" -lt 10 ] && [ "$(ipc lock state | tr -d '[:space:]"')" != "locked" ]; do
    sleep 1
    lock_waited=$((lock_waited + 1))
done
check_eq "lock.state after lock" "locked" "$(ipc lock state | tr -d '[:space:]"')"

# NEGATIVE LEG FIRST, and it is the one that must never regress: if a wrong
# passphrase unlocked the session, the positive leg below would pass on a
# machine with no authentication at all.
wrong_result="$(ipc lock submit "${lock_wrong}" | tr -d '[:space:]"')"
check_eq "lock.submit is available in this image" "submitted" "${wrong_result}"
sleep 3
check_eq "lock.state after a WRONG passphrase" "locked" "$(ipc lock state | tr -d '[:space:]"')"

# POSITIVE LEG: the correct passphrase must open the session.
ipc lock submit "${lock_password}" >/dev/null 2>&1
unlock_waited=0
while [ "${unlock_waited}" -lt 15 ] && [ "$(ipc lock state | tr -d '[:space:]"')" != "unlocked" ]; do
    sleep 1
    unlock_waited=$((unlock_waited + 1))
done
unlock_state="$(ipc lock state | tr -d '[:space:]"')"
if [ "${unlock_state}" = "unlocked" ]; then
    note "ok   the CORRECT passphrase unlocked the session after ${unlock_waited}s"
else
    note "FAIL the correct passphrase did not unlock the session (state '${unlock_state}')"
    FAILED=1
fi

# Everything after this group assumes an unlocked session, and a machine left
# locked here would fail the rest of the file for a reason that has nothing to
# do with what those groups test.
check_eq "lock.state at the end of the round trip" "unlocked" "$(ipc lock state | tr -d '[:space:]"')"

# --- group 8d: the lock's frosted glass samples the wallpaper ---------------
#
# THE BUG THIS WOULD HAVE CAUGHT. The lock surface blurs the active wallpaper
# behind its text. It shipped drawing a flat cream rectangle instead: the
# source Image was `visible: false`, an item that is never rendered is not a
# texture provider, so MultiEffect sampled nothing and only the scrim reached
# the screen. Every assertion in this file passed. A human found it by looking
# at a screenshot, which is the failure mode this suite exists to prevent.
#
# THE TEST. If the effect samples the wallpaper, the locked frame depends on
# which wallpaper is active. If it samples nothing, the locked frame is the
# same flat scrim whichever wallpaper is set. So: lock under wallpaper A,
# again under A, and again under B.
#
#   sha(A) != sha(A2)  -> the frame is not stable (the lock clock shows HH:MM
#                         and a minute rolled over). INCONCLUSIVE, not a
#                         verdict — the control is what makes the rest safe.
#   sha(A) == sha(A2) != sha(B) -> the wallpaper reaches the surface. PASS.
#   sha(A) == sha(A2) == sha(B) -> two different wallpapers produce an
#                         identical locked screen. That is the bug. FAIL.
#
# ANSWERED ON THE FIRST RUN, and worth writing down because it decides whether
# any visual assertion about the lock is possible at all: wlr-screencopy DOES
# capture while an ext-session-lock-v1 surface holds the session under Hyprland
# 0.56.2. All three frames came back at ~25 KB and legible. The refused-capture
# branch below stays, because that is a compositor behaviour rather than a
# guarantee, and a future one may differ.
lock_frost_capture() {
    # $1 = wallpaper id, $2 = output path. Sets the wallpaper, locks, captures,
    # unlocks. Prints the frame's sha256, or nothing if anything refused.
    ipc wallpaper set "$1" >/dev/null 2>&1 || return 1
    lf_waited=0
    while [ "${lf_waited}" -lt 5 ] \
            && [ "$(ipc wallpaper state | jq -r '.active' 2>/dev/null)" != "$1" ]; do
        sleep 1
        lf_waited=$((lf_waited + 1))
    done
    [ "$(ipc wallpaper state | jq -r '.active' 2>/dev/null)" = "$1" ] || return 1

    ipc lock lock >/dev/null 2>&1
    lf_waited=0
    while [ "${lf_waited}" -lt 10 ] && [ "$(ipc lock state | tr -d '[:space:]"')" != "locked" ]; do
        sleep 1
        lf_waited=$((lf_waited + 1))
    done
    [ "$(ipc lock state | tr -d '[:space:]"')" = "locked" ] || return 1
    # The surface animates in over the shared 300 ms curve; two seconds is the
    # same headroom the painted-pixels probe above allows.
    sleep 2
    rm -f "$2"
    grim "$2" 2>/dev/null || true

    ipc lock submit "${lock_password}" >/dev/null 2>&1
    lf_waited=0
    while [ "${lf_waited}" -lt 15 ] && [ "$(ipc lock state | tr -d '[:space:]"')" != "unlocked" ]; do
        sleep 1
        lf_waited=$((lf_waited + 1))
    done
    [ "$(ipc lock state | tr -d '[:space:]"')" = "unlocked" ] || return 1
    [ -s "$2" ] || return 1
    sha256sum "$2" | cut -d" " -f1
}

# Vacuity guard: this needs two RASTER wallpapers. A vector plate takes a
# different path through the surface entirely (`showsPhoto` is false), so
# comparing a plate against a photograph would prove nothing about the blur.
lock_frost_rasters="$(ipc wallpaper list \
    | jq -r '[.wallpapers[] | select(.vector == false) | .id] | .[0:2] | join(" ")' 2>/dev/null)"
lock_frost_a="$(printf "%s" "${lock_frost_rasters}" | cut -d" " -f1)"
lock_frost_b="$(printf "%s" "${lock_frost_rasters}" | cut -d" " -f2)"
lock_frost_restore="$(ipc wallpaper state | jq -r ".active" 2>/dev/null)"

if [ -z "${lock_frost_a}" ] || [ -z "${lock_frost_b}" ] || [ "${lock_frost_a}" = "${lock_frost_b}" ]; then
    note "info fewer than two raster wallpapers ship; the frosted-glass comparison did not run"
else
    lock_sha_a="$(lock_frost_capture "${lock_frost_a}" /run/punar/lock-frost-a.png)"
    lock_sha_a2="$(lock_frost_capture "${lock_frost_a}" /run/punar/lock-frost-a2.png)"
    lock_sha_b="$(lock_frost_capture "${lock_frost_b}" /run/punar/lock-frost-b.png)"

    if [ -z "${lock_sha_a}" ] || [ -z "${lock_sha_a2}" ] || [ -z "${lock_sha_b}" ]; then
        note "info could not capture a frame while the session was locked; the frosted-glass"
        note "info claim is UNPROVEN on this run. wlr-screencopy may refuse while an"
        note "info ext-session-lock surface holds the session — that is a fact worth having."
    elif [ "${lock_sha_b}" = "${lock_sha_a}" ] || [ "${lock_sha_b}" = "${lock_sha_a2}" ]; then
        note "FAIL a second wallpaper produced a locked screen identical to the first — the"
        note "FAIL lock surface is drawing its scrim and nothing else (lock-frost-*.png)"
        FAILED=1
    else
        note "ok   the locked screen under '${lock_frost_b}' matches neither capture under '${lock_frost_a}', so the field samples the wallpaper"
    fi

    # WHY B IS COMPARED AGAINST BOTH A CAPTURES rather than against one, and why
    # there is no INCONCLUSIVE branch any more.
    #
    # Something on this surface varies between captures independently of the
    # wallpaper — the first run produced two different frames under the SAME
    # wallpaper — and the password field carries a blinking caret, which is the
    # obvious candidate but is not established. Whatever it is, an earlier
    # version reported INCONCLUSIVE whenever it moved, which on a working frost
    # would have meant a gate that can never reach a clean pass: the worst
    # outcome, because it reads as coverage.
    #
    # Two captures under wallpaper A bound that variation instead of arguing
    # about it. If the wallpaper reached the surface, B cannot match either of
    # them; if it did not, B is one of them. The residual risk is a periodic
    # element slower than the gap between captures, which would let A and A2
    # land in the same phase — recorded here rather than papered over.
    if [ "${lock_sha_a}" != "${lock_sha_a2}" ]; then
        note "info the two captures under '${lock_frost_a}' differ, so something on this"
        note "info surface varies independently of the wallpaper; the comparison above"
        note "info accounts for it by testing B against both."
    fi

    # Whatever the verdict, copy the surface's own account of what it resolved
    # into the report. When this comparison fails the next question is always
    # "did the photo branch run, and did the Image load", and that answer should
    # not require anyone to go and find a journal.
    #
    # READ OVER IPC, NOT OUT OF THE JOURNAL. The first version of this grepped
    # `journalctl --user`, captured nothing, and said nothing about having
    # captured nothing — the shell is `exec`d from greetd, so its stderr lands
    # in the system journal, which the punar user running this script cannot
    # read. Silent instrumentation is worse than none.
    lock_field="$(ipc lock field | tr -d '"')"
    case "${lock_field}" in
        refused)    note "FAIL lock.field refused; the exercise marker is missing from a dev image"
                    FAILED=1 ;;
        unreported) note "info the lock field never reported; it was never constructed" ;;
        "")         note "FAIL lock.field returned nothing at all"
                    FAILED=1 ;;
        *)          note "info lock field · ${lock_field}" ;;
    esac

    if [ -n "${lock_frost_restore}" ] && [ "${lock_frost_restore}" != "null" ]; then
        ipc wallpaper set "${lock_frost_restore}" >/dev/null 2>&1 || true
    else
        ipc wallpaper reset >/dev/null 2>&1 || true
    fi
    check_eq "the wallpaper is restored after the frost comparison" \
        "${lock_frost_restore}" "$(ipc wallpaper state | jq -r ".active" 2>/dev/null)"
fi

# --- group 8c: creating a workspace by pointer ------------------------------
# Overview's "+ New project" control focuses the lowest unused workspace id,
# because focusing a workspace that does not exist is what creates it. The
# button's wiring is QML that qmllint checks structurally; what needs proving on
# a running machine is that premise. A pointer click is not reachable over IPC,
# so this exercises the dispatch the click performs, and says so.
ws_free="$(hyprctl -j workspaces 2>/dev/null \
    | jq -r '[.[].id] as $t | first(range(1; 64) | select(. as $i | ($t | index($i)) | not))')"
if [ -n "${ws_free}" ] && [ "${ws_free}" -gt 0 ] 2>/dev/null; then
    hyprctl dispatch "hl.dsp.focus({ workspace = '${ws_free}' })" >/dev/null 2>&1 || true
    ws_created() {
        hyprctl -j workspaces 2>/dev/null \
            | jq -e --argjson id "${ws_free}" 'any(.[]; .id == $id)' >/dev/null
    }
    if wait_for 15 ws_created; then
        note "ok   focusing free workspace ${ws_free} created it (the New project dispatch)"
    else
        note "FAIL focusing free workspace ${ws_free} did not create it; New project would do nothing"
        FAILED=1
    fi
    hyprctl dispatch "hl.dsp.focus({ workspace = '1' })" >/dev/null 2>&1 || true
else
    note "FAIL could not find a free workspace id to exercise"
    FAILED=1
fi

# --- group 9: an unattended session locks itself ----------------------------
# The lock surface and its PAM stack existed long before anything invoked them
# on their own: locking was always a deliberate act (PUNAR + Escape), so a
# walked-away machine stayed open. hypridle now closes that.
#
# The shipped policy is a ten-minute timeout, which no gate can wait for, and
# firing it for real would lock the session out from under every later
# exercise. So the two halves are proven separately: the POLICY is asserted
# from the shipped config, and the MECHANISM is proven live below with a
# throwaway listener. What is deliberately NOT proven here is the composition —
# that the shipped ten-minute listener reaches the lock. That needs a human or
# a dedicated long-idle run.
IDLE_CONF=/etc/xdg/hypr/punar-hypridle.conf
if pgrep -u "$(id -un)" -f "hypridle -c ${IDLE_CONF}" >/dev/null 2>&1; then
    note "ok   hypridle runs in the session against the shipped system config"
else
    note "FAIL no hypridle is running against ${IDLE_CONF}; an idle session never locks"
    FAILED=1
fi

if [ -f "${IDLE_CONF}" ] && [ ! -w "${IDLE_CONF}" ]; then
    note "ok   idle policy is present and not writable by the session user"
else
    note "FAIL ${IDLE_CONF} is missing or writable by $(id -un); auto-lock could be edited away"
    FAILED=1
fi

# Only that a listener exists. This image ships a CI override with a day-long
# timeout, because the product's ten minutes locks the session out from under
# the exercises. The product's bound is asserted by check-release-image.sh
# against the release tree, where nothing overrides it — asserting it here
# would only ever prove the override.
idle_timeout="$(awk '/^[[:space:]]*timeout[[:space:]]*=/ {print $3; exit}' "${IDLE_CONF}" 2>/dev/null)"
if [ -n "${idle_timeout}" ] && [ "${idle_timeout}" -gt 0 ]; then
    note "ok   an idle listener is configured (${idle_timeout}s in this image)"
else
    note "FAIL no idle listener is configured at all"
    FAILED=1
fi

if grep -qE '^[[:space:]]*lock_cmd[[:space:]]*=.*ipc call lock lock' "${IDLE_CONF}" 2>/dev/null; then
    note "ok   idle policy locks through the shell's own lock surface"
else
    note "FAIL idle policy does not route locking to the Punar lock surface"
    FAILED=1
fi

# The packaged unit carries no -c, so an enabled copy would both duplicate the
# daemon and fail against a user config this image does not ship.
if find /usr/lib/systemd/user /etc/systemd/user -name 'hypridle.service' -path '*.wants/*' 2>/dev/null | grep -q .; then
    note "FAIL the packaged hypridle.service is enabled; it would duplicate the session daemon"
    FAILED=1
else
    note "ok   the packaged hypridle.service stays disabled"
fi

# MECHANISM, live: a throwaway listener with a two-second timeout proves the
# compositor actually delivers ext-idle-notify-v1 to a hypridle client in this
# session. It touches a file instead of locking, so the gate stays usable.
idle_probe_conf=/run/punar/surfaces-idle-probe.conf
idle_probe_flag=/run/punar/surfaces-idle-probe.fired
rm -f "${idle_probe_flag}"
cat > "${idle_probe_conf}" <<PROBE
listener {
    timeout = 2
    on-timeout = touch ${idle_probe_flag}
}
PROBE
hypridle -c "${idle_probe_conf}" >/dev/null 2>&1 &
idle_probe_pid=$!
idle_waited=0
while [ "${idle_waited}" -lt 20 ] && [ ! -e "${idle_probe_flag}" ]; do
    sleep 1
    idle_waited=$((idle_waited + 1))
done
kill "${idle_probe_pid}" 2>/dev/null || true
wait "${idle_probe_pid}" 2>/dev/null || true
if [ -e "${idle_probe_flag}" ]; then
    note "ok   the compositor delivered an idle notification to hypridle after ${idle_waited}s"
else
    note "FAIL no idle notification reached hypridle within 20s; the idle path is dead"
    FAILED=1
fi
rm -f "${idle_probe_conf}" "${idle_probe_flag}"

# --- group 9b: the power buttons are actually AUTHORIZED to act -------------
#
# THE GAP THIS CLOSES, and it shipped: the session menu's Restart button did
# nothing on the owner's machine. Every static gate passed — the QML parses, the
# row activates, the argv is fixed and correct — because the failure was one
# layer further down: `systemctl reboot` is a POLKIT-MEDIATED request, and a
# caller polkit does not consider an active local session gets "Interactive
# authentication required" on a stderr nobody collected.
#
# ASK FROM INSIDE THE SESSION, and the reason is the first version of this group
# getting it wrong. This script runs from punar-surfaces-check.service — a
# SYSTEM service with User=punar and no PAMName, so the process has no logind
# session of its own. polkit judges the CALLER, so asking from here measures a
# subject that is not the one pressing the button, and the first run reported
# "challenge" for a machine whose button may well work. Worse, the session-active
# check that was supposed to catch that borrowed the graphical session's id
# through a `${XDG_SESSION_ID:-$(...)}` fallback and passed — a control that
# cannot fail is not a control.
#
# So the assertion is made from a child of the COMPOSITOR, re-entered through
# `hyprctl dispatch` exactly as group 2 re-enters the surface bindings. The
# service-context answer is kept as an info line: the contrast between the two
# is the evidence for which subject polkit is judging.
mkdir -p /run/punar
rm -f /run/punar/canpower.txt

# The facts a failure needs in order to name its own cause, rather than leaving
# a reader to guess between "no rule", "no authority" and "wrong subject".
POWER_RULE=/usr/share/polkit-1/rules.d/50-punar-power.rules
if [ -f "${POWER_RULE}" ]; then
    note "ok   the Punar power policy rule is installed ($(wc -c < "${POWER_RULE}" | tr -d ' ') bytes)"
else
    note "FAIL ${POWER_RULE} is not in this image; nothing grants the desktop user power actions"
    FAILED=1
fi
polkit_unit=none
for candidate in polkit.service polkitd.service; do
    if systemctl is-active --quiet "${candidate}" 2>/dev/null; then
        polkit_unit="${candidate}"
        break
    fi
done
note "# polkit authority unit: ${polkit_unit} (D-Bus activated; 'none' only means not running right now)"

# The service context, recorded but NOT asserted on.
service_session="${XDG_SESSION_ID:-none}"
graphical_session="$(loginctl --value show-user "$(id -u)" -p Display 2>/dev/null)"
session_active="$(loginctl show-session "${graphical_session}" -p Active --value 2>/dev/null)"
session_count="$(loginctl list-sessions --no-legend 2>/dev/null | wc -l | tr -d ' ')"
note "# checker session='${service_session}' graphical session='${graphical_session}' active='${session_active}' sessions=${session_count}"

# A graphical session logind does not consider active is the single most common
# reason a desktop's power buttons stop working, and it is invisible from inside
# the shell. Assert it on the session the BUTTON runs in.
check_eq "logind considers the graphical session active" "yes" "${session_active}"

cat > /run/punar/canpower.sh <<'POWERPROBE'
#!/bin/sh
# Runs as a child of Hyprland, so its polkit subject is the session the session
# menu's rows actually run in. logind answers CanReboot/CanPowerOff for the
# CALLER over the same rules `systemctl reboot` consults, which is how this asks
# "would the row work" without rebooting the machine to find out.
exec > /run/punar/canpower.txt 2>&1
printf 'session=%s\n' "${XDG_SESSION_ID:-none}"
for verb in CanReboot CanPowerOff; do
    printf '%s=%s\n' "${verb}" "$(busctl --system call org.freedesktop.login1 \
        /org/freedesktop/login1 org.freedesktop.login1.Manager "${verb}" 2>/dev/null \
        | tr -d '"' | awk '{print $2}')"
done
# THE ACTION THE PUNAR RULE ACTUALLY GRANTS, asked by name.
#
# CanReboot alone is a weak discriminator: with a single session logind consults
# org.freedesktop.login1.reboot, whose SHIPPED default is already
# allow_active=yes, so it answers "yes" on an image carrying no Punar rule at
# all. Whether the stronger `-multiple-sessions` action is reached depends on
# another user happening to hold a session — machine state, not a property of
# the fix. Asking polkit about that action by name removes the dependence: it is
# auth_admin_keep in the shipped policy and YES only because
# 50-punar-power.rules says so.
if command -v pkcheck >/dev/null 2>&1; then
    pkcheck --action-id org.freedesktop.login1.reboot-multiple-sessions \
        --process "$$" >/dev/null 2>&1
    printf 'pkcheck_multiple_sessions=%s\n' "$?"
else
    printf 'pkcheck_multiple_sessions=absent\n'
fi
loginctl list-sessions --no-legend 2>/dev/null | tr -s ' ' | cut -d' ' -f1-4 \
    | while IFS= read -r row; do printf 'session_row=%s\n' "${row}"; done
POWERPROBE
chmod +x /run/punar/canpower.sh
hyprctl dispatch "hl.dsp.exec_cmd('/run/punar/canpower.sh')" >/dev/null 2>&1

power_probe_waited=0
while [ "${power_probe_waited}" -lt 20 ] && [ ! -s /run/punar/canpower.txt ]; do
    sleep 1
    power_probe_waited=$((power_probe_waited + 1))
done

if [ ! -s /run/punar/canpower.txt ]; then
    note "FAIL the in-session power probe produced nothing after 20s; logind was not asked from the session"
    FAILED=1
else
    note "# in-session probe: $(tr '\n' ' ' < /run/punar/canpower.txt)"
    for power_verb in CanReboot CanPowerOff; do
        power_verdict="$(sed -n "s/^${power_verb}=//p" /run/punar/canpower.txt)"
        case "${power_verdict}" in
            yes)
                note "ok   logind ${power_verb} = yes from inside the session (the menu row acts unprompted)"
                ;;
            challenge)
                note "FAIL logind ${power_verb} = challenge from inside the session; the row would need a polkit password dialog the session menu cannot show"
                FAILED=1
                ;;
            "")
                note "FAIL logind ${power_verb} returned nothing from inside the session; logind is not answering"
                FAILED=1
                ;;
            *)
                note "FAIL logind ${power_verb} = ${power_verdict} from inside the session; the row would be refused"
                FAILED=1
                ;;
        esac
    done

    # The action that is authorized ONLY because of the Punar rule. Exit 0 is
    # "authorized"; anything else is polkit declining to say yes without a
    # password, which is the state the session menu cannot recover from.
    pkcheck_result="$(sed -n 's/^pkcheck_multiple_sessions=//p' /run/punar/canpower.txt)"
    case "${pkcheck_result}" in
        0)
            note "ok   polkit authorizes reboot-multiple-sessions for the session (50-punar-power.rules is in force)"
            ;;
        absent)
            note "info pkcheck is not installed, so the -multiple-sessions action could not be asked by name; the CanReboot legs above are then only as strong as this machine's session count"
            ;;
        "")
            note "FAIL the in-session probe reported no pkcheck result at all"
            FAILED=1
            ;;
        *)
            note "FAIL polkit does not authorize reboot-multiple-sessions (pkcheck exit ${pkcheck_result}); the shipped auth_admin_keep default is still in force, so 50-punar-power.rules is absent or is not being applied"
            FAILED=1
            ;;
    esac
    sed -n 's/^session_row=/# logind session row: /p' /run/punar/canpower.txt >> "${REPORT}"
fi

# The same question from THIS process, which has no session. Recorded because
# the two answers differing is the proof that polkit is judging the subject and
# not the machine — and because a future reader will otherwise repeat the
# mistake this group was born from.
outside_verdict="$(busctl --system call org.freedesktop.login1 /org/freedesktop/login1 \
    org.freedesktop.login1.Manager CanReboot 2>/dev/null | tr -d '"' | awk '{print $2}')"
note "# CanReboot from the sessionless service context: ${outside_verdict:-no answer} (not asserted on)"

# The polkit agent is the fallback that turns a "challenge" into a prompt rather
# than a silent nothing. hyprland.lua starts it explicitly, so its absence means
# the compositor's start hook did not take effect.
if systemctl --user is-active --quiet hyprpolkitagent.service; then
    note "ok   hyprpolkitagent is running (a challenged action could still prompt)"
else
    note "FAIL hyprpolkitagent is not running; any challenged polkit action fails silently"
    FAILED=1
fi

# --- group 9d: nothing the compositor prints reaches the terminal -----------
#
# THE BUG THIS CLOSES was visible to the owner and invisible to every gate: a
# "terminal like screen" between the greeter and the desktop. greetd connects a
# session's stdio straight to the VT — that is how the packaged text greeter
# works at all — so Hyprland's startup log was printed onto tty1. It sat there
# unseen while the compositor held DRM and was revealed the instant the greeter
# exited, which is exactly the handover the session scripts clear the terminal
# to keep black. The clear ran BEFORE the printing, so it tidied away the
# previous occupant's text and put our own there instead.
#
# Asserted on the live process rather than by grepping the script, because what
# matters is where the descriptors actually point on a running machine.
hypr_pid="$(pgrep -x Hyprland 2>/dev/null | head -1)"
if [ -z "${hypr_pid}" ]; then
    note "FAIL no Hyprland process found; the compositor stdio assertion cannot run"
    FAILED=1
else
    # WHY THIS IS TWO MEASUREMENTS AND NOT ONE. Reading another process's fd
    # links needs PTRACE_MODE_READ, which the checker — a system service, not a
    # descendant of the compositor — does not always get even at the same uid.
    # The first version asserted on the link alone and reported "the assertion
    # did not run" as a FAILURE, which is a gate failing because it could not
    # look. So: when the link is readable it is the direct evidence and is
    # asserted; when it is not, the journal identifier carries the claim,
    # because output that reached the journal under the session's own tag is
    # output that did not reach the terminal.
    hypr_fd_readable=0
    for hypr_fd in 1 2; do
        hypr_target="$(readlink "/proc/${hypr_pid}/fd/${hypr_fd}" 2>/dev/null)"
        [ -n "${hypr_target}" ] && hypr_fd_readable=1
        case "${hypr_target}" in
            /dev/tty*|/dev/console|/dev/vc/*)
                note "FAIL Hyprland fd ${hypr_fd} is ${hypr_target}; its log lands on the terminal and shows through at every session handover"
                FAILED=1
                ;;
            "")
                note "info Hyprland fd ${hypr_fd} is not readable from this service ($(readlink "/proc/${hypr_pid}/fd/${hypr_fd}" 2>&1 >/dev/null | head -c 80)); the journal leg below carries the claim"
                ;;
            *)
                note "ok   Hyprland fd ${hypr_fd} is ${hypr_target}, not a terminal"
                ;;
        esac
    done

    # The positive evidence, and the only leg that works without ptrace: the
    # session script execs the compositor through `systemd-cat --identifier=
    # punar-session`, so entries under that identifier exist if and only if the
    # compositor's output is going to the journal. An empty journal here means
    # the redirect is not in force, whatever the file on disk says.
    hypr_journal="$(journalctl --identifier=punar-session --lines=1 --no-pager 2>/dev/null | grep -c . || true)"
    if [ "${hypr_journal:-0}" -gt 0 ]; then
        note "ok   the compositor's output is in the journal under punar-session"
    elif [ "${hypr_fd_readable}" -eq 1 ]; then
        note "info no punar-session journal entries yet; the fd assertion above already carries the claim"
    else
        note "FAIL neither Hyprland's fds nor the punar-session journal could be read; nothing here proved the compositor is off the terminal"
        FAILED=1
    fi
fi

# --- group 9c: a device policy change needs a password, and then works ------
#
# THE PATH THIS COVERS, end to end and as the session user: System Control's
# Policy view offers an administrator a pin, asks for a reason and a password,
# and runs /usr/lib/punar/punar-policy-set.sh, which re-authenticates through
# punar-authd and spends the ticket on `punarctl policy set`. Every piece of
# that has unit tests; none of them proves the CHAIN, and the chain is where a
# missing binary, a socket group, a PAM stack or a ticket directory mode fails.
#
# NEGATIVE LEGS FIRST. If a change went through without a password, the positive
# leg below would pass on a machine with no authentication at all.
#
# The dev user's password is set by mkosi.profiles/dev/mkosi.postinst.chroot,
# the same one group 8b uses.
policy_password="punar"
policy_wrong="definitely-not-the-passphrase"
policy_path="security.firewall"

policy_source_kind() {
    punarctl policy explain "$1" --json 2>/dev/null \
        | sed -n 's/.*"source":{"kind":"\([a-z_]*\)".*/\1/p'
}
policy_effective_value() {
    punarctl policy explain "$1" --json 2>/dev/null \
        | sed -n 's/.*"effective_value":"\([a-z]*\)".*/\1/p'
}

policy_before_kind="$(policy_source_kind "${policy_path}")"
policy_value="$(policy_effective_value "${policy_path}")"
note "# policy ${policy_path} source=${policy_before_kind:-none} value=${policy_value:-none}"

if [ -z "${policy_value}" ]; then
    note "FAIL punarctl policy explain ${policy_path} returned no effective value; the rest of this group cannot run"
    FAILED=1
else
    # 1. No confirmation at all.
    policy_no_ticket="$(punarctl policy set "${policy_path}" "${policy_value}" \
        --reason "gate: no ticket" 2>&1 >/dev/null)"
    case "${policy_no_ticket}" in
        *password*)
            note "ok   a policy change with no confirmation is refused, in words that name the fix"
            ;;
        *)
            note "FAIL a policy change with no confirmation was not refused as expected: '${policy_no_ticket}'"
            FAILED=1
            ;;
    esac

    # 2. A wrong password. The helper must stop before punarctl is reached.
    printf '%s\n' "${policy_wrong}" \
        | /usr/lib/punar/punar-policy-set.sh "${policy_path}" "${policy_value}" "gate: wrong password" \
          >/dev/null 2>&1
    policy_wrong_rc="$?"
    check_eq "the helper's exit status for a wrong password" "3" "${policy_wrong_rc}"
    check_eq "the winning source after a wrong password" \
        "${policy_before_kind}" "$(policy_source_kind "${policy_path}")"

    # 3. THE POSITIVE LEG. Pinning the value the device already has changes
    #    nothing about the machine and everything about the provenance, which
    #    is what is being asserted — a gate must not leave a CI VM with its
    #    firewall in a different state than it found it.
    printf '%s\n' "${policy_password}" \
        | /usr/lib/punar/punar-policy-set.sh "${policy_path}" "${policy_value}" "gate: administrator pin" \
          >/dev/null 2>&1
    policy_set_rc="$?"
    check_eq "the helper's exit status for a correct password" "0" "${policy_set_rc}"
    check_eq "the winning source after an administrator pin" \
        "device_specific_override" "$(policy_source_kind "${policy_path}")"
    check_eq "the effective value is unchanged by a same-value pin" \
        "${policy_value}" "$(policy_effective_value "${policy_path}")"

    # 4. And withdrawing it hands the path back to the layer underneath.
    printf '%s\n' "${policy_password}" \
        | /usr/lib/punar/punar-policy-set.sh "${policy_path}" --clear "gate: withdraw" \
          >/dev/null 2>&1
    policy_clear_rc="$?"
    check_eq "the helper's exit status for a withdrawal" "0" "${policy_clear_rc}"
    check_eq "the winning source after withdrawing the pin" \
        "${policy_before_kind}" "$(policy_source_kind "${policy_path}")"

    # 5. THE PROPERTY THE WHOLE DESIGN RESTS ON: a ticket is trustworthy only
    #    because an unprivileged process cannot create one. Counting the files
    #    would be vacuous here — this runs as the session user, so an
    #    unreadable directory and an empty one both count zero.
    #
    #    EXISTENCE IS ASSERTED FIRST, and that is the half the earlier version
    #    was missing: `ls` fails for "no such directory" exactly as it fails for
    #    "not yours to read", so on a machine where punar-authd had never minted
    #    anything the leg passed while proving nothing. The successful pin above
    #    guarantees the directory is there by now, so its absence is a failure.
    if [ ! -d /run/punar-authd/tickets ]; then
        note "FAIL /run/punar-authd/tickets does not exist after a successful administrative change; the ticket path was not the one exercised"
        FAILED=1
    elif ls /run/punar-authd/tickets >/dev/null 2>&1; then
        note "FAIL the session user can read /run/punar-authd/tickets; a ticket would be forgeable"
        FAILED=1
    else
        note "ok   the ticket directory exists and is unreadable to the session user"
    fi

    # LEAVE THE MACHINE AS IT WAS FOUND, whatever happened above. A withdraw leg
    # that fails partway leaves a device_specific_override pinned on
    # security.firewall, and every later group that reads policy — m4's merge
    # assertions, m5's org-precedence ones — then fails for a reason that has
    # nothing to do with what it is testing. One unconditional attempt, and a
    # loud line if even that does not take.
    if [ "$(policy_source_kind "${policy_path}")" = "device_specific_override" ]; then
        printf '%s\n' "${policy_password}" \
            | /usr/lib/punar/punar-policy-set.sh "${policy_path}" --clear "gate: cleanup" \
              >/dev/null 2>&1
        if [ "$(policy_source_kind "${policy_path}")" = "device_specific_override" ]; then
            note "FAIL ${policy_path} is still pinned by this gate; later policy groups will fail for the wrong reason"
            FAILED=1
        else
            note "info the administrator pin was cleaned up after a failed leg"
        fi
    fi
fi

# --- group 10: an application can actually notify ---------------------------
#
# THE GAP THIS CLOSES. Punar ships a real freedesktop notification daemon
# (Services/Notifications.qml binds org.freedesktop.Notifications through
# Quickshell's NotificationServer), a centre that keeps records, and toasts.
# None of it had ever been proven end to end: before this group, no script in
# os/images, tools/ or tests/ ever SENT a notification. The surfaces sweep above
# opens the centre and screenshots it, which proves the window renders and
# nothing at all about whether an application can reach it.
#
# That is the exact failure the daemon's own ownership probe exists to catch.
# Quickshell yields the bus name SILENTLY when another daemon already holds it —
# it logs a line no user reads and then simply receives nothing, which looks
# identical to "nobody has notified you". Shipping that unproven is precisely
# what spec 1.22 forbids.
#
# WHY busctl AND NOT notify-send. No libnotify ships in this image, and adding a
# package so a test can pass would make the gate prove something about the test
# harness rather than about the product. busctl is already present — the shell
# itself uses it for the ownership probe — and calling Notify directly over
# D-Bus is a truer test anyway: it is the raw freedesktop interface any
# application would use, with no convenience layer standing in.
notif_app="Punar Gate Probe"

# (1) Punar must actually OWN the name in this image. "punar" is proven by PID
#     comparison against Quickshell.processId; "foreign" means another daemon
#     holds it and nothing reaches us; "unverified" means the probe could not
#     run and is NOT treated as success — the absence of an answer is not an
#     answer.
notif_owner="$(ipc notifications owner | tr -d '[:space:]"')"
check_eq "notifications.owner" "punar" "${notif_owner}"

# (2) The negative leg FIRST, so the positive one cannot be vacuous: the probe's
#     app name must not already be a group. Without this, a pre-existing row
#     would make step (4) pass while proving nothing.
notif_groups_before="$(ipc notifications groups | tr -d '"')"
case "|${notif_groups_before}|" in
    *"|${notif_app}|"*)
        note "FAIL '${notif_app}' was already a notification group before the probe sent anything"
        FAILED=1 ;;
    *)  note "ok   '${notif_app}' is not a group before the probe sends" ;;
esac
notif_count_before="$(ipc notifications count | tr -d '[:space:]"')"

# (3) Send one real notification over the session bus. Signature is the
#     freedesktop Notify contract: app_name, replaces_id, icon, summary, body,
#     actions[], hints{}, expire_timeout. -1 is the server's own default expiry.
# The shell inherits a full session environment from its own startup; this
# script does not necessarily, and `qs ipc` cannot reveal the difference —
# Quickshell's IPC is a Unix socket in XDG_RUNTIME_DIR, not D-Bus, so every
# `ipc` call above can succeed on a shell whose session bus this script cannot
# address. Fall back to the standard per-user bus socket when the variable is
# absent, which is exactly what libdbus does.
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ] \
        && [ -n "${XDG_RUNTIME_DIR:-}" ] \
        && [ -S "${XDG_RUNTIME_DIR}/bus" ]; then
    DBUS_SESSION_BUS_ADDRESS="unix:path=${XDG_RUNTIME_DIR}/bus"
    export DBUS_SESSION_BUS_ADDRESS
    note "info session bus address defaulted to ${XDG_RUNTIME_DIR}/bus"
fi

# THE `--` IS LOAD-BEARING. The last argument is the freedesktop
# expire_timeout, and -1 means "use the server's default". Without `--`,
# getopt reads that -1 as a command-line option and busctl exits with
# "unrecognized option '-1'" before sending anything — which is exactly what
# the first run of this gate recorded. Do not remove it as tidying.
busctl --user -- call org.freedesktop.Notifications /org/freedesktop/Notifications \
    org.freedesktop.Notifications Notify "susssasa{sv}i" \
    "${notif_app}" 0 "" "Gate probe" "sent by surfaces-check over D-Bus" 0 0 -1 \
    > /run/punar/notify-send.txt 2>&1 && notif_send_rc=0 || notif_send_rc=$?
# The measurement below is still what decides pass/fail - busctl can exit 0
# having reached a bus that dropped the call. But a send that FAILED must say
# why, or a red run leaves nobody able to tell a broken probe from a broken
# daemon. This line is diagnosis, never the verdict.
note "info busctl Notify exit=${notif_send_rc} output='$(tr -d "\r\n" < /run/punar/notify-send.txt 2>/dev/null | head -c 200)'"
note "info session bus: DBUS_SESSION_BUS_ADDRESS='${DBUS_SESSION_BUS_ADDRESS:-unset}' XDG_RUNTIME_DIR='${XDG_RUNTIME_DIR:-unset}' user=$(id -un 2>/dev/null)"

# (4) MEASURE the effect; never trust the sender's exit status. busctl can
#     return 0 having reached a bus that dropped the call on the floor.
notif_seen=0
notif_waited=0
while [ "${notif_waited}" -lt 15 ]; do
    notif_groups_after="$(ipc notifications groups | tr -d '"')"
    case "|${notif_groups_after}|" in
        *"|${notif_app}|"*) notif_seen=1; break ;;
    esac
    sleep 1
    notif_waited=$((notif_waited + 1))
done
if [ "${notif_seen}" -eq 1 ]; then
    note "ok   the notification reached the centre grouped under '${notif_app}' after ${notif_waited}s"
else
    note "FAIL no notification from '${notif_app}' reached the centre within 15s (groups: '${notif_groups_after:-}')"
    FAILED=1
fi

# (5) The record COUNT moved too. Grouping alone could in principle be
#     satisfied by a header with no row under it.
notif_count_after="$(ipc notifications count | tr -d '[:space:]"')"
if [ "${notif_count_after:-0}" -gt "${notif_count_before:-0}" ]; then
    note "ok   centre record count rose ${notif_count_before} -> ${notif_count_after}"
else
    note "FAIL centre record count did not rise (${notif_count_before} -> ${notif_count_after})"
    FAILED=1
fi

# (6) Leave the centre as we found it, and prove clearing is real rather than
#     cosmetic — a centre that cannot forget is its own defect.
ipc notifications clear >/dev/null 2>&1 || true
notif_count_cleared="$(ipc notifications count | tr -d '[:space:]"')"
check_eq "notifications.count after clear" "0" "${notif_count_cleared}"

# --- 10b. Grouping and ordering, told apart from a flat list -----------------
# Group 10 above sends ONE notification from ONE application. With a single
# record, "grouped by application, newest first" and "one flat list" produce
# identical output, so the accessor that exists to discriminate them was not
# being used to discriminate anything. Its count leg is `>` only, so a second
# record silently vanishing would also be invisible.
#
# Three records from two senders is the smallest arrangement that separates
# them: two groups from three records is a claim a flat list cannot make, and
# re-sending from the FIRST sender last makes the order a claim too.
#
# ASSERT THE RELATION, NOT THE STRING. The expected order is derived from the
# send order this script controls — the group whose newest record is newest
# sorts first — rather than pinned as a literal "Alpha|Beta", which would
# become a scheduled failure the day grouping gains pinned or priority sources.
#
# It runs AFTER the clear above, from a centre proven empty, so the count is an
# exact delta rather than a floor and no unrelated group can appear between the
# two names being compared.
notif_a="Punar Gate Alpha"
notif_b="Punar Gate Beta"

notif_send() {
    busctl --user -- call org.freedesktop.Notifications /org/freedesktop/Notifications \
        org.freedesktop.Notifications Notify "susssasa{sv}i" \
        "$1" 0 "" "$2" "sent by surfaces-check over D-Bus" 0 0 -1 \
        >> /run/punar/notify-send.txt 2>&1
}
# Waiting for each send to land before making the next one is what makes the
# ordering assertion deterministic: every busctl call is its own bus
# connection, and D-Bus orders messages per sender, not across senders.
notif_wait_count() {
    notif_w=0
    while [ "${notif_w}" -lt 15 ]; do
        [ "$(ipc notifications count | tr -d '[:space:]"')" = "$1" ] && return 0
        sleep 1
        notif_w=$((notif_w + 1))
    done
    return 1
}

# Vacuity guard for both names, on an empty centre: if either were already a
# group, every assertion below would pass without the sends proving anything.
notif_groups_pre="$(ipc notifications groups | tr -d '"')"
case "|${notif_groups_pre}|" in
    *"|${notif_a}|"*|*"|${notif_b}|"*)
        note "FAIL a 10b probe name was already a group before anything was sent"
        FAILED=1 ;;
    *)  note "ok   neither 10b probe name is a group before sending" ;;
esac

notif_ordered=1
notif_send "${notif_a}" "first from Alpha"  || notif_ordered=0
notif_wait_count 1                          || notif_ordered=0
notif_send "${notif_b}" "only from Beta"    || notif_ordered=0
notif_wait_count 2                          || notif_ordered=0
notif_send "${notif_a}" "second from Alpha" || notif_ordered=0
notif_wait_count 3                          || notif_ordered=0
check_eq "three records landed one at a time" "1" "${notif_ordered}"

# Exactly three records, exactly two groups: a flat list would report three.
notif_count_3="$(ipc notifications count | tr -d '[:space:]"')"
check_eq "record count after three sends" "3" "${notif_count_3}"

notif_groups_3="$(ipc notifications groups | tr -d '"')"
notif_group_n="$(printf '%s' "${notif_groups_3}" | awk -F'|' '{print NF}')"
check_eq "three records from two senders form two groups" "2" "${notif_group_n}"

# The relation: Alpha sent last, so Alpha's group must sort ahead of Beta's.
case "${notif_groups_3}" in
    "${notif_a}|${notif_b}")
        note "ok   the group whose newest record is newest sorts first" ;;
    *)  note "FAIL groups are not in most-recent-first order (got '${notif_groups_3}', Alpha sent last)"
        FAILED=1 ;;
esac

ipc notifications clear >/dev/null 2>&1 || true
notif_count_10b="$(ipc notifications count | tr -d '[:space:]"')"
check_eq "notifications.count after the 10b clear" "0" "${notif_count_10b}"

# --- 10c. Sender text is treated as untrusted input --------------------------
# A notification's application name, summary and body come from any application
# on the machine and are then drawn in Punar's own chrome — in the centre, in
# the same visual register as a punard approval. Services/Notifications.qml
# therefore sanitises them at the boundary: bidi overrides dropped, control
# characters turned into spaces, whitespace runs collapsed, length bounded.
#
# That is a claim about a running shell, so it is asserted against one. The
# `groups` accessor prints the stored source of each group, which is the exact
# string a surface would draw, so a name that survived unsanitised shows up
# here rather than in a screenshot nobody reads.
#
# The interesting one is the newline. A Text item honours an explicit newline
# even with wrapping off and eliding on, and the toast's meta row sizes the
# card, whose height is unbounded — so before this, an application name full of
# newlines grew the card without limit. There is no pointer here to see that
# with; what CAN be observed is that the newline never reaches the store.
notif_hostile="$(printf 'Punar Gate\nHostile\007\342\200\256Probe')"
notif_hostile_clean="Punar Gate Hostile Probe"

notif_send "${notif_hostile}" "hostile name probe" || true
notif_wait_count 1 || true

notif_groups_h="$(ipc notifications groups | tr -d '"')"
check_eq "control and bidi characters are stripped from an application name" \
    "${notif_hostile_clean}" "${notif_groups_h}"

# Independently of the exact expected string above: whatever came back, it is
# one line. This is the assertion that speaks to the unbounded card directly.
#
# COUNTED OFF THE CAPTURED VALUE, not off a pipeline. `wc -l` counts newline
# characters, and every command's output ends with one, so piping `ipc` straight
# into it reported 1 for a perfectly clean single-line name — a failing
# assertion against working code, which is the worst kind. Command substitution
# strips trailing newlines, so an embedded newline is the only thing left to
# count.
notif_group_lines="$(printf '%s' "${notif_groups_h}" | wc -l | tr -d '[:space:]')"
check_eq "a stored source spans no lines of its own" "0" "${notif_group_lines}"

ipc notifications clear >/dev/null 2>&1 || true
notif_wait_count 0 || true

# Length is asserted as a RELATION, not against the shipped cap: a sender that
# writes far more than any surface can draw gets bounded. Pinning 64 here would
# go red the day the cap is retuned, which is a legitimate product change.
notif_long="$(printf 'PunarGateLong%.0s' 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20)"
notif_long_len="$(printf '%s' "${notif_long}" | wc -c | tr -d '[:space:]')"
notif_send "${notif_long}" "length bound probe" || true
notif_wait_count 1 || true
notif_stored_len="$(ipc notifications groups | tr -d '"' | wc -c | tr -d '[:space:]')"
if [ "${notif_stored_len}" -lt "${notif_long_len}" ]; then
    note "ok   an over-long application name is bounded (${notif_long_len} bytes sent, ${notif_stored_len} stored)"
else
    note "FAIL an over-long application name was stored unbounded (${notif_long_len} sent, ${notif_stored_len} stored)"
    FAILED=1
fi

ipc notifications clear >/dev/null 2>&1 || true
notif_count_10c="$(ipc notifications count | tr -d '[:space:]"')"
check_eq "notifications.count after the 10c clear" "0" "${notif_count_10c}"

# --- artifacts --------------------------------------------------------------
hyprctl -j clients > /run/punar/surfaces-clients.json 2>/dev/null || true

finish
