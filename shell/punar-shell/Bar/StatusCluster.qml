pragma ComponentBehavior: Bound
// StatusCluster — the live right-hand cluster of the bar (Plate D-016,
// docs/design/mockups/menubar.html; Sect I·03, Sect III, Sect V·02).
//
// THE CALM RULE IS THE DESIGN (Sect II·01), and this file is written so
// that it holds by construction: every slot below carries its own
// `visible` expression bound to real data, and a Row positioner skips
// invisible items. A personal, idle machine therefore renders this
// component as ZERO PIXELS — no cluster, no separator, no colour, no
// greyed-out placeholder waiting to light up — and the bar stays
// `PUNAR · 1` at the left and `08:26` at the right, exactly as it renders
// today. A masthead with nothing to report is complete, not empty.
//
// FIXED ORDER, BY LIFECYCLE (Sect I·03): AI · ENV · CRED · APPROVAL —
// what you started, what you hold, what waits on you — then the bar's own
// org annotation and the clock, which are not slots and open nothing.
// Severity NEVER reorders anything: position is stable so muscle memory
// holds, and urgency is carried by colour, word and focus-landing
// instead. The order is the literal order of `slotModel` below; there is
// no sort function to get wrong.
//
// WHAT DOES NOT RENDER, AND WHY (Sect IV — the honest half of this file):
//   · ENV — `punar-env` has NO state file. Running podman on a timer to
//     fill a bar slot is exactly the polling loop spec §6.3 prohibits, so
//     the slot does not render at all until `/run/punar/envs.json`
//     ({v, envs:[{project, name, state, started_at}], ts}, written
//     atomically on up/down/destroy the way punard writes status.json)
//     exists. D-016 Sect IV·06 says that in those words; this file obeys
//     it literally — there is no Envs singleton and no placeholder.
//   · CRED — `punar-secrets` is a broker with NO state directory at all
//     (docs/api/ipc.md §16: that is the strongest available form of the
//     "never written to disk" promise), so no file carries a live
//     credential lease and there is nothing to observe without polling.
//     The one live TTL the shell CAN observe — a just-in-time privilege
//     grant from `grants[]` in /run/punard/approvals.json — is already
//     drawn by Plate D-012's ELEVATED chip in Bar.qml, and one fact is
//     not announced twice in the same bar.
//   · BATTERY · NET · AUDIO — Quickshell services exist, nothing is
//     wired; they earn a slot only when they have something to say
//     (Sect IV·09, Milestone 11).
// Their absence costs nothing here: no disabled widget, no tooltip, no
// upsell — they are simply not in `slotModel`.

import QtQuick
import Quickshell
import "../Theme"
import "../Services"

FocusScope {
    id: cluster

    // Milliseconds, supplied by the bar's seconds clock — which the bar
    // enables ONLY while `needsSeconds` is true. This component owns no
    // timer of its own (Sect IV·10).
    property real nowMs: 0

    // Width the cluster may occupy before detail has to be shed. 0 = do
    // not shed.
    property real availableWidth: 0

    implicitWidth: row.implicitWidth
    implicitHeight: 22

    // ---- AI sessions · /run/punar/agents.json (M7, shipped) ----------

    readonly property int aiActive: Agents.managedCount + Agents.observedCount

    // The unknown count is the larger of what the registry file counts
    // right now (agents.json `counts.unknown`) and what agentd has RAISED
    // and not yet had dealt with (alerts.json). D-016 Sect II·04 calls
    // the bar "the residue that stays until it is dealt with", which is
    // the alert's lifetime, not the process's. Both files are named to
    // the popover: the bar counts what was DETECTED and never claims the
    // absence of what was not (spec §23, §1.22).
    readonly property int unknownCount: Math.max(Agents.unknownCount, Alerts.activeCount)

    // ---- Approvals · /run/punard/approvals.json (M9, shipped) --------
    //
    // NOTE ON THE PATH: D-016 Sect IV·04 writes `/run/punar/approvals.json`.
    // The shipped side contract (docs/api/ipc.md §15) puts the file in the
    // root-owned `/run/punard` instead, because `/run/punar` is
    // `0755 punar:punar` and the file that tells a human what they are
    // about to authorize must not be spoofable. The Approvals singleton
    // owns that path; this component only reads its properties.

    readonly property var nextApproval: {
        var best = null;
        var bestLeft = 0;
        for (var i = 0; i < Approvals.pending.length; i++) {
            var a = Approvals.pending[i];
            var left = Approvals.secondsUntil(Approvals.str(a, "expires_at"), cluster.nowMs);
            if (best === null || left < bestLeft) {
                best = a;
                bestLeft = left;
            }
        }
        return best;
    }

    readonly property int approvalSecondsLeft: cluster.nextApproval === null ? 0
        : Approvals.secondsUntil(Approvals.str(cluster.nextApproval, "expires_at"), cluster.nowMs)

    // THE ONLY TIMER THIS FEATURE COSTS (Sect IV·10): the bar's seconds
    // clock is enabled while — and only while — a countdown is on screen.
    // It performs no I/O; it re-renders a local subtraction against a
    // timestamp already in memory, and it is bounded by how long an
    // approval can be pending (300 s — docs/api/ipc.md §14.4).
    readonly property bool needsSeconds: Approvals.pendingCount > 0

    // ---- helpers -----------------------------------------------------

    // `HH:mm:ss` in local time, or "" for anything unparsable — a stamp
    // the shell cannot read prints nothing rather than a guess.
    function stamp(iso: string): string {
        if (iso === "")
            return "";
        var at = Date.parse(iso);
        if (isNaN(at))
            return "";
        return Qt.formatDateTime(new Date(at), "HH:mm:ss");
    }

    // At most three rows of detail in registry vocabulary, with "and N
    // more" beyond that — the popover never scrolls, because the bar
    // summarises and the owning surface details (Sect III·04).
    function capRows(rows: var, total: int): var {
        var out = rows.slice(0, 3);
        if (total > 3)
            out.push({
                "text": "and " + (total - 3) + " more",
                "tone": "none"
            });
        return out;
    }

    function agentRows(): var {
        var out = [];
        var total = 0;
        var i;
        for (i = 0; i < Agents.sessions.length; i++) {
            var s = Agents.sessions[i];
            if (s === null || typeof s !== "object" || s.status !== "active")
                continue;
            total++;
            out.push({
                "text": String(s.session_id || "session") + " · "
                    + String(s.agent_name || s.classification || "agent"),
                "tone": "none"
            });
        }
        for (i = 0; i < Agents.detections.length; i++) {
            var d = Agents.detections[i];
            if (d === null || typeof d !== "object")
                continue;
            total++;
            out.push({
                "text": String(d.agent || d.executable || "unrecognised process")
                    + " · unknown · suspected",
                "tone": "bad"
            });
        }
        if (out.length === 0)
            return [
                {
                    "text": "nothing registered",
                    "tone": "none"
                }
            ];
        return cluster.capRows(out, total);
    }

    function approvalRows(): var {
        var a = cluster.nextApproval;
        if (a === null)
            return [];
        var out = [];
        out.push({
            "text": Approvals.id(a) + " · " + Approvals.str(a, "capability"),
            "tone": "none"
        });
        var who = Approvals.str(a, "user");
        var risk = Approvals.str(a, "risk");
        if (who !== "" || risk !== "")
            out.push({
                "text": (who === "" ? "" : who + " · ") + (risk === "" ? "" : "risk " + risk),
                "tone": risk === "high" ? "bad" : "warn"
            });
        out.push({
            "text": cluster.approvalSecondsLeft > 0
                ? "expires in " + Approvals.clockWide(cluster.approvalSecondsLeft)
                : "expired · denied by timeout",
            "tone": cluster.approvalSecondsLeft > 0 ? "warn" : "bad"
        });
        return out;
    }

    // ---- the fixed-order slot table ---------------------------------
    //
    // One entry per slot, each with its own `visible` expression, each
    // naming the surface that owns it — a slot with no destination is a
    // slot that should not exist, which is the claim above the fold of
    // the whole plate: nothing appears in the bar that you cannot open.

    readonly property var slotModel: [
        {
            "key": "agents",
            "visible": cluster.aiActive > 0 || cluster.unknownCount > 0,
            "label": "AI",
            "value": cluster.aiActive > 0 ? String(cluster.aiActive) : "",
            "detail": "",
            "severity": "none",
            "operating": true,
            "flagLabel": cluster.unknownCount > 0 ? "Unknown AI" : "",
            "flagValue": cluster.unknownCount > 0 ? String(cluster.unknownCount) : "",
            "title": "AI sessions · " + cluster.aiActive + " active · "
                + cluster.unknownCount + " unknown",
            "rows": cluster.agentRows(),
            "source": "/run/punar/agents.json"
                + (Agents.scannedAt === "" ? "" : " · scanned " + cluster.stamp(Agents.scannedAt))
                + (Alerts.activeCount > 0 ? "\n/run/punar-agentd/alerts.json · "
                   + Alerts.activeCount + " raised" : "")
                + "\ndetected, not guaranteed — spec §23",
            "action": "↵ Open AI panel · Super + A",
            "target": "aipanel"
        },
        {
            "key": "approvals",
            "visible": Approvals.pendingCount > 0,
            "label": "Approval",
            "value": String(Approvals.pendingCount),
            // The countdown is a TEXT SUBSTITUTION, not an animation
            // (Sect II·05), and it does not lie once it reaches zero:
            // punard may not have swept yet, but the verdict is already
            // decided, so the slot says EXPIRED and turns from the
            // pending colour to the denied one (ipc.md §14.4).
            "detail": cluster.approvalSecondsLeft > 0
                ? Approvals.clockWide(cluster.approvalSecondsLeft) : "Expired",
            "severity": cluster.approvalSecondsLeft > 0 ? "warn" : "bad",
            "operating": true,
            "flagLabel": "",
            "flagValue": "",
            "title": "Approvals · " + Approvals.pendingCount + " pending",
            "rows": cluster.approvalRows(),
            "source": "/run/punard/approvals.json"
                + (Approvals.updatedAt === "" ? "" : " · updated " + cluster.stamp(Approvals.updatedAt))
                + "\ncountdown computed locally from expires_at",
            "action": "↵ Open approval overlay",
            "target": "approval"
        }
    ]

    readonly property var visibleSlots: {
        var out = [];
        for (var i = 0; i < cluster.slotModel.length; i++) {
            if (cluster.slotModel[i].visible)
                out.push(cluster.slotModel[i]);
        }
        return out;
    }

    readonly property int slotCount: cluster.visibleSlots.length

    // Slots shed DETAIL, never PRESENCE (Sect I·05): there is no overflow
    // menu, because a hidden alarm is a missable alarm. Level 3 is the
    // full row; level 1 drops the optional detail strings and nothing
    // else — the words UNKNOWN AI and the approval countdown are never
    // `detail`, so they are never collapsed at any width.
    //
    // The measurement is a CHARACTER COUNT, not the rendered row width:
    // Geist Mono is a fixed-advance face, so counting characters in the
    // mono grid IS measuring, and it avoids the binding loop that reading
    // the row's own implicitWidth back into its children would create.
    readonly property real monoAdvance: 11 * 0.6 + Theme.tracking(11, 0.12)

    readonly property real naturalWidth: {
        var chars = 0;
        var slots = 0;
        for (var i = 0; i < cluster.slotModel.length; i++) {
            var s = cluster.slotModel[i];
            if (!s.visible)
                continue;
            slots++;
            chars += s.label.length + s.value.length + s.detail.length
                + s.flagLabel.length + s.flagValue.length;
        }
        if (slots === 0)
            return 0;
        // per-slot padding + inter-slot middle-dot gutter
        return chars * cluster.monoAdvance + slots * 34 + (slots - 1) * 16;
    }

    readonly property int detailLevel: (cluster.availableWidth > 0
        && cluster.naturalWidth > cluster.availableWidth) ? 1 : 3

    // ---- focus (Sect III) -------------------------------------------
    //
    // FOCUS IS NOT THEFT (Sect III·05). -1 means the cluster is not
    // focused, and the bar binds its layer-shell keyboard focus straight
    // to this number: at rest the surface requests NO keyboard focus at
    // all, so typing into an editor can never fall into the bar.

    property int focusIndex: -1

    // Hover opens the popover too (Sect III·04), but never takes focus —
    // the pointer never makes a focus statement for the user
    // (hyprland.conf: `follow_mouse = 0`, the same rule one layer down).
    property int hoverIndex: -1

    readonly property int activeIndex: cluster.focusIndex >= 0 ? cluster.focusIndex
                                                               : cluster.hoverIndex

    readonly property var activeSlot: (cluster.activeIndex >= 0
        && cluster.activeIndex < cluster.slotCount) ? cluster.visibleSlots[cluster.activeIndex]
                                                    : null

    // Scene-x of the active slot's right edge — the popover anchors to it.
    property real activeSlotRight: 0

    // Focus lands on the leftmost slot UNLESS something is warn or bad,
    // in which case it lands on the highest-severity slot — if the bar is
    // shouting you almost certainly pressed the key because of it
    // (Sect III·01).
    function landingIndex(): int {
        var bad = -1;
        var warn = -1;
        for (var i = 0; i < cluster.visibleSlots.length; i++) {
            var s = cluster.visibleSlots[i];
            var sev = s.flagLabel !== "" ? "bad" : s.severity;
            if (sev === "bad" && bad < 0)
                bad = i;
            else if (sev === "warn" && warn < 0)
                warn = i;
        }
        if (bad >= 0)
            return bad;
        if (warn >= 0)
            return warn;
        return cluster.slotCount > 0 ? 0 : -1;
    }

    // Returns false when there is nothing to report — SUPER+SHIFT+B on a
    // calm bar does nothing at all rather than grabbing the keyboard for
    // an empty row.
    function focusCluster(): bool {
        if (cluster.slotCount === 0)
            return false;
        cluster.focusIndex = cluster.landingIndex();
        cluster.forceActiveFocus();
        return true;
    }

    function releaseFocus(): void {
        cluster.focusIndex = -1;
    }

    // ← → (and H L) walk the visible slots WITHOUT wrapping, so the ends
    // are felt (Sect III·01).
    function step(delta: int): void {
        if (cluster.slotCount === 0)
            return;
        var next = cluster.focusIndex + delta;
        if (next < 0)
            next = 0;
        if (next > cluster.slotCount - 1)
            next = cluster.slotCount - 1;
        cluster.focusIndex = next;
    }

    // Every slot is a door (Sect III·03). The destination is reached
    // through the SAME documented IPC contract Hyprland's own binds use
    // (shell README; docs/api/ipc.md) — a fixed argv, never a shell
    // string — so the bar is a discovery path onto surfaces that already
    // own their own chords, never a second implementation of them.
    function openSurface(target: string): void {
        if (target === "")
            return;
        try {
            Quickshell.execDetached(["qs", "-p", Quickshell.shellDir,
                                     "ipc", "call", target, "open"]);
        } catch (e) {
            // No `qs` on PATH: the surface keeps its own chord, and the
            // bar has simply failed to be a shortcut to it.
            console.warn("punar-shell: cannot open", target, e);
        }
    }

    function activate(index: int): void {
        if (index < 0 || index >= cluster.slotCount)
            return;
        cluster.openSurface(cluster.visibleSlots[index].target);
        cluster.releaseFocus();
    }

    // A slot disappearing under the focus must not strand it.
    onSlotCountChanged: {
        if (cluster.focusIndex >= cluster.slotCount)
            cluster.focusIndex = cluster.slotCount - 1;
    }

    Keys.onPressed: function (event) {
        switch (event.key) {
        case Qt.Key_Escape:
            cluster.releaseFocus();
            event.accepted = true;
            break;
        case Qt.Key_Left:
        case Qt.Key_H:
            cluster.step(-1);
            event.accepted = true;
            break;
        case Qt.Key_Right:
        case Qt.Key_L:
            cluster.step(1);
            event.accepted = true;
            break;
        case Qt.Key_Return:
        case Qt.Key_Enter:
            cluster.activate(cluster.focusIndex);
            event.accepted = true;
            break;
        case Qt.Key_Question:
            // D-017 Sect II·04: `?` from inside a shell surface that
            // already owns the keyboard opens the shortcut help.
            cluster.releaseFocus();
            cluster.openSurface("shortcuts");
            event.accepted = true;
            break;
        default:
            break;
        }
    }

    Row {
        id: row

        anchors.verticalCenter: parent.verticalCenter
        spacing: 0

        Repeater {
            model: cluster.visibleSlots

            delegate: Row {
                id: slotRow

                required property int index
                required property var modelData

                readonly property bool isActive: cluster.activeIndex === slotRow.index

                spacing: 0

                onIsActiveChanged: {
                    if (slotRow.isActive)
                        cluster.activeSlotRight = slotItem.mapToItem(null, slotItem.width, 0).x;
                }

                StatusSlot {
                    id: slotItem

                    anchors.verticalCenter: parent.verticalCenter
                    label: slotRow.modelData.label
                    value: slotRow.modelData.value
                    detail: slotRow.modelData.detail
                    severity: slotRow.modelData.severity
                    operating: slotRow.modelData.operating
                    flagLabel: slotRow.modelData.flagLabel
                    flagValue: slotRow.modelData.flagValue
                    detailLevel: cluster.detailLevel
                    selected: cluster.focusIndex === slotRow.index

                    // Arrival: ONE 300 ms fade-and-4px-slide on the
                    // standard curve, once, when the slot appears — and
                    // nothing at rest ever animates (Sect II·02, II·05).
                    opacity: 0
                    transform: Translate {
                        id: arrive
                        x: 4

                        Behavior on x {
                            NumberAnimation {
                                duration: Theme.durStandard
                                easing.type: Easing.BezierSpline
                                easing.bezierCurve: Theme.easingCurve
                            }
                        }
                    }

                    Behavior on opacity {
                        NumberAnimation {
                            duration: Theme.durStandard
                            easing.type: Easing.BezierSpline
                            easing.bezierCurve: Theme.easingCurve
                        }
                    }

                    Component.onCompleted: {
                        slotItem.opacity = 1;
                        arrive.x = 0;
                    }

                    onHoveredChanged: {
                        if (slotItem.hovered)
                            cluster.hoverIndex = slotRow.index;
                        else if (cluster.hoverIndex === slotRow.index)
                            cluster.hoverIndex = -1;
                    }

                    // The mouse still works (Sect III·02): the first
                    // click focuses the slot and opens its popover, a
                    // second click opens the surface.
                    onPressedOnce: {
                        if (cluster.focusIndex === slotRow.index)
                            cluster.activate(slotRow.index);
                        else {
                            cluster.focusIndex = slotRow.index;
                            cluster.forceActiveFocus();
                        }
                    }
                }

                // The middle-dot gutter between slots (Sect I·03); the
                // last slot has none, so the cluster ends on a word.
                Text {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: slotRow.index < cluster.slotCount - 1
                    text: "  ·  "
                    font.family: Theme.fontMono
                    font.pixelSize: 11
                    color: Theme.shellInputBorder
                }
            }
        }
    }
}
