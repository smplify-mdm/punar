pragma ComponentBehavior: Bound
// ApprovalOverlay — the Milestone 9 approval gate, implementing
// docs/design/mockups/command-approval.html Sect II (Plate D-003, the
// acceptance reference) and spec §28: an approval is a CONTRACT CARD —
// who is asking, for what, under which policy, for how long, and what
// exactly happens on yes.
//
// A GATE, NOT A NOTIFICATION. The overlay appears UNBIDDEN whenever
// something is pending, because the capability behind it has already been
// refused and is waiting on a human. It is not a tray icon and it does
// not queue quietly. `Esc` DEFERS — dismissal is not denial, the request
// stays pending, and the overlay reopens for anything new.
//
// AN AI AGENT MAY RESOLVE NOTHING (spec §60, ipc.md §14.5). That rule is
// enforced in punard at the peer's cgroup, not here; this surface simply
// never offers an agent a button, because an agent has no keyboard on
// this layer surface and every action runs through `punarctl`, which the
// daemon authorizes independently.
//
// DATA (ipc.md §15, milestone-9.md §8.1): the Approvals singleton follows
// `/run/punard/approvals.json` with an inotify FileView — no socket client
// in the shell, no polling, no timers except the countdown below. The file
// is NON-AUTHORITATIVE: `A` sends only the `approval_id`, and punard
// re-derives the contract from its own record before executing anything.
// A missing or unparsable file renders no gate at all — fail closed.
//
// THE ONE TIMER (spec §6.3): a 1 Hz countdown that runs ONLY while the
// overlay is open with something pending, and stops otherwise. A UI clock
// with a visible consumer is not the continuous high-frequency polling
// §6.3 prohibits — the M1 bar clock set this precedent.
//
// THE REASON IS SHOWN, AND QUARANTINED (milestone-9.md §8.3). D-003
// renders it, D-012 says it goes into the audit event verbatim, and §73
// requires *why* and *who requested it*: a gate whose justification is
// hidden is a rubber stamp. It is also requester-authored text, so punard
// validates it at creation (one line, ≤512 bytes, no control characters)
// and this surface renders it in a QUOTED REQUESTER VOICE — plain
// non-interactive Text, PlainText format, no links, visually distinct
// from the system-voice contract block. System prose and requester prose
// never share a typeface here.
//
// Driven from Hyprland / the m9-check probe via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call approval open

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Theme"
import "../Services"

Scope {
    id: root

    property bool open: false
    property bool windowVisible: false

    // The approval on the card. Kept across file rewrites so a resolution
    // elsewhere does not yank the record out from under the reader — the
    // verdict is drawn on the same card that asked the question.
    property string selectedId: ""

    // Approvals the human pressed Esc on. Dismissal is not denial: the
    // request stays pending in punard, and this set only suppresses the
    // unbidden reopen for THAT id. Anything new raises the gate again.
    property var deferredIds: ({})

    // Live seconds since epoch for the countdown, refreshed by the 1 Hz
    // timer while the overlay is open. Held as a property so every
    // countdown binding recomputes from one tick rather than each keeping
    // its own clock.
    property real nowMs: Date.now()

    // ---- shared type grammar (DESIGN_LANGUAGE.md §1) ----

    // Meta / label register: Geist Mono, tracked, uppercase. This is the
    // SYSTEM voice, and it is the only voice allowed to look like one.
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.ink3
        textFormat: Text.PlainText
    }

    // A bordered tag (mockup .risk / .pill): mono, tracked, uppercase, in
    // its own status color.
    component Pill: Rectangle {
        id: pill

        property string text: ""
        property color tone: Theme.ink3

        implicitWidth: pillLabel.implicitWidth + 18
        implicitHeight: pillLabel.implicitHeight + 8
        color: "transparent"
        border.width: Theme.hairline
        border.color: pill.tone
        radius: Theme.radiusTag

        Text {
            id: pillLabel

            anchors.centerIn: parent
            text: pill.text
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            font.letterSpacing: Theme.tracking(9, 0.13)
            font.capitalization: Font.AllUppercase
            color: pill.tone
            textFormat: Text.PlainText
        }
    }

    // An action button (mockup .btn): filled for the affirmative, ghost
    // for the destructive, each carrying its visible key binding. The
    // keyboard is the primary path; these are the legend for it.
    component ActionButton: Rectangle {
        id: button

        property string label: ""
        property string binding: ""
        property bool filled: false
        property color tone: Theme.ink
        property bool enabledLook: true

        signal activated()

        implicitWidth: buttonRow.implicitWidth + 30
        implicitHeight: buttonRow.implicitHeight + 16
        radius: Theme.radiusTag
        color: button.filled ? button.tone : "transparent"
        border.width: Theme.hairline
        border.color: button.tone
        opacity: button.enabledLook ? 1 : 0.4

        Row {
            id: buttonRow

            anchors.centerIn: parent
            spacing: 6

            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: button.label
                font.family: Theme.fontMono
                font.pixelSize: 11
                font.weight: 600
                font.letterSpacing: Theme.tracking(11, 0.1)
                font.capitalization: Font.AllUppercase
                color: button.filled ? Theme.actionFg : button.tone
                textFormat: Text.PlainText
            }
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: keyCap.implicitWidth + 8
                height: keyCap.implicitHeight + 3
                radius: 3
                color: "transparent"
                border.width: Theme.hairline
                border.color: button.filled ? Theme.actionFg : button.tone
                opacity: 0.7

                Text {
                    id: keyCap

                    anchors.centerIn: parent
                    text: button.binding
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 600
                    color: button.filled ? Theme.actionFg : button.tone
                    textFormat: Text.PlainText
                }
            }
        }

        MouseArea {
            anchors.fill: parent
            enabled: button.enabledLook
            cursorShape: Qt.PointingHandCursor
            onClicked: button.activated()
        }
    }

    // ---- record reading (all tolerant; a missing field renders nothing) ----

    function record(): var {
        return Approvals.byId(root.selectedId);
    }

    function field(key: string): string {
        return Approvals.str(root.record(), key);
    }

    function requester(): var {
        var a = root.record();
        if (a === null || a === undefined || typeof a !== "object")
            return null;
        var r = a.requester;
        return (r !== null && r !== undefined && typeof r === "object") ? r : null;
    }

    // The name to put in front of the requester's own words.
    //
    // WHY THIS IS USUALLY THE KERNEL-ATTESTED ID AND NOT A FRIENDLY NAME:
    // punard writes `agent_name: null` into the summary on purpose
    // (punar-common/src/approval.rs, SummaryRequester). The friendly name
    // lives in `/run/punar/agents.json`, a `0644 punar:punar` display file
    // any local process can rewrite — and copying a spoofable name onto
    // the one surface whose entire job is to be unspoofable would
    // reintroduce the attack this file exists to prevent. This overlay
    // therefore does NOT reach into the Agents singleton for a prettier
    // label: on a gate, the attested `agt_` id is the identity.
    function requesterName(): string {
        var r = root.requester();
        var name = Approvals.str(r, "agent_name");
        if (name !== "")
            return name;
        if (Approvals.str(r, "type") === "ai_agent") {
            var id = Approvals.str(r, "id");
            return id !== "" ? id : "The AI agent";
        }
        var user = root.field("user");
        return user !== "" ? user : "The requester";
    }

    // The subject of the system's own sentence. The identity chain sits
    // directly above it carrying the attested id, so the sentence says
    // WHAT KIND of principal is asking rather than repeating the id — the
    // card names the requester once, precisely, and reads as English.
    function requesterPhrase(): string {
        var r = root.requester();
        var name = Approvals.str(r, "agent_name");
        if (name !== "")
            return name;
        if (Approvals.str(r, "type") === "ai_agent")
            return "This AI agent";
        var user = root.field("user");
        return user !== "" ? user : "This requester";
    }

    // Plate D-003's identity chain, one mono line: principal kind, agent,
    // session, human. Only the parts the record carries are drawn — an
    // absent project is absent, never a placeholder.
    function identityChain(): string {
        var r = root.requester();
        var parts = [];
        var kind = Approvals.str(r, "type");
        parts.push(kind === "ai_agent" ? "AI agent" : (kind === "user" ? "User" : "Requester"));
        var name = Approvals.str(r, "agent_name");
        if (name !== "")
            parts.push(name);
        // D-003 draws a project between the agent and the session id. The
        // summary carries no project (ipc.md §15) and this surface does not
        // borrow one from the spoofable display file, so the chain simply
        // does not print one — an absent link is absent, never a
        // placeholder and never a guess.
        var id = Approvals.str(r, "id");
        if (id !== "")
            parts.push(id);
        var user = root.field("user");
        if (user !== "")
            parts.push(user);
        return parts.join(" · ");
    }

    // The exact typed call that will run — `capability(resource)`, whose
    // semantics ipc.md §14.3 defines once for all three kinds, which is
    // why one formatter serves them all. The daemon's own `contract`
    // string wins when it sent one.
    function contractCall(): string {
        var explicit = root.field("contract");
        if (explicit !== "")
            return explicit;
        var cap = root.field("capability");
        var res = root.field("resource");
        return res === "" ? cap : cap + "(" + res + ")";
    }

    // The policy citation. UNMANAGED-FIRST (DESIGN_LANGUAGE.md §8):
    // whatever punard cites is what is drawn — a personal device cites
    // personal defaults, an enrolled one cites the organization by name.
    // The shell never upgrades a personal citation into an org one.
    function policyCitation(): string {
        var a = root.record();
        var p = (a !== null && a !== undefined && typeof a === "object") ? a.policy : null;
        var name = Approvals.str(p, "name");
        var id = Approvals.str(p, "policy_id");
        // `Personal defaults · personal-defaults` says one thing twice;
        // when the machine id is only the display name in kebab-case, the
        // citation prints once.
        if (name !== "" && id !== "")
            return id.replace(/-/g, " ").toLowerCase() === name.toLowerCase()
                ? name : name + " · " + id;
        if (name !== "")
            return name;
        if (id !== "")
            return id;
        return "Personal defaults";
    }

    // The system's own one-sentence account of the request (mockup .req),
    // derived from the record so it can never disagree with the contract
    // block beneath it.
    function requestSentence(): string {
        var who = root.requesterPhrase();
        var cap = root.field("capability");
        var res = root.field("resource");
        switch (root.field("kind")) {
        case "credential_request":
            return who + " wants a short-lived " + res + " credential.";
        case "privilege_request":
            return who + " is requesting " + cap + " for " + res + ".";
        default:
            return who + " wants to set " + cap + " to " + res + ".";
        }
    }

    // The execution sibling of the shown record (ipc.md §14.3), or null.
    function execution(): var {
        var a = root.record();
        if (a === null || a === undefined || typeof a !== "object")
            return null;
        var e = a.execution;
        return (e !== null && e !== undefined && typeof e === "object") ? e : null;
    }

    // Plate D-003's verdict register, drawn from the record — with the
    // audit pointer, which is what ties this card to the trail without
    // extending audit-event.json (ipc.md §14.3).
    function verdictText(): string {
        var exec = root.execution();
        var evt = Approvals.str(exec, "audit_event_id");
        var audit = evt === "" ? "" : " · audit " + evt;
        switch (root.shownStatus) {
        case "approved":
            if (exec === null)
                return "✓ Approved" + audit;
            if (Approvals.str(exec, "result") === "success")
                return "✓ Approved · " + root.contractCall() + " executed" + audit;
            return "Approved, but not applied · " + Approvals.str(exec, "result") + audit;
        case "denied":
            return "Denied · nothing executed" + audit;
        case "expired":
            return "Expired · denied by timeout" + audit;
        default:
            // Pending in the file, but the clock ran out here — the card
            // says so before the daemon's lazy sweep does (ipc.md §14.4).
            return "Expired · denied by timeout";
        }
    }

    // Green only for an approval that actually executed (or that has
    // nothing to execute yet). An approved-but-failed apply is red: the
    // human said yes and the machine did not deliver, and that is not a
    // success.
    function verdictGood(): bool {
        if (root.shownStatus !== "approved")
            return false;
        var exec = root.execution();
        if (exec === null)
            return true;
        return Approvals.str(exec, "result") === "success";
    }

    // ---- state ----

    readonly property string shownStatus: {
        var a = root.record();
        return a === null ? "" : Approvals.status(a);
    }

    readonly property int secondsLeft: Approvals.secondsUntil(root.field("expires_at"), root.nowMs)

    // Pending in the file, but the clock has already run out here. The
    // card says EXPIRED immediately whether or not punard has swept
    // (ipc.md §14.4); pressing A then gets `expired` from the daemon and
    // the next file change makes it official.
    readonly property bool lapsed: root.shownStatus === "pending" && root.secondsLeft <= 0

    readonly property bool decided: root.shownStatus !== "" && root.shownStatus !== "pending"

    readonly property bool actionable: root.shownStatus === "pending" && !root.lapsed

    // Position of the shown approval within the pending queue, for the
    // ↑/↓ affordance and the count badge.
    readonly property int pendingIndex: {
        for (var i = 0; i < Approvals.pending.length; i++) {
            if (Approvals.id(Approvals.pending[i]) === root.selectedId)
                return i;
        }
        return -1;
    }

    function isDeferred(approvalId: string): bool {
        return root.deferredIds[approvalId] === true;
    }

    // The first pending approval the human has not deferred, or "".
    function nextUndeferred(): string {
        for (var i = 0; i < Approvals.pending.length; i++) {
            var id = Approvals.id(Approvals.pending[i]);
            if (id !== "" && !root.isDeferred(id))
                return id;
        }
        return "";
    }

    // Re-evaluate the gate whenever the file changes. This is the whole
    // control loop: no polling, no queue of its own — punard's record is
    // the queue, and this reacts to it.
    function syncGate(): void {
        // Drop deferrals for approvals that are no longer pending: a
        // deferral suppresses one reopen, never a future request.
        var kept = ({});
        for (var i = 0; i < Approvals.pending.length; i++) {
            var pid = Approvals.id(Approvals.pending[i]);
            if (root.isDeferred(pid))
                kept[pid] = true;
        }
        root.deferredIds = kept;

        // A decided card lingers briefly so the verdict is readable, then
        // the overlay moves on. D-003's `.ap.decided` state, with a clock.
        if (root.open && root.decided) {
            if (!lingerTimer.running)
                lingerTimer.restart();
            return;
        }

        // The shown approval vanished from the file entirely (evicted):
        // fall through to whatever is still pending.
        if (root.record() === null)
            root.selectedId = "";

        var next = root.nextUndeferred();
        if (next === "") {
            if (root.open && Approvals.pendingCount === 0)
                root.dismiss();
            return;
        }
        if (root.selectedId === "" || Approvals.status(root.record()) !== "pending")
            root.selectedId = next;
        if (!root.open)
            root.show();
    }

    function moveSelection(delta: int): void {
        var queue = Approvals.pending;
        if (queue.length === 0)
            return;
        var at = root.pendingIndex < 0 ? 0 : root.pendingIndex + delta;
        at = Math.max(0, Math.min(queue.length - 1, at));
        root.selectedId = Approvals.id(queue[at]);
    }

    // ---- actions ----

    // Every decision runs DETACHED through punarctl with fixed argv —
    // never a shell string, never an IPC client in the shell. The overlay
    // does not read the process result: the next FileView change is the
    // truth (ipc.md §15). Only the `approval_id` is sent; punard
    // re-derives the contract from its own record before executing.
    function resolve(decision: string): void {
        if (!root.actionable)
            return;
        var id = root.selectedId;
        if (id === "")
            return;
        try {
            Quickshell.execDetached(["punarctl", "approvals", "resolve", id, "--decision", decision]);
        } catch (e) {
            // No punarctl on a dev machine: the card stays as it is, and
            // the request stays pending in the daemon. Nothing is guessed.
            console.warn("punar-shell: approval action unavailable:", e);
        }
    }

    // Esc: defer. The request stays pending in punard, the overlay closes,
    // and this id will not raise the gate unbidden again — anything new
    // will.
    function defer(): void {
        if (root.selectedId !== "") {
            var next = ({});
            for (var key in root.deferredIds)
                next[key] = root.deferredIds[key];
            next[root.selectedId] = true;
            root.deferredIds = next;
        }
        root.dismiss();
    }

    function show(): void {
        hideTimer.stop();
        root.nowMs = Date.now();
        root.windowVisible = true;
        root.open = true;
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        lingerTimer.stop();
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle(): void {
        if (root.open) {
            root.dismiss();
        } else {
            // An explicit open clears deferrals: the human asked to see
            // what is waiting, so show all of it.
            root.deferredIds = ({});
            Approvals.refresh();
            if (root.selectedId === "" || root.record() === null)
                root.selectedId = Approvals.pendingCount > 0 ? Approvals.id(Approvals.pending[0]) : "";
            root.show();
        }
    }

    Component.onCompleted: root.syncGate()

    Connections {
        target: Approvals

        // One handler, one control loop: punard's file is the queue.
        function onApprovalsChanged(): void {
            root.syncGate();
        }
    }

    // SUPER-less entry point: the gate opens itself. This handler exists
    // for Hyprland binds and for the m9-check probe:
    //   qs -p /usr/share/punar/shell ipc call approval open
    IpcHandler {
        target: "approval"

        function toggle(): void {
            root.toggle();
        }
        function open(): void {
            root.deferredIds = ({});
            Approvals.refresh();
            if (root.selectedId === "" || root.record() === null)
                root.selectedId = Approvals.pendingCount > 0 ? Approvals.id(Approvals.pending[0]) : "";
            root.show();
        }
        function close(): void {
            root.dismiss();
        }
        // Read-only probes (the `aipanel` / `overview` precedent).
        function state(): string {
            return root.open ? "open" : "closed";
        }
        function pending(): string {
            return String(Approvals.pendingCount);
        }
        // Which card is on screen. The m9-check probe asserts against
        // this so a screenshot is not the only evidence of what the human
        // was actually shown.
        function selected(): string {
            return root.selectedId;
        }
    }

    // THE ONE TIMER. 1 Hz, running only while the overlay is open with
    // something to count down — a UI clock with a visible consumer, not
    // the continuous polling §6.3 prohibits. It stops the moment the
    // overlay closes or the card is decided.
    Timer {
        id: countdown

        interval: 1000
        repeat: true
        running: root.open && root.windowVisible && root.actionable
        onTriggered: root.nowMs = Date.now()
    }

    // A decided card stays up long enough to read its verdict, then the
    // overlay advances or closes (D-003's `.ap.decided` state).
    Timer {
        id: lingerTimer

        interval: 2600
        onTriggered: {
            root.selectedId = "";
            root.syncGate();
            if (Approvals.pendingCount === 0 || root.nextUndeferred() === "")
                root.dismiss();
        }
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: root.windowVisible = false
    }

    PanelWindow {
        id: win

        visible: root.windowVisible
        anchors {
            top: true
            bottom: true
            left: true
            right: true
        }
        exclusionMode: ExclusionMode.Ignore
        color: "transparent" // scrim + card own all visible pixels
        WlrLayershell.namespace: "punar-approval"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive : WlrKeyboardFocus.None

        onVisibleChanged: {
            if (win.visible)
                keys.forceActiveFocus();
        }

        Connections {
            target: root

            // Re-arm keyboard focus on every open, not only on creation:
            // a reopen inside the 300 ms hide animation keeps the same
            // window, so `onVisibleChanged` never fires and the card would
            // come back focus-less, swallowing Esc (the M7 AI-panel bug).
            function onOpenChanged(): void {
                if (root.open)
                    keys.forceActiveFocus();
            }
        }

        // Warm ink-wash scrim at 22% — the token curve, show/hide only.
        Rectangle {
            anchors.fill: parent
            color: Theme.inkWash
            opacity: root.open ? 1 : 0

            Behavior on opacity {
                NumberAnimation {
                    duration: Theme.durStandard
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }

            MouseArea {
                // Keyboard-first, but a scrim click defers too (Esc
                // parity). A click outside a gate is not an answer.
                anchors.fill: parent
                onClicked: root.defer()
            }
        }

        // ---- the approval card (Plate D-003 .ap) ----
        Rectangle {
            id: card

            width: Math.min(520, win.width * 0.8)
            implicitHeight: cardBody.implicitHeight + 34
            height: card.implicitHeight
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? Math.round((win.height - height) / 2)
                         : Math.round((win.height - height) / 2) + 10
            color: Theme.paperSurface
            border.width: Theme.hairline
            border.color: Theme.border
            radius: Theme.radius
            opacity: root.open ? 1 : 0
            // Soft drop shadow deliberately omitted (llvmpipe budget; the
            // scrim + hairline carry separation — the M1/M2 deviation).

            Behavior on opacity {
                NumberAnimation {
                    duration: Theme.durStandard
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }
            Behavior on y {
                NumberAnimation {
                    duration: Theme.durStandard
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }

            FocusScope {
                id: keys

                anchors.fill: parent
                focus: true

                Keys.onPressed: function (event) {
                    switch (event.key) {
                    case Qt.Key_A:
                        root.resolve("approved");
                        event.accepted = true;
                        break;
                    case Qt.Key_D:
                        root.resolve("denied");
                        event.accepted = true;
                        break;
                    case Qt.Key_Escape:
                        // Dismissal is not denial.
                        root.defer();
                        event.accepted = true;
                        break;
                    case Qt.Key_Down:
                    case Qt.Key_J:
                        root.moveSelection(1);
                        event.accepted = true;
                        break;
                    case Qt.Key_Up:
                    case Qt.Key_K:
                        root.moveSelection(-1);
                        event.accepted = true;
                        break;
                    }
                }
            }

            Column {
                id: cardBody

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                anchors.topMargin: 18
                spacing: 0

                // ---- head: id, count badge, risk pill, live countdown ----
                Item {
                    width: parent.width
                    height: 22

                    Row {
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 0

                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "Approval"
                            color: Theme.ink
                        }
                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            text: " · " + (root.selectedId === "" ? "none" : root.selectedId)
                        }
                        // The multi-approval badge (D-003 Sect III lists
                        // the queue under "states not drawn"; this is the
                        // count half of it, and the ↑↓ legend is below).
                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            visible: Approvals.pendingCount > 1 && root.pendingIndex >= 0
                            text: "  " + (root.pendingIndex + 1) + " of " + Approvals.pendingCount
                            color: Theme.inputBorder
                        }
                    }

                    Row {
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 10

                        Pill {
                            anchors.verticalCenter: parent.verticalCenter
                            visible: root.field("risk") !== ""
                            text: root.field("risk")
                            tone: {
                                switch (root.field("risk")) {
                                case "high":
                                case "critical":
                                    return Theme.statusBad;
                                case "medium":
                                    return Theme.statusWarn;
                                default:
                                    return Theme.ink3;
                                }
                            }
                        }

                        // The live countdown, tabular (Geist Mono is
                        // inherently tabular), warn-amber under a minute.
                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            font.letterSpacing: Theme.tracking(9, 0.13)
                            text: {
                                if (root.decided)
                                    return root.shownStatus;
                                if (root.lapsed)
                                    return "Expired";
                                return "Expires " + Approvals.clock(root.secondsLeft);
                            }
                            color: {
                                if (root.decided)
                                    return Theme.ink3;
                                if (root.lapsed)
                                    return Theme.statusBad;
                                return root.secondsLeft < 60 ? Theme.statusWarn : Theme.ink3;
                            }
                        }
                    }
                }

                Item {
                    width: parent.width
                    height: 10
                }

                // The 2 px ink rule that closes the masthead (§3).
                Rectangle {
                    width: parent.width
                    height: 2
                    color: Theme.ink
                }

                Item {
                    width: parent.width
                    height: 12
                }

                // ---- identity chain, one mono line ----
                Meta {
                    width: parent.width
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.13)
                    text: root.identityChain()
                    elide: Text.ElideRight
                }

                Item {
                    width: parent.width
                    height: 14
                }

                // ---- the SYSTEM voice: what is being asked ----
                Text {
                    width: parent.width
                    text: root.requestSentence()
                    font.family: Theme.fontSans
                    font.pixelSize: 17
                    font.weight: 500
                    color: Theme.ink
                    wrapMode: Text.WordWrap
                    textFormat: Text.PlainText
                }

                Item {
                    width: parent.width
                    height: 6
                }

                // ---- the REQUESTER voice: their own words, quoted ----
                //
                // Typographically quarantined (milestone-9.md §8.3): a
                // quoted attribution in the sans body register, indented
                // behind a rule, never the tracked mono the system speaks
                // in. Plain text, no rich formatting, no link activation —
                // the human is never invited to read agent text as an OS
                // statement.
                Item {
                    width: parent.width
                    height: reasonText.implicitHeight + 4
                    visible: root.field("reason") !== ""

                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        width: Theme.hairline
                        color: Theme.border
                    }

                    Text {
                        id: reasonText

                        anchors.left: parent.left
                        anchors.leftMargin: 10
                        anchors.right: parent.right
                        anchors.top: parent.top
                        text: root.requesterName() + " says: “" + root.field("reason") + "”"
                        font.family: Theme.fontSans
                        font.pixelSize: 14
                        font.italic: true
                        color: Theme.ink2
                        wrapMode: Text.WordWrap
                        // Requester-authored text: plain, inert, no links.
                        textFormat: Text.PlainText
                    }
                }

                Item {
                    width: parent.width
                    height: 14
                }

                // ---- contract block, between hairlines (D-003 .contract) ----
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.border
                }

                Column {
                    width: parent.width
                    topPadding: 10
                    bottomPadding: 10
                    spacing: 3

                    Row {
                        spacing: 0

                        Meta {
                            font.pixelSize: 9
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(9, 0.1)
                            text: "One-time execution · "
                        }
                        // The exact typed capability that will run — never
                        // a root shell (spec §10, §60).
                        Meta {
                            font.pixelSize: 9
                            font.weight: 600
                            font.letterSpacing: Theme.tracking(9, 0.1)
                            color: Theme.ink
                            text: root.contractCall()
                        }
                    }
                    Meta {
                        width: parent.width
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.1)
                        text: "Policy · " + root.policyCitation()
                        elide: Text.ElideRight
                    }
                    Meta {
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.1)
                        text: "Recorded to local audit either way"
                    }
                }

                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.border
                }

                Item {
                    width: parent.width
                    height: 14
                }

                // ---- actions, or the verdict once decided ----
                Item {
                    width: parent.width
                    height: 34
                    visible: !root.decided

                    Row {
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 10

                        ActionButton {
                            label: "Deny"
                            binding: "D"
                            tone: Theme.destructive
                            enabledLook: root.actionable
                            onActivated: root.resolve("denied")
                        }
                        ActionButton {
                            label: "Approve"
                            binding: "A"
                            filled: true
                            tone: Theme.actionBg
                            enabledLook: root.actionable
                            onActivated: root.resolve("approved")
                        }
                    }
                }

                // The verdict register (D-003's three states), drawn from
                // the record — including the audit pointer, which is what
                // ties this card to the trail (ipc.md §14.3).
                Item {
                    width: parent.width
                    height: 34
                    visible: root.decided || root.lapsed

                    Text {
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        width: parent.width
                        text: root.verdictText()
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        font.weight: 600
                        font.letterSpacing: Theme.tracking(10, 0.12)
                        font.capitalization: Font.AllUppercase
                        color: root.verdictGood() ? Theme.statusOk : Theme.statusBad
                        elide: Text.ElideRight
                        textFormat: Text.PlainText
                    }
                }

                // ---- foot ----
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.border
                }

                Item {
                    width: parent.width
                    height: 26

                    Meta {
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 8
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(8, 0.13)
                        text: Approvals.pendingCount > 1
                            ? "Esc · decide later · ↑↓ next"
                            : "Esc · decide later (request stays pending)"
                    }
                    Meta {
                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 8
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(8, 0.13)
                        text: "Punar · local approval"
                    }
                }
            }
        }
    }
}
