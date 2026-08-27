pragma ComponentBehavior: Bound
// NotificationCenter — the PUNAR+SHIFT+N surface, implementing
// docs/design/mockups/notifications-osd.html Sect II (Plate D-009, the
// acceptance reference): a paper card on the warm ink-wash scrim holding
// the ledger of interruptions, grouped by who spoke, walked with j/k,
// dismissed with x, cleared with C, quieted with D.
//
// "THE CENTRE IS A LEDGER OF INTERRUPTIONS, GROUPED BY WHO SPOKE" — and
// it reads three registers rather than keeping one of its own:
//
//   Approvals      punard's `/run/punard/approvals.json`, via the M9
//                  Approvals singleton. STICKY: `x` and `Clear all` skip
//                  them, because an approval is a decision, not noise —
//                  it leaves by being approved, denied or expiring
//                  (D-009 Sect II register 04).
//   punar-agentd   `/run/punar-agentd/alerts.json`, via the M10 Alerts
//                  singleton — THE SAME READER the alert region uses, not
//                  a second copy of it. Also sticky, for the same reason.
//   Applications   this shell's own freedesktop notification daemon, via
//                  Services/Notifications.qml. The only rows `x` and
//                  `Clear all` touch.
//
// The sticky rule is therefore true BY CONSTRUCTION: approvals and alerts
// are not in the notification daemon's model at all, so no code path
// exists that could clear them, and none can be introduced by accident.
//
// DO NOT DISTURB, AND THE EXCEPTION PRINTED BESIDE IT (Sect II register
// 03). Quiet silences toasts, never the record: every row below is
// present whether or not the toast ever appeared. It applies to every
// freedesktop urgency including `Critical`, because urgency is asserted
// by the sender and a sender must not defeat the user's own switch. What
// quiet cannot reach are the two surfaces this shell does not route
// through the daemon — the M9 approval gate, which opens itself, and the
// M10 first-sighting shadow-AI alert, whose milestone-10.md §5.5 rule is
// that a first sighting always appears. Deadlines and first sightings
// outrank quiet, and the rule is printed on the surface in the warn tone
// because it is a promise about a warn state.
//
// WHEN ANOTHER DAEMON OWNS THE BUS NAME, THE EMPTY STATE TELLS THE TRUTH.
// A calm "nothing is waiting" over a session where Punar is receiving
// nothing at all would be the most comfortable lie this shell could tell.
// The Notifications singleton probes the owner of
// `org.freedesktop.Notifications` by PID; when the owner is provably
// someone else, this surface says so, names the process, and drops the
// calm empty state entirely (spec 1.22).
//
// KEYBOARD-FIRST, AND EVERY KEY PRINTED (spec 12.1 / 12.3, D-009 Sect IV):
//   j / ↓   next row          k / ↑   previous row
//   x       dismiss           ↵       open what the row points at
//   C       clear all         D       do not disturb
//   Esc     close
// The footer names all of them, because "discoverability is a printed
// fact, not a memory test".
//
// TIMERS (spec 6.3): exactly one, the approval countdown, and it runs
// ONLY while this surface is open. A closed centre holds no running timer;
// the shell's idle cost with notifications shipped is unchanged.
//
// Expected memory: one paper card holding a Flickable over rows that are
// short strings plus references to records three other singletons already
// hold. It introduces no cache, no image path and no history file
// (the daemon's records are the history), so its resident cost is the
// window plus its delegates — the same order as the M7 AI panel, and well
// inside the shell's share of the budget. The services RSS gate
// (spec 6.2) sums the punar daemons and is untouched by this file: nothing
// here adds a resident process.
//
// Toggled from Hyprland via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call notifications toggle
//
// INTEGRATION (shell.qml, which this file does not own). The three
// notification surfaces are siblings; the two cross-surface signals follow
// the AlertStack.onInspectRequested precedent and are connected by the
// shell root:
//
//     ToastStack {
//         onCenterRequested: notificationCenter.show()
//     }
//     NotificationCenter {
//         id: notificationCenter
//         onApprovalRequested: function (approvalId) {
//             approvalOverlay.selectedId = approvalId;   // its own cursor
//             approvalOverlay.show();
//         }
//         onInspectRequested: function (detectionId) {
//             aiPanel.showDetection(detectionId);
//         }
//     }
//     Osd {
//     }
//
// Unconnected, every one of those actions is inert rather than broken: the
// row simply does not open anything, and the surface says nothing about a
// key it cannot honour.

import QtQuick
import Quickshell
import Quickshell.Wayland
import "../Theme"
import "../Services"

DeferredSurfaceBase {
    id: root

    // Loader contract used by the isolated cost probe. Production opens the
    // surface through shell.qml's DeferredSurface wrapper; the probe passes
    // this flag at construction time so Loader.Ready and show() remain two
    // separately measured timestamps, matching every other deferred surface.
    property bool openOnReady: false
    property bool windowVisible: false

    // The row under the cursor, keyed by the id its own register uses.
    property string selectedKey: ""

    // Live clock for the approval countdown. Ticks only while open.
    property real nowMs: Date.now()

    // Wired in shell.qml — the AlertStack.onInspectRequested precedent, so
    // this surface never reaches into another one directly, and a shell
    // built without those surfaces simply has nothing connected.
    signal approvalRequested(string approvalId)
    signal inspectRequested(string detectionId)

    // ---- shared type grammar (DESIGN_LANGUAGE.md §1) ----

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.13)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        textFormat: Text.PlainText
    }

    // Mono with its CASE PRESERVED: evidence, not labels — a path, an id,
    // a body line. The meta grammar uppercases labels, never evidence.
    component Data: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 500
        font.letterSpacing: Theme.tracking(9, 0.1)
        color: Theme.shellInk3
        textFormat: Text.PlainText
    }

    component Pill: Rectangle {
        id: pill

        property string text: ""
        property color tone: Theme.shellInk3

        implicitWidth: pillLabel.implicitWidth + 14
        implicitHeight: pillLabel.implicitHeight + 5
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

    // A ghost control carrying its printed key (D-009 `.ghost`). Every key
    // it prints is bound in Keys.onPressed below — the surface holds the
    // keyboard whenever it is open, so no hint here is speculative.
    component KeyButton: Rectangle {
        id: keyButton

        property string label: ""
        property string binding: ""
        property color tone: Theme.shellInk3

        signal activated

        implicitWidth: keyButtonRow.implicitWidth + 18
        implicitHeight: keyButtonRow.implicitHeight + 10
        radius: Theme.radiusTag
        color: "transparent"
        border.width: Theme.hairline
        border.color: keyButton.tone

        Row {
            id: keyButtonRow

            anchors.centerIn: parent
            spacing: 5

            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: keyButton.label
                font.family: Theme.fontMono
                font.pixelSize: 9
                font.weight: 600
                font.letterSpacing: Theme.tracking(9, 0.1)
                font.capitalization: Font.AllUppercase
                color: keyButton.tone
                textFormat: Text.PlainText
            }

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                visible: keyButton.binding !== ""
                width: keyButtonCap.implicitWidth + 8
                height: keyButtonCap.implicitHeight + 3
                radius: 3
                color: "transparent"
                border.width: Theme.hairline
                border.color: keyButton.tone
                opacity: 0.7

                Text {
                    id: keyButtonCap

                    anchors.centerIn: parent
                    text: keyButton.binding
                    font.family: Theme.fontMono
                    font.pixelSize: 8
                    font.weight: 600
                    color: keyButton.tone
                    textFormat: Text.PlainText
                }
            }
        }

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: keyButton.activated()
        }
    }

    // ---- the ledger ----
    //
    // One flat list so j/k walk everything in one motion; each row knows
    // whether it opens a group, so the headers are drawn from the same
    // pass and can never disagree with the rows beneath them.
    readonly property var rows: {
        var out = [];

        var ap = Approvals.pending;
        for (var i = 0; i < ap.length; i++) {
            out.push({
                kind: "approval",
                key: Approvals.id(ap[i]),
                group: "Approvals",
                head: i === 0,
                rec: ap[i]
            });
        }

        var al = Alerts.active;
        for (var j = 0; j < al.length; j++) {
            out.push({
                kind: "alert",
                key: Alerts.id(al[j]),
                group: "punar-agentd",
                head: j === 0,
                rec: al[j]
            });
        }

        var groups = Notifications.groups;
        for (var g = 0; g < groups.length; g++) {
            var items = groups[g].items;
            for (var k = 0; k < items.length; k++) {
                out.push({
                    kind: "notif",
                    key: Notifications.key(items[k]),
                    group: groups[g].source,
                    head: k === 0,
                    rec: items[k]
                });
            }
        }
        return out;
    }

    readonly property int rowCount: root.rows.length

    // Sticky rows resolve; they never dismiss.
    function isSticky(kind: string): bool {
        return kind !== "notif";
    }

    readonly property bool hasSticky: Approvals.pendingCount > 0 || Alerts.activeCount > 0

    function rowIndex(key: string): int {
        for (var i = 0; i < root.rows.length; i++) {
            if (root.rows[i].key === key)
                return i;
        }
        return -1;
    }

    function selectedRow(): var {
        var at = root.rowIndex(root.selectedKey);
        return at < 0 ? null : root.rows[at];
    }

    // NOTE — these two read `root.rows` DIRECTLY and never `root.rowCount`.
    // `rowCount` is its own binding, and QML re-evaluates bindings lazily:
    // inside `onRowsChanged` the list is already new while the derived
    // count may still be the old one. Trusting the count there indexes off
    // the end of the list (observed as a TypeError on the first clear-all).
    // The list is the single source of its own length.
    function moveSelection(delta: int): void {
        var list = root.rows;
        if (list.length === 0)
            return;
        var at = root.rowIndex(root.selectedKey);
        at = (at < 0 ? 0 : at) + delta;
        at = Math.max(0, Math.min(list.length - 1, at));
        root.selectedKey = list[at].key;
    }

    // Keep the reader's place across a rewrite of any of the three
    // registers; land on the first row when the selection disappears.
    function reselect(): void {
        var list = root.rows;
        if (list.length === 0) {
            root.selectedKey = "";
            return;
        }
        if (root.rowIndex(root.selectedKey) < 0)
            root.selectedKey = list[0].key;
    }

    onRowsChanged: root.reselect()

    // ---- row copy ----
    //
    // Every builder drops a clause the record does not carry. An absent
    // field is absent, never a placeholder and never a guess (spec 1.22).

    // The typed call punard will run if this approval is granted.
    function approvalSentence(rec: var): string {
        var explicit = Approvals.str(rec, "contract");
        if (explicit !== "")
            return "Approval waiting · " + explicit;
        var cap = Approvals.str(rec, "capability");
        var res = Approvals.str(rec, "resource");
        if (cap === "")
            return "Approval waiting";
        return "Approval waiting · " + (res === "" ? cap : cap + " · " + res);
    }

    function approvalSub(rec: var): string {
        var parts = [];
        var id = Approvals.str(rec, "approval_id");
        if (id !== "")
            parts.push(id);
        var requester = (rec !== null && typeof rec === "object") ? rec.requester : null;
        var who = Approvals.str(requester, "agent_name");
        if (who === "")
            who = Approvals.str(requester, "id");
        if (who === "")
            who = Approvals.str(rec, "user");
        if (who !== "")
            parts.push(who);
        parts.push("Enter opens the approval card");
        return parts.join(" · ");
    }

    function alertSentence(rec: var): string {
        var name = Alerts.str(rec, "agent");
        return "Unknown AI activity suspected · " + (name === "" ? "an unnamed process" : name);
    }

    function alertSub(rec: var): string {
        var parts = [];
        var exe = Alerts.str(rec, "executable");
        var owner = Alerts.str(rec, "owner");
        if (exe !== "") {
            var home = owner === "root" ? "/root/" : "/home/" + owner + "/";
            parts.push(owner !== "" && exe.indexOf(home) === 0
                       ? "~/" + exe.substring(home.length) : exe);
        }
        parts.push("suspected, not certain");
        parts.push("Enter inspects");
        return parts.join(" · ");
    }

    function notifSub(rec: var): string {
        var parts = [];
        var detail = Notifications.detailOf(rec);
        if (detail !== "")
            parts.push(detail.replace(/\s+/g, " "));
        var at = Notifications.timeOf(rec);
        if (at !== "")
            parts.push(at);
        var acts = Notifications.actionsOf(rec);
        if (acts.length > 0) {
            var label = acts[0].text;
            parts.push("Enter · " + ((typeof label === "string" && label !== "") ? label : acts[0].identifier));
        }
        return parts.join(" · ");
    }

    function rowSentence(row: var): string {
        switch (row.kind) {
        case "approval":
            return root.approvalSentence(row.rec);
        case "alert":
            return root.alertSentence(row.rec);
        default:
            return Notifications.sentenceOf(row.rec);
        }
    }

    function rowSub(row: var): string {
        switch (row.kind) {
        case "approval":
            return root.approvalSub(row.rec);
        case "alert":
            return root.alertSub(row.rec);
        default:
            return root.notifSub(row.rec);
        }
    }

    // ---- actions ----

    // `x` — dismisses ONLY an application notification. Approvals and AI
    // alerts resolve; they do not dismiss, and the footer says so
    // permanently rather than scolding after the fact.
    function dismissSelected(): void {
        var row = root.selectedRow();
        if (row === null || root.isSticky(row.kind))
            return;
        Notifications.dismissKey(row.key);
    }

    // `Enter` — opens whatever the row points at. A row with nothing to
    // open does nothing AND says nothing about Enter in its subline, so no
    // key is ever printed that would not fire.
    function openSelected(): void {
        var row = root.selectedRow();
        if (row === null)
            return;
        if (row.kind === "approval") {
            root.hide();
            root.approvalRequested(row.key);
            return;
        }
        if (row.kind === "alert") {
            root.hide();
            root.inspectRequested(Alerts.str(row.rec, "detection_id"));
            return;
        }
        var acts = Notifications.actionsOf(row.rec);
        if (acts.length === 0)
            return;
        Notifications.invokeAction(acts[0]);
    }

    // `C` — clears application notifications only, by construction.
    function clearAll(): void {
        Notifications.clearAll();
    }

    // ---- surface ----

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("notifications");
        hideTimer.stop();
        // One-shot re-reads: they cover a register whose file did not exist
        // when the watch was armed (a daemon started after the shell). An
        // event per open, never a poll.
        Approvals.refresh();
        Alerts.refresh();
        Notifications.probeOwnership();
        // The toasts step aside: the record they were a copy of is now on
        // screen (Services/Notifications.qml `centreOpened`).
        Notifications.noteCentreOpened();
        root.nowMs = Date.now();
        root.reselect();
        root.windowVisible = true;
        root.open = true;
    }

    Component.onCompleted: {
        SurfaceTiming.constructed("notifications");
        if (root.openOnReady)
            root.show();
    }

    function hide(): void {
        if (!root.open)
            return;
        root.open = false;
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle(): void {
        if (root.open)
            root.hide();
        else
            root.show();
    }

    function dismiss(): void {
        root.hide();
    }

    function ipcState(): string {
        return root.open ? "open" : "closed";
    }

    // Read-only and mutation methods are exposed through shell.qml's tiny
    // resident IPC proxy. The visual ledger itself exists only while someone
    // is using it.
    function ipcCount(): string {
        return String(root.rowCount);
    }

    function ipcFocused(): string {
        return root.selectedKey;
    }

    function ipcOwner(): string {
        return Notifications.ownership;
    }

    function ipcDismiss(): string {
        var key = root.selectedKey;
        root.dismissSelected();
        return key;
    }

    function ipcClear(): string {
        var n = Notifications.count;
        root.clearAll();
        return String(n);
    }

    function ipcDnd(mode: string): string {
        if (mode === "on")
            Notifications.setDnd(true);
        else if (mode === "off")
            Notifications.setDnd(false);
        else if (mode === "toggle")
            Notifications.toggleDnd();
        return Notifications.dnd ? "on" : "off";
    }

    Timer {
        id: hideTimer

        interval: Theme.durStandard
        repeat: false
        onTriggered: {
            root.windowVisible = false;
            root.unloadRequested();
        }
    }

    // The ONE clock on this surface, and it runs only while the surface is
    // open (spec 6.3 / PERFORMANCE_BUDGETS.md). It exists because an
    // approval's expiry is a deadline someone is waiting on; a closed
    // centre has no deadline to draw.
    Timer {
        interval: 1000
        repeat: true
        running: root.open && Approvals.pendingCount > 0
        onTriggered: root.nowMs = Date.now()
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
        color: "transparent" // the scrim and card own every visible pixel
        WlrLayershell.namespace: "punar-notifications"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

        onVisibleChanged: {
            if (win.visible && root.open)
                centerKeys.forceActiveFocus();
        }

        Connections {
            target: root

            // Re-arm focus on every open, not only on creation: an open
            // inside the 300 ms hide animation keeps the same window, so
            // `onVisibleChanged` never fires and the surface would come
            // back focus-less, swallowing Esc (the M7 bug, re-learned in
            // M9 and not re-learned here).
            function onOpenChanged(): void {
                if (root.open)
                    centerKeys.forceActiveFocus();
            }
        }

        // Warm ink-wash scrim at 22% (DESIGN_LANGUAGE.md §3 / the
        // command-center mockup: "the warm ink wash at 22%, never a
        // blur-only dim").
        Rectangle {
            anchors.fill: parent
            color: Theme.shellScrim
            opacity: root.open ? 1 : 0

            Behavior on opacity {
                NumberAnimation {
                    duration: Theme.durStandard
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }

            MouseArea {
                // Keyboard-first, but a scrim click still defers (Esc parity).
                anchors.fill: parent
                onClicked: root.hide()
            }
        }

        FocusScope {
            id: centerKeys

            anchors.fill: parent
            focus: true

            Keys.onPressed: function (event) {
                switch (event.key) {
                case Qt.Key_Escape:
                    root.hide();
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
                case Qt.Key_X:
                    root.dismissSelected();
                    event.accepted = true;
                    break;
                case Qt.Key_Return:
                case Qt.Key_Enter:
                    root.openSelected();
                    event.accepted = true;
                    break;
                case Qt.Key_C:
                    root.clearAll();
                    event.accepted = true;
                    break;
                case Qt.Key_D:
                    Notifications.toggleDnd();
                    event.accepted = true;
                    break;
                }
            }

            // ---- the centre card (D-009 `.centerwrap`) ----
            Rectangle {
                id: card

                width: Math.min(680, Math.round(win.width * 0.78))
                anchors.horizontalCenter: parent.horizontalCenter
                y: root.open ? Math.round(win.height * 0.09) : Math.round(win.height * 0.09) - 10
                height: Math.min(Math.round(win.height * 0.78), cardColumn.implicitHeight)
                color: Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellBorder
                radius: Theme.radius
                clip: true
                opacity: root.open ? 1 : 0
                // The mockup's soft drop shadow is omitted deliberately:
                // blur is costly on the llvmpipe VM path and the scrim
                // already separates the card (the standing M1/M2
                // deviation, PERFORMANCE_BUDGETS.md).

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

                MouseArea {
                    // Block clicks from falling through to the scrim.
                    anchors.fill: parent
                }

                Column {
                    id: cardColumn

                    width: parent.width

                    // ---- masthead (DESIGN_LANGUAGE.md §5) ----
                    Item {
                        width: parent.width
                        height: 34

                        Row {
                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 0

                            Meta {
                                text: "Punar"
                                color: Theme.shellFg
                            }
                            Meta {
                                text: " · Notification centre"
                            }
                            // UNMANAGED-FIRST (§8): the org name is
                            // ADDITIVE chrome. Its absence is calm paper,
                            // never an "unenrolled" notice.
                            Meta {
                                visible: Status.enrolled && Status.orgName !== ""
                                text: " · " + Status.orgName
                            }
                        }

                        Meta {
                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            text: "Punar+Shift+N"
                        }
                    }

                    // The masthead rule (§5: a 2px ink rule closes the
                    // header block, exactly as the field-note masthead does).
                    Rectangle {
                        width: parent.width
                        height: 2
                        color: Theme.shellFg
                    }

                    // ---- head: count and clear-all ----
                    Item {
                        width: parent.width
                        height: 44

                        Meta {
                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            color: Theme.shellFg
                            text: "Notifications · " + root.rowCount
                        }

                        KeyButton {
                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            visible: Notifications.count > 0
                            label: "Clear all"
                            binding: "C"
                            onActivated: root.clearAll()
                        }
                    }

                    // ---- the honest banner ----
                    //
                    // Drawn ONLY for a PROVEN foreign owner — one whose PID
                    // is not this process. An unverified probe manufactures
                    // neither an alarm nor a reassurance.
                    Item {
                        width: parent.width
                        height: visible ? bannerText.implicitHeight + 26 : 0
                        visible: !Notifications.ownershipHealthy()

                        Rectangle {
                            anchors.fill: parent
                            anchors.leftMargin: 16
                            anchors.rightMargin: 16
                            anchors.topMargin: 2
                            anchors.bottomMargin: 10
                            color: "transparent"
                            border.width: Theme.hairline
                            border.color: Theme.shellStatusWarn
                            radius: Theme.radiusTag

                            Data {
                                id: bannerText

                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10
                                color: Theme.shellStatusWarn
                                wrapMode: Text.WordWrap
                                text: "Another notification daemon owns org.freedesktop.Notifications"
                                      + (Notifications.ownerName === "" ? "" : " · " + Notifications.ownerName)
                                      + " · pid " + Notifications.ownerPid
                                      + " — application notifications are reaching it, not Punar. Stop that process and restart the shell."
                            }
                        }
                    }

                    // ---- the ledger ----
                    //
                    // A Flickable over a plain Column, NOT a virtualising
                    // ListView: the row heights are content-derived and the
                    // surface's own height is derived from them in turn, so
                    // an estimated `contentHeight` would chase itself. The
                    // list is short by nature — a centre with hundreds of
                    // rows is a bug in something else, and `Clear all` is
                    // one key away.
                    Item {
                        width: parent.width
                        height: root.rowCount === 0 ? 0 : Math.min(Math.round(win.height * 0.44), rowsColumn.implicitHeight)
                        visible: root.rowCount > 0

                        Flickable {
                            id: list

                            anchors.fill: parent
                            clip: true
                            contentWidth: width
                            contentHeight: rowsColumn.implicitHeight
                            boundsBehavior: Flickable.StopAtBounds

                            // Keep the keyboard cursor on screen. Called by
                            // a row when it becomes selected — an event,
                            // never a per-frame check.
                            function reveal(top: real, rowHeight: real): void {
                                var maxY = Math.max(0, list.contentHeight - list.height);
                                var target = list.contentY;
                                if (top < target)
                                    target = top;
                                else if (top + rowHeight > target + list.height)
                                    target = top + rowHeight - list.height;
                                list.contentY = Math.max(0, Math.min(maxY, target));
                            }

                            Column {
                                id: rowsColumn

                                width: list.width

                                Repeater {
                                    model: root.rows

                                    delegate: Column {
                                        id: rowItem

                                        required property var modelData

                                        readonly property bool isSelected: rowItem.modelData.key === root.selectedKey
                                        readonly property bool isBad: rowItem.modelData.kind === "alert"
                                        readonly property int secondsLeft: rowItem.modelData.kind === "approval"
                                            ? Approvals.secondsUntil(Approvals.str(rowItem.modelData.rec, "expires_at"), root.nowMs)
                                            : 0

                                        width: rowsColumn.width

                                        onIsSelectedChanged: {
                                            if (rowItem.isSelected)
                                                list.reveal(rowItem.y, rowItem.height);
                                        }

                                        // ---- group head (D-009 `.gsrc`) ----
                                        //
                                        // "A notification always names its
                                        // speaker; anonymous interruptions do not
                                        // exist."
                                        Item {
                                            width: parent.width
                                            height: rowItem.modelData.head ? 26 : 0
                                            visible: rowItem.modelData.head

                                            Meta {
                                                anchors.left: parent.left
                                                anchors.leftMargin: 16
                                                anchors.bottom: parent.bottom
                                                anchors.bottomMargin: 5
                                                color: Theme.shellInk2
                                                text: rowItem.modelData.group
                                            }

                                            Rectangle {
                                                anchors.left: parent.left
                                                anchors.right: parent.right
                                                anchors.leftMargin: 16
                                                anchors.rightMargin: 16
                                                anchors.bottom: parent.bottom
                                                height: Theme.hairline
                                                color: Theme.shellBorder
                                            }
                                        }

                                        // ---- the row ----
                                        Rectangle {
                                            width: parent.width
                                            implicitHeight: rowBody.implicitHeight + 18
                                            height: implicitHeight
                                            // Selection is the raise fill plus a
                                            // 2 px ink left rule — the house
                                            // vocabulary from the command center,
                                            // and colour-independent (§9.4).
                                            color: rowItem.isSelected ? Theme.shellRaise2 : "transparent"

                                            Rectangle {
                                                anchors.left: parent.left
                                                anchors.top: parent.top
                                                anchors.bottom: parent.bottom
                                                width: 2
                                                visible: rowItem.isSelected
                                                color: Theme.shellFg
                                            }

                                            MouseArea {
                                                anchors.fill: parent
                                                onClicked: root.selectedKey = rowItem.modelData.key
                                                onDoubleClicked: {
                                                    root.selectedKey = rowItem.modelData.key;
                                                    root.openSelected();
                                                }
                                            }

                                            Column {
                                                id: rowBody

                                                anchors.left: parent.left
                                                anchors.right: parent.right
                                                anchors.verticalCenter: parent.verticalCenter
                                                anchors.leftMargin: 16
                                                anchors.rightMargin: 16
                                                spacing: 4

                                                Item {
                                                    width: parent.width
                                                    height: rowClaim.implicitHeight

                                                    Text {
                                                        id: rowClaim

                                                        anchors.left: parent.left
                                                        anchors.right: rowPill.visible ? rowPill.left : parent.right
                                                        anchors.rightMargin: rowPill.visible ? 10 : 0
                                                        text: root.rowSentence(rowItem.modelData)
                                                        font.family: Theme.fontSans
                                                        font.pixelSize: 13
                                                        font.weight: 500
                                                        // The ONLY red in the
                                                        // panel is the suspected-AI
                                                        // row (Sect II register 02).
                                                        color: rowItem.isBad ? Theme.shellStatusBad : Theme.shellFg
                                                        elide: Text.ElideRight
                                                        textFormat: Text.PlainText
                                                    }

                                                    // The live datum, right-aligned:
                                                    // an expiry in the warn tone,
                                                    // because an approval is a
                                                    // deadline someone is waiting on.
                                                    Pill {
                                                        id: rowPill

                                                        anchors.right: parent.right
                                                        anchors.verticalCenter: parent.verticalCenter
                                                        visible: rowItem.modelData.kind === "approval"
                                                        tone: Theme.shellStatusWarn
                                                        text: rowItem.secondsLeft > 0
                                                            ? "Expires " + Approvals.clock(rowItem.secondsLeft)
                                                            : "Expired"
                                                    }
                                                }

                                                Data {
                                                    width: parent.width
                                                    text: root.rowSub(rowItem.modelData)
                                                    color: rowItem.isBad ? Theme.shellInk2 : Theme.shellInk3
                                                    elide: Text.ElideRight
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // ---- the calm empty state ----
                    //
                    // It must read FINISHED, not broken — so it appears
                    // only when the daemon is actually receiving. When
                    // another process owns the bus name the banner above
                    // has already said so and this stays hidden, because
                    // "nothing is waiting" would then be false.
                    Item {
                        width: parent.width
                        height: visible ? 132 : 0
                        visible: root.rowCount === 0

                        Column {
                            anchors.centerIn: parent
                            width: parent.width - 48
                            spacing: 10

                            Text {
                                anchors.horizontalCenter: parent.horizontalCenter
                                text: Notifications.ownershipHealthy()
                                    ? "Nothing is waiting."
                                    : "Punar is not receiving notifications."
                                font.family: Theme.fontSans
                                font.pixelSize: 17
                                font.weight: 500
                                color: Theme.shellFg
                                textFormat: Text.PlainText
                            }

                            Data {
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.WordWrap
                                color: Theme.shellInk3
                                text: Notifications.ownershipHealthy()
                                    ? "Applications and Punar file their interruptions here. An empty centre means everything has been read — not that something was lost."
                                    : "The banner above names the process holding the notification bus name."
                            }
                        }
                    }

                    // ---- do not disturb (D-009 `.dndrow`) ----
                    Rectangle {
                        width: parent.width
                        height: Theme.hairline
                        color: Theme.shellBorder
                    }

                    Item {
                        width: parent.width
                        height: dndText.implicitHeight + 28

                        // The switch. Its state is a word as well as a
                        // position — the knob alone is not a reading.
                        Rectangle {
                            id: dndToggle

                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            width: 34
                            height: 18
                            radius: 9
                            color: Notifications.dnd ? Theme.shellFg : "transparent"
                            border.width: Theme.hairline
                            border.color: Notifications.dnd ? Theme.shellFg : Theme.shellInputBorder

                            Rectangle {
                                width: 12
                                height: 12
                                radius: 6
                                y: 3
                                x: Notifications.dnd ? dndToggle.width - width - 3 : 3
                                color: Notifications.dnd ? Theme.shellSurface : Theme.shellInputBorder

                                Behavior on x {
                                    NumberAnimation {
                                        duration: Theme.durMicro
                                        easing.type: Easing.BezierSpline
                                        easing.bezierCurve: Theme.easingCurve
                                    }
                                }
                            }

                            MouseArea {
                                anchors.fill: parent
                                cursorShape: Qt.PointingHandCursor
                                onClicked: Notifications.toggleDnd()
                            }
                        }

                        Column {
                            anchors.left: dndToggle.right
                            anchors.right: parent.right
                            anchors.leftMargin: 12
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 4

                            Meta {
                                color: Theme.shellFg
                                text: "Do not disturb · " + (Notifications.dnd ? "On · D" : "Off · D")
                            }

                            // The rule, printed in the warn tone because it
                            // is a promise about a warn state (Sect II
                            // register 03). Both halves are literally true
                            // of the shipped system: quiet suppresses this
                            // daemon's toasts, and the two surfaces named
                            // are not this daemon's to suppress.
                            Data {
                                id: dndText

                                width: parent.width
                                wrapMode: Text.WordWrap
                                color: Theme.shellStatusWarn
                                text: "Silences toasts, never the record. Approval gates and first-sighting AI alerts are not toasts — quiet never reaches them."
                            }
                        }
                    }

                    // ---- footer: every key printed (spec 12.3) ----
                    Rectangle {
                        width: parent.width
                        height: Theme.hairline
                        color: Theme.shellBorder
                    }

                    Item {
                        width: parent.width
                        height: 30

                        // The key legend always wins the space it needs;
                        // the sticky reminder appears only when a sticky
                        // row is actually on screen, and only if there is
                        // room for it. A legend that overlaps its own
                        // footnote teaches nobody anything.
                        Data {
                            id: keyLegend

                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.right: stickyHint.visible ? stickyHint.left : parent.right
                            anchors.rightMargin: stickyHint.visible ? 12 : 16
                            anchors.verticalCenter: parent.verticalCenter
                            font.pixelSize: 8
                            color: Theme.shellInputBorder
                            elide: Text.ElideRight
                            text: "j/k Move · x Dismiss · Enter Open · C Clear · D Quiet · Esc Close"
                        }

                        Data {
                            id: stickyHint

                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            font.pixelSize: 8
                            color: Theme.shellInputBorder
                            visible: root.hasSticky
                                     && card.width - keyLegend.implicitWidth - implicitWidth > 60
                            text: "Approvals and AI alerts resolve · they don't dismiss"
                        }
                    }
                }
            }
        }
    }
}
