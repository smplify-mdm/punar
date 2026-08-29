pragma ComponentBehavior: Bound
// PrivacyPanel — PUNAR+P local network visibility, Plate D-006.
//
// This surface renders only the root-owned on-demand connection view. It
// never performs DNS, packet capture, SNI parsing, or content inspection.
// Denied destinations are personal live-view data; the audit trail receives
// only their zone. Relay and DNS states keep the dashed honesty grammar until
// a real data path/protection service exists.

import QtQuick
import Quickshell
import Quickshell.Wayland
import "../Theme"
import "../Services"

DeferredSurfaceBase {
    id: root

    property bool windowVisible: false
    property int selectedIndex: 0
    property int expandedIndex: -1

    readonly property var networkView: Network.view
    readonly property var processes: {
        var view = root.networkView;
        return view !== null && view !== undefined && Array.isArray(view.processes)
            ? view.processes : [];
    }
    readonly property int connectionCount: {
        var total = 0;
        for (var i = 0; i < root.processes.length; i++) {
            var rows = root.processes[i].connections;
            total += Array.isArray(rows) ? rows.length : 0;
        }
        return total;
    }

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.14)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    component DashedTag: Item {
        id: tag
        property string label: ""
        implicitWidth: tagText.implicitWidth + 14
        implicitHeight: 18

        Canvas {
            anchors.fill: parent
            onPaint: {
                var ctx = getContext("2d");
                ctx.clearRect(0, 0, width, height);
                ctx.strokeStyle = String(Theme.shellInputBorder);
                ctx.lineWidth = 1;
                ctx.setLineDash([3, 3]);
                ctx.beginPath();
                ctx.roundedRect(0.5, 0.5, width - 1, height - 1,
                               Theme.radiusTag, Theme.radiusTag);
                ctx.stroke();
            }
            onWidthChanged: requestPaint()
            onHeightChanged: requestPaint()
        }
        Meta {
            id: tagText
            anchors.centerIn: parent
            font.pixelSize: 8
            font.letterSpacing: Theme.tracking(8, 0.1)
            text: tag.label
        }
    }

    component StatusChip: Rectangle {
        id: chip
        property string label: ""
        property string detail: ""
        property bool honestLimit: false

        implicitWidth: chipRow.implicitWidth + 20
        implicitHeight: 30
        radius: Theme.radiusTag
        color: Theme.shellSurface
        border.width: Theme.hairline
        border.color: Theme.shellBorder

        Row {
            id: chipRow
            anchors.centerIn: parent
            spacing: 7
            Meta {
                anchors.verticalCenter: parent.verticalCenter
                color: Theme.shellFg
                text: chip.label
            }
            Meta {
                anchors.verticalCenter: parent.verticalCenter
                font.weight: 500
                text: chip.detail
            }
            DashedTag {
                anchors.verticalCenter: parent.verticalCenter
                visible: chip.honestLimit
                label: "Not active"
            }
        }
    }

    function relayMode(): string {
        var view = root.networkView;
        var relay = view !== null && view.relay !== null
            && typeof view.relay === "object" ? view.relay : null;
        if (relay === null || typeof relay.mode !== "string")
            return "Unknown";
        return String(relay.mode).replace(/_/g, " ");
    }

    function scannedAt(): string {
        var view = root.networkView;
        if (view === null || typeof view.scanned_at !== "string")
            return "Not scanned";
        var date = new Date(view.scanned_at);
        return date.getTime() === date.getTime()
            ? Qt.formatDateTime(date, "d MMM · HH:mm") : view.scanned_at;
    }

    function processName(process: var): string {
        return process !== null && typeof process.name === "string"
            ? process.name : "Unknown process";
    }

    function processMeta(process: var): string {
        var parts = [];
        if (process !== null && process.governed === true)
            parts.push("Governed");
        else
            parts.push("Watched · not governed");
        var session = process !== null && typeof process.session === "object"
            ? process.session : null;
        if (session !== null) {
            if (typeof session.project === "string")
                parts.push(session.project);
            if (typeof session.id === "string")
                parts.push(session.id);
        }
        return parts.join(" · ");
    }

    function connectionLabel(connection: var): string {
        if (connection !== null && typeof connection.name === "string"
                && connection.name !== "")
            return connection.name;
        return connection !== null && typeof connection.destination === "string"
            ? connection.destination : "Unknown destination";
    }

    function connectionMeta(connection: var): string {
        var fields = [];
        for (var i = 0; i < 3; i++) {
            var key = ["zone", "category", "route"][i];
            if (connection !== null && typeof connection[key] === "string")
                fields.push(String(connection[key]).replace(/_/g, " "));
        }
        return fields.join(" · ");
    }

    function restoreSelection(): void {
        if (root.processes.length === 0) {
            root.selectedIndex = -1;
            root.expandedIndex = -1;
            return;
        }
        root.selectedIndex = Math.max(0, Math.min(root.selectedIndex,
                                                  root.processes.length - 1));
        if (root.expandedIndex < 0 || root.expandedIndex >= root.processes.length)
            root.expandedIndex = root.selectedIndex;
    }

    function moveSelection(delta: int): void {
        if (root.processes.length === 0)
            return;
        root.selectedIndex = Math.max(0, Math.min(root.processes.length - 1,
                                                  root.selectedIndex + delta));
        processList.positionViewAtIndex(root.selectedIndex, ListView.Contain);
    }

    function toggleExpanded(): void {
        if (root.selectedIndex < 0 || root.selectedIndex >= root.processes.length)
            return;
        root.expandedIndex = root.expandedIndex === root.selectedIndex
            ? -1 : root.selectedIndex;
    }

    function show(): void {
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
        Network.refresh();
        root.restoreSelection();
        processList.forceActiveFocus();
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        hideTimer.restart();
    }

    function toggle(): void {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    function ipcState(): string {
        return root.open ? "open" : "closed";
    }

    function ipcRows(): string {
        return String(root.processes.length);
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: {
            root.windowVisible = false;
            root.unloadRequested();
        }
    }

    Connections {
        target: Network
        function onViewChanged(): void {
            root.restoreSelection();
        }
    }

    PanelWindow {
        id: win
        visible: root.windowVisible
        anchors { top: true; bottom: true; left: true; right: true }
        exclusionMode: ExclusionMode.Ignore
        color: "transparent"
        WlrLayershell.namespace: "punar-privacy"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

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
            MouseArea { anchors.fill: parent; onClicked: root.dismiss() }
        }

        Rectangle {
            id: sheet
            width: Math.min(1020, win.width * 0.92)
            height: Math.min(700, win.height * 0.88)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? Math.round((win.height - height) / 2)
                         : Math.round((win.height - height) / 2) - 10
            opacity: root.open ? 1 : 0
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder
            radius: Theme.radius
            clip: true

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

            MouseArea { anchors.fill: parent }

            Item {
                id: mast
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: 62

                Column {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 3
                    Row {
                        Meta { text: "Punar"; color: Theme.shellFg }
                        Meta { text: " · Privacy" }
                    }
                    Meta {
                        font.weight: 500
                        text: Status.enrolled ? Status.orgName : "Personal · local only"
                    }
                }
                Column {
                    width: 230
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 3
                    Meta {
                        width: parent.width
                        horizontalAlignment: Text.AlignRight
                        color: Theme.shellFg
                        text: root.connectionCount + (root.connectionCount === 1
                              ? " connection" : " connections")
                    }
                    Meta {
                        width: parent.width
                        horizontalAlignment: Text.AlignRight
                        font.weight: 500
                        text: Network.refreshing ? "Scanning locally…" : root.scannedAt()
                    }
                }
            }

            Rectangle {
                id: mastRule
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: mast.bottom
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: 2
                color: Theme.shellFg
            }

            Flow {
                id: statusBand
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: mastRule.bottom
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                anchors.topMargin: 12
                spacing: 9
                height: implicitHeight

                StatusChip {
                    label: "Packet path"
                    detail: root.relayMode()
                    honestLimit: root.networkView !== null
                        && root.networkView.relay !== null
                        && typeof root.networkView.relay === "object"
                        && root.networkView.relay.simulated === true
                }
                StatusChip {
                    label: "DNS protection"
                    detail: "Phase 2"
                    honestLimit: true
                }
                StatusChip {
                    visible: root.networkView !== null
                    label: "Enforcement"
                    detail: root.networkView !== null
                        && typeof root.networkView.enforcement === "string"
                        ? String(root.networkView.enforcement) : "Unknown"
                    honestLimit: root.networkView === null
                        || root.networkView.enforcement !== "available"
                }
            }

            Meta {
                id: question
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: statusBand.bottom
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                anchors.topMargin: 14
                font.pixelSize: 10
                font.letterSpacing: Theme.tracking(10, 0.16)
                text: "Who is talking to the network?"
            }

            ListView {
                id: processList
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: question.bottom
                anchors.bottom: footRule.top
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                anchors.topMargin: 8
                anchors.bottomMargin: 8
                clip: true
                focus: true
                interactive: contentHeight > height
                model: root.processes
                spacing: 0

                Keys.onPressed: function (event) {
                    switch (event.key) {
                    case Qt.Key_Escape:
                        root.dismiss();
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
                    case Qt.Key_Return:
                    case Qt.Key_Enter:
                        root.toggleExpanded();
                        event.accepted = true;
                        break;
                    case Qt.Key_R:
                        Network.refresh();
                        event.accepted = true;
                        break;
                    }
                }

                delegate: Item {
                    id: processRow
                    required property var modelData
                    required property int index
                    width: processList.width
                    readonly property bool selected: index === root.selectedIndex
                    readonly property bool expanded: index === root.expandedIndex
                    readonly property var connections: Array.isArray(processRow.modelData.connections)
                        ? processRow.modelData.connections : []
                    readonly property var denied: Array.isArray(processRow.modelData.denied)
                        ? processRow.modelData.denied : []
                    height: 50 + (expanded
                        ? Math.max(34, (connections.length + denied.length) * 38
                                   + (typeof processRow.modelData.note === "string" ? 28 : 0))
                        : 0)

                    Rectangle {
                        anchors.fill: parent
                        color: processRow.selected ? Theme.shellMuted : "transparent"
                    }
                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        width: 2
                        visible: processRow.selected
                        color: Theme.shellFg
                    }
                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.top: parent.top
                        height: Theme.hairline
                        color: Theme.shellBorder
                    }

                    Column {
                        anchors.left: parent.left
                        anchors.leftMargin: 12
                        anchors.right: countMeta.left
                        anchors.rightMargin: 14
                        anchors.top: parent.top
                        anchors.topMargin: 9
                        spacing: 2
                        Text {
                            width: parent.width
                            text: root.processName(processRow.modelData)
                            font.family: Theme.fontSans
                            font.pixelSize: 14
                            font.weight: 600
                            color: Theme.shellFg
                            elide: Text.ElideRight
                        }
                        Meta {
                            width: parent.width
                            font.pixelSize: 8
                            font.weight: 500
                            text: root.processMeta(processRow.modelData)
                            elide: Text.ElideRight
                        }
                    }
                    Meta {
                        id: countMeta
                        anchors.right: parent.right
                        anchors.rightMargin: 10
                        anchors.top: parent.top
                        anchors.topMargin: 18
                        color: processRow.denied.length > 0
                            ? Theme.shellStatusBad : Theme.shellInk3
                        text: processRow.connections.length + " live"
                            + (processRow.denied.length > 0
                               ? " · " + processRow.denied.length + " denied" : "")
                    }

                    Column {
                        anchors.left: parent.left
                        anchors.leftMargin: 20
                        anchors.right: parent.right
                        anchors.rightMargin: 12
                        anchors.top: parent.top
                        anchors.topMargin: 52
                        visible: processRow.expanded

                        Repeater {
                            model: processRow.connections
                            delegate: Item {
                                id: connectionRow
                                required property var modelData
                                width: parent.width
                                height: 38
                                Text {
                                    anchors.left: parent.left
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: Math.max(120, parent.width * 0.36)
                                    text: root.connectionLabel(connectionRow.modelData)
                                    font.family: Theme.fontMono
                                    font.pixelSize: 10
                                    font.weight: 500
                                    color: Theme.shellFg
                                    elide: Text.ElideRight
                                }
                                Meta {
                                    anchors.left: parent.left
                                    anchors.leftMargin: Math.max(138, parent.width * 0.39)
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    horizontalAlignment: Text.AlignRight
                                    font.pixelSize: 8
                                    font.weight: 500
                                    text: root.connectionMeta(connectionRow.modelData)
                                    elide: Text.ElideLeft
                                }
                            }
                        }

                        Repeater {
                            model: processRow.denied
                            delegate: Item {
                                id: deniedRow
                                required property var modelData
                                width: parent.width
                                height: 38
                                Text {
                                    anchors.left: parent.left
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: Math.max(120, parent.width * 0.36)
                                    text: typeof deniedRow.modelData.zone === "string"
                                        ? deniedRow.modelData.zone : "Denied zone"
                                    font.family: Theme.fontMono
                                    font.pixelSize: 10
                                    font.weight: 600
                                    color: Theme.shellStatusBad
                                    elide: Text.ElideRight
                                }
                                Meta {
                                    anchors.left: parent.left
                                    anchors.leftMargin: Math.max(138, parent.width * 0.39)
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    horizontalAlignment: Text.AlignRight
                                    color: Theme.shellStatusBad
                                    text: "Denied · "
                                        + (typeof deniedRow.modelData.attempts === "number"
                                           ? deniedRow.modelData.attempts : 0)
                                        + " attempts · "
                                        + (typeof deniedRow.modelData.kind === "string"
                                           ? deniedRow.modelData.kind : "policy")
                                    elide: Text.ElideLeft
                                }
                            }
                        }

                        Meta {
                            width: parent.width
                            height: visible ? 28 : 0
                            visible: typeof processRow.modelData.note === "string"
                            font.weight: 500
                            verticalAlignment: Text.AlignVCenter
                            text: visible ? processRow.modelData.note : ""
                        }

                        Meta {
                            width: parent.width
                            height: visible ? 28 : 0
                            visible: processRow.connections.length === 0
                                && processRow.denied.length === 0
                                && typeof processRow.modelData.note !== "string"
                            font.weight: 500
                            verticalAlignment: Text.AlignVCenter
                            text: "No current TCP connections"
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: {
                            root.selectedIndex = processRow.index;
                            root.toggleExpanded();
                            processList.forceActiveFocus();
                        }
                    }
                }

                Text {
                    anchors.centerIn: parent
                    width: Math.min(560, parent.width - 48)
                    visible: root.processes.length === 0
                    text: Network.refreshing ? "Scanning local TCP sockets…"
                        : (Network.errorText !== "" ? Network.errorText
                           : "No current TCP connections were observed.")
                    font.family: Theme.fontSans
                    font.pixelSize: 15
                    lineHeight: 1.45
                    horizontalAlignment: Text.AlignHCenter
                    wrapMode: Text.WordWrap
                    color: Theme.shellInk3
                }
            }

            Rectangle {
                id: footRule
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: footer.top
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: Theme.hairline
                color: Theme.shellBorder
            }
            Item {
                id: footer
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: 43
                Meta {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    text: "↑↓ Process · ↵ Expand · R Refresh · Esc Close"
                }
                Meta {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    horizontalAlignment: Text.AlignRight
                    text: "TCP only · No content inspection"
                }
            }
        }
    }
}
