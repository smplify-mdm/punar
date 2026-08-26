pragma ComponentBehavior: Bound
// Overview — the SUPER+TAB project-workspace overview (Milestone 2),
// implementing docs/design/mockups/desktop-multitasking.html state
// 03 OVERVIEW (Plate D-007, the acceptance reference): a grid of
// project-workspace cards on a paper sheet over the warm ink-wash scrim.
// Each card is a field-note mini plate — masthead meta row (workspace
// number · NAME, tracked mono), a wireframe of the workspace's real
// window layout scaled from client at/size, hairline borders. Selection
// is the raise fill + 2 px ink rule; empty workspaces render as dashed
// outlines (the honesty grammar — nothing is claimed solid that isn't).
//
// Data flow (milestone-2.md §5 — no polling, renders on demand): on open,
// refreshWorkspaces() + refreshToplevels() once; everything else binds to
// the live Quickshell.Hyprland models, which socket2 events keep current.
//
// Toggled from Hyprland via Quickshell IPC:
//   quickshell ipc call overview toggle   (equivalently: qs ipc call …)
// Hyprland bind: bindd = SUPER, TAB, …, exec, quickshell ipc call overview toggle

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Hyprland
import "../Theme"
import "../Services"

Scope {
    id: root

    property bool open: false
    property bool windowVisible: false
    property string query: ""
    // Workspace id being renamed inline, -1 when none.
    property int renamingId: -1

    // Meta-row / label grammar (DESIGN_LANGUAGE.md §1): mono, tracked,
    // uppercase — the same component grammar as Bar and CommandCenter.
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    // ---- live data (Quickshell.Hyprland — no hyprctl parsing) ----

    // All real workspaces (id >= 1; specials hidden), sorted by id.
    readonly property var allCards: {
        var wss = Hyprland.workspaces.values;
        var out = [];
        for (var i = 0; i < wss.length; i++) {
            if (wss[i].id >= 1)
                out.push(wss[i]);
        }
        out.sort(function (a, b) {
            return a.id - b.id;
        });
        return out;
    }

    // Cards after the live type-to-search filter (name or number).
    readonly property var cards: {
        var q = root.query.trim().toLowerCase();
        if (q === "")
            return root.allCards;
        var out = [];
        for (var i = 0; i < root.allCards.length; i++) {
            var ws = root.allCards[i];
            var label = WorkspaceState.isNamed(ws) ? ws.name : String(ws.id);
            if (label.toLowerCase().indexOf(q) !== -1 || String(ws.id).indexOf(q) !== -1)
                out.push(ws);
        }
        return out;
    }

    function show() {
        if (!root.open)
            SurfaceTiming.begin("overview");
        // On-demand refresh — the one moment geometry is (re)fetched
        // (milestone-2.md §5; PERFORMANCE_BUDGETS.md: renders on demand).
        Hyprland.refreshWorkspaces();
        Hyprland.refreshToplevels();
        hideTimer.stop();
        root.renamingId = -1;
        root.windowVisible = true;
        root.open = true;
    }

    function dismiss() {
        if (!root.open)
            return;
        root.open = false;
        root.renamingId = -1;
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle() {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    // SUPER+TAB entry point (replaces the M1 `workspace e+1` placeholder).
    IpcHandler {
        target: "overview"

        function toggle(): void {
            root.toggle();
        }
        function open(): void {
            root.show();
        }
        function close(): void {
            root.dismiss();
        }
        // Read-only, for the m2-exercise CI check.
        function state(): string {
            return root.open ? "open" : "closed";
        }
        function latency(): string {
            return SurfaceTiming.sample("overview");
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
        color: "transparent" // scrim + sheet own all visible pixels
        WlrLayershell.namespace: "punar-overview"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

        onVisibleChanged: {
            if (win.visible) {
                searchInput.text = "";
                searchInput.forceActiveFocus();
                win.selectFocused();
            }
        }

        // Start the selection on the focused workspace's card.
        function selectFocused() {
            var f = Hyprland.focusedWorkspace;
            var idx = root.cards.length > 0 ? 0 : -1;
            if (f !== null) {
                for (var i = 0; i < root.cards.length; i++) {
                    if (root.cards[i].id === f.id) {
                        idx = i;
                        break;
                    }
                }
            }
            grid.currentIndex = idx;
        }

        function moveSel(delta: int) {
            if (root.cards.length === 0)
                return;
            var idx = (grid.currentIndex < 0 ? 0 : grid.currentIndex) + delta;
            grid.currentIndex = Math.max(0, Math.min(root.cards.length - 1, idx));
        }

        // Enter: switch to the selected project and close.
        function commit() {
            var ws = grid.currentIndex >= 0 && grid.currentIndex < root.cards.length
                     ? root.cards[grid.currentIndex] : null;
            if (ws === null)
                return;
            Hyprland.dispatch("workspace " + ws.id);
            root.dismiss();
        }

        function beginRename() {
            var ws = grid.currentIndex >= 0 && grid.currentIndex < root.cards.length
                     ? root.cards[grid.currentIndex] : null;
            if (ws !== null)
                root.renamingId = ws.id;
        }

        // Commit an inline rename. Empty clears the name; an invalid name
        // is refused (the input underline turns status-bad; see delegate).
        // Persistence rides the resulting socket2 renameworkspace event —
        // WorkspaceState debounces and writes the state file atomically.
        function commitRename(wsId: int, text: string): bool {
            var name = text.trim();
            if (name === "") {
                Hyprland.dispatch("renameworkspace " + wsId);
            } else if (WorkspaceState.validName(name)) {
                Hyprland.dispatch("renameworkspace " + wsId + " " + name);
            } else {
                return false;
            }
            root.renamingId = -1;
            searchInput.forceActiveFocus();
            return true;
        }

        function cancelRename() {
            root.renamingId = -1;
            searchInput.forceActiveFocus();
        }

        // Warm ink-wash scrim at 22% — 300 ms token curve, only on
        // show/hide (§4: fluid, not decorative).
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
                onClicked: root.dismiss()
            }
        }

        // ---- the overview sheet (Plate D-007 .overview) ----
        Rectangle {
            id: sheet

            width: Math.min(980, win.width * 0.9)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? win.height * 0.1 : (win.height * 0.1) - 10
            height: sheetColumn.implicitHeight
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder
            radius: Theme.radius
            clip: true
            opacity: root.open ? 1 : 0
            // Soft drop shadow deliberately omitted (llvmpipe budget; the
            // scrim + hairline carry separation — same M1 deviation).

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
                id: sheetColumn
                width: parent.width

                // Masthead row: PUNAR · WORKSPACES | N projects · search.
                Item {
                    width: parent.width
                    height: 40

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
                            text: " · Workspaces"
                        }
                        Meta {
                            text: " · " + root.allCards.length
                                  + (root.allCards.length === 1 ? " project" : " projects")
                        }
                    }

                    // Type-to-search: the greeter's underline field grammar.
                    Row {
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 8

                        Item {
                            width: 200
                            height: 20
                            anchors.verticalCenter: parent.verticalCenter

                            TextInput {
                                id: searchInput
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                font.family: Theme.fontMono
                                font.pixelSize: 11
                                font.letterSpacing: Theme.tracking(11, 0.08)
                                font.capitalization: Font.AllUppercase
                                color: Theme.shellFg
                                clip: true
                                onTextChanged: root.query = text

                                Keys.onPressed: function (event) {
                                    var cols = grid.columns;
                                    switch (event.key) {
                                    case Qt.Key_Escape:
                                        root.dismiss();
                                        event.accepted = true;
                                        break;
                                    case Qt.Key_Left:
                                        win.moveSel(-1);
                                        event.accepted = true;
                                        break;
                                    case Qt.Key_Right:
                                        win.moveSel(1);
                                        event.accepted = true;
                                        break;
                                    case Qt.Key_Up:
                                        win.moveSel(-cols);
                                        event.accepted = true;
                                        break;
                                    case Qt.Key_Down:
                                        win.moveSel(cols);
                                        event.accepted = true;
                                        break;
                                    case Qt.Key_Return:
                                    case Qt.Key_Enter:
                                        win.commit();
                                        event.accepted = true;
                                        break;
                                    // H/J/K/L navigate while the query is
                                    // empty; once typing has begun, letters
                                    // belong to the search (D-007 register
                                    // 02: typing searches).
                                    case Qt.Key_H:
                                        if (searchInput.text === "") {
                                            win.moveSel(-1);
                                            event.accepted = true;
                                        }
                                        break;
                                    case Qt.Key_L:
                                        if (searchInput.text === "") {
                                            win.moveSel(1);
                                            event.accepted = true;
                                        }
                                        break;
                                    case Qt.Key_K:
                                        if (searchInput.text === "") {
                                            win.moveSel(-cols);
                                            event.accepted = true;
                                        }
                                        break;
                                    case Qt.Key_J:
                                        if (searchInput.text === "") {
                                            win.moveSel(cols);
                                            event.accepted = true;
                                        }
                                        break;
                                    case Qt.Key_R:
                                        if (searchInput.text === "") {
                                            win.beginRename();
                                            event.accepted = true;
                                        }
                                        break;
                                    }
                                }
                            }

                            Text {
                                anchors.fill: searchInput
                                visible: searchInput.text === ""
                                text: "Type to search"
                                font.family: Theme.fontMono
                                font.pixelSize: 11
                                font.letterSpacing: Theme.tracking(11, 0.08)
                                font.capitalization: Font.AllUppercase
                                color: Theme.shellInputBorder
                            }

                            Rectangle {
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.bottom: parent.bottom
                                height: Theme.hairline
                                color: Theme.shellInputBorder
                            }
                        }

                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "↵"
                            font.capitalization: Font.MixedCase
                        }
                    }

                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: Theme.hairline
                        color: Theme.shellBorder
                    }
                }

                Item {
                    width: parent.width
                    height: 12
                }

                // ---- project-workspace card grid (4 columns, D-007) ----
                GridView {
                    id: grid

                    readonly property int columns: 4

                    width: parent.width - 24
                    anchors.horizontalCenter: parent.horizontalCenter
                    cellWidth: Math.floor(width / columns)
                    // mini (16:10 inside 14 px gutters) + meta rows.
                    cellHeight: Math.round((cellWidth - 14) * 10 / 16) + 52
                    height: Math.min(
                                Math.ceil(Math.max(root.cards.length, 1) / columns) * cellHeight,
                                Math.max(win.height * 0.62, cellHeight))
                    clip: true
                    interactive: contentHeight > height
                    boundsBehavior: Flickable.StopAtBounds
                    model: root.cards
                    onModelChanged: {
                        if (currentIndex >= root.cards.length)
                            currentIndex = root.cards.length - 1;
                        if (currentIndex < 0 && root.cards.length > 0)
                            currentIndex = 0;
                    }

                    delegate: Item {
                        id: cell

                        required property int index
                        required property var modelData

                        readonly property var ws: cell.modelData
                        readonly property bool sel: cell.GridView.isCurrentItem
                        readonly property bool named: WorkspaceState.isNamed(cell.ws)
                        readonly property int winCount: cell.ws.toplevels.values.length

                        width: grid.cellWidth
                        height: grid.cellHeight

                        // Card: transparent at rest; selection = raise fill
                        // + 2 px ink rule + slight scale (150 ms micro).
                        Rectangle {
                            id: card

                            anchors.fill: parent
                            anchors.margins: 7
                            radius: Theme.radius
                            color: cell.sel ? Theme.shellMuted : "transparent"
                            scale: cell.sel ? 1.02 : 1.0

                            Behavior on scale {
                                NumberAnimation {
                                    duration: Theme.durMicro
                                    easing.type: Easing.BezierSpline
                                    easing.bezierCurve: Theme.easingCurve
                                }
                            }

                            // The 2 px ink rule (selection grammar).
                            Rectangle {
                                anchors.left: parent.left
                                anchors.top: parent.top
                                anchors.bottom: parent.bottom
                                width: 2
                                radius: 1
                                color: Theme.shellFg
                                visible: cell.sel
                            }

                            Column {
                                anchors.fill: parent
                                anchors.margins: 8
                                anchors.leftMargin: 10
                                spacing: 0

                                // ---- wireframe mini plate ----
                                Item {
                                    id: mini

                                    width: parent.width
                                    height: Math.round(width * 10 / 16)

                                    readonly property bool empty: cell.winCount === 0
                                    // Wireframe inset (mockup .mini padding 5).
                                    readonly property real pad: 5

                                    // Normalize a client's global at/size to
                                    // 0..1 of its monitor's logical space.
                                    function normGeo(ipc: var): var {
                                        if (!ipc || ipc.at === undefined || ipc.size === undefined)
                                            return null;
                                        var mon = cell.ws.monitor;
                                        var s = mon && mon.scale > 0 ? mon.scale : 1;
                                        var mx = mon ? mon.x : 0;
                                        var my = mon ? mon.y : 0;
                                        var mw = mon && mon.width > 0 ? mon.width / s : 1920;
                                        var mh = mon && mon.height > 0 ? mon.height / s : 1080;
                                        var x = (ipc.at[0] - mx) / mw;
                                        var y = (ipc.at[1] - my) / mh;
                                        var w = ipc.size[0] / mw;
                                        var h = ipc.size[1] / mh;
                                        return {
                                            x: Math.max(0, Math.min(1, x)),
                                            y: Math.max(0, Math.min(1, y)),
                                            w: Math.max(0.04, Math.min(1, w)),
                                            h: Math.max(0.04, Math.min(1, h))
                                        };
                                    }

                                    // Occupied: solid mini with the real layout.
                                    Rectangle {
                                        anchors.fill: parent
                                        visible: !mini.empty
                                        color: Theme.shellMuted
                                        border.width: Theme.hairline
                                        border.color: Theme.shellBorder
                                        radius: Theme.radiusTag
                                        clip: true

                                        Repeater {
                                            model: mini.empty ? [] : cell.ws.toplevels.values

                                            delegate: Rectangle {
                                                id: mw

                                                required property var modelData

                                                readonly property var ipc: mw.modelData.lastIpcObject
                                                readonly property var geo: mini.normGeo(mw.ipc)
                                                readonly property bool floats: mw.ipc && mw.ipc.floating === true
                                                readonly property bool inGroup: mw.ipc && Array.isArray(mw.ipc.grouped)
                                                                                && mw.ipc.grouped.length > 1

                                                visible: mw.geo !== null
                                                x: mini.pad + (mw.geo ? mw.geo.x : 0) * (mini.width - 2 * mini.pad)
                                                y: mini.pad + (mw.geo ? mw.geo.y : 0) * (mini.height - 2 * mini.pad)
                                                width: (mw.geo ? mw.geo.w : 0) * (mini.width - 2 * mini.pad)
                                                height: (mw.geo ? mw.geo.h : 0) * (mini.height - 2 * mini.pad)
                                                radius: 3
                                                color: Theme.shellSurface
                                                border.width: Theme.hairline
                                                // A float must read as a float
                                                // even in wireframe.
                                                border.color: mw.floats ? Theme.shellInputBorder : Theme.shellBorder
                                                z: mw.floats ? 2 : 1

                                                // Group slab tab notch
                                                // (stacked windows share
                                                // geometry; the notch says so).
                                                Rectangle {
                                                    visible: mw.inGroup
                                                    anchors.top: parent.top
                                                    anchors.left: parent.left
                                                    anchors.topMargin: 2
                                                    anchors.leftMargin: 2
                                                    width: Math.min(12, parent.width / 3)
                                                    height: 3
                                                    radius: 1
                                                    color: Theme.shellInputBorder
                                                }
                                            }
                                        }
                                    }

                                    // Empty: dashed outline — the honesty
                                    // grammar (dashed = not real yet).
                                    Canvas {
                                        anchors.fill: parent
                                        visible: mini.empty
                                        onPaint: {
                                            var ctx = getContext("2d");
                                            ctx.clearRect(0, 0, width, height);
                                            ctx.strokeStyle = String(Theme.shellInputBorder);
                                            ctx.lineWidth = 1;
                                            ctx.setLineDash([4, 4]);
                                            ctx.beginPath();
                                            ctx.roundedRect(0.5, 0.5, width - 1, height - 1,
                                                            Theme.radiusTag, Theme.radiusTag);
                                            ctx.stroke();
                                        }
                                        onVisibleChanged: if (visible) requestPaint()
                                        onWidthChanged: requestPaint()
                                        onHeightChanged: requestPaint()
                                    }

                                    Meta {
                                        anchors.centerIn: parent
                                        visible: mini.empty
                                        font.pixelSize: 8
                                        font.weight: 500
                                        font.letterSpacing: Theme.tracking(8, 0.14)
                                        text: "No windows"
                                    }
                                }

                                Item {
                                    width: parent.width
                                    height: 8
                                }

                                // ---- masthead meta row: N · NAME ----
                                Item {
                                    width: parent.width
                                    height: 13

                                    Meta {
                                        anchors.left: parent.left
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        visible: root.renamingId !== cell.ws.id
                                        font.pixelSize: 8
                                        font.letterSpacing: Theme.tracking(8, 0.12)
                                        color: Theme.shellFg
                                        elide: Text.ElideRight
                                        text: cell.named ? cell.ws.id + " · " + cell.ws.name
                                                         : String(cell.ws.id)
                                    }

                                    // Inline rename: mono input in the card
                                    // masthead (R begins, ↵ commits, Esc
                                    // cancels). Invalid names are refused —
                                    // the underline turns status-bad.
                                    Item {
                                        anchors.fill: parent
                                        visible: root.renamingId === cell.ws.id

                                        onVisibleChanged: {
                                            if (visible) {
                                                renameInput.text = cell.named ? cell.ws.name : "";
                                                renameInput.invalid = false;
                                                renameInput.forceActiveFocus();
                                                renameInput.selectAll();
                                            }
                                        }

                                        TextInput {
                                            id: renameInput

                                            property bool invalid: false

                                            anchors.left: parent.left
                                            anchors.right: parent.right
                                            anchors.verticalCenter: parent.verticalCenter
                                            font.family: Theme.fontMono
                                            font.pixelSize: 10
                                            font.letterSpacing: Theme.tracking(10, 0.06)
                                            color: Theme.shellFg
                                            clip: true
                                            onTextChanged: invalid = false

                                            Keys.onPressed: function (event) {
                                                switch (event.key) {
                                                case Qt.Key_Return:
                                                case Qt.Key_Enter:
                                                    if (!win.commitRename(cell.ws.id, renameInput.text))
                                                        renameInput.invalid = true;
                                                    event.accepted = true;
                                                    break;
                                                case Qt.Key_Escape:
                                                    win.cancelRename();
                                                    event.accepted = true;
                                                    break;
                                                }
                                            }
                                        }

                                        Rectangle {
                                            anchors.left: parent.left
                                            anchors.right: parent.right
                                            anchors.bottom: parent.bottom
                                            height: Theme.hairline
                                            color: renameInput.invalid ? Theme.shellStatusBad
                                                                       : Theme.shellInputBorder
                                        }
                                    }
                                }

                                // Second meta line: window count · last title.
                                Meta {
                                    width: parent.width
                                    font.pixelSize: 8
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(8, 0.12)
                                    elide: Text.ElideRight
                                    text: {
                                        if (cell.winCount === 0)
                                            return "Empty";
                                        var line = cell.winCount
                                                   + (cell.winCount === 1 ? " window" : " windows");
                                        var ipc = cell.ws.lastIpcObject;
                                        var title = ipc && ipc.lastwindowtitle ? ipc.lastwindowtitle : "";
                                        return title !== "" ? line + " · " + title : line;
                                    }
                                }
                            }

                            MouseArea {
                                anchors.fill: parent
                                enabled: root.renamingId !== cell.ws.id
                                onClicked: {
                                    grid.currentIndex = cell.index;
                                    win.commit();
                                }
                            }
                        }
                    }
                }

                // Explicit empty state — silence is not support.
                Item {
                    width: parent.width
                    height: 36
                    visible: root.cards.length === 0

                    Meta {
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.weight: 500
                        text: "No matches"
                    }
                }

                Item {
                    width: parent.width
                    height: 8
                }

                // Footer meta row with the plate's assertion.
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.shellBorder
                }
                Item {
                    width: parent.width
                    height: 29

                    Meta {
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 8
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(8, 0.13)
                        text: "←↑↓→ Navigate · ↵ Switch · R Rename · Esc Close"
                    }
                    Meta {
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 8
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(8, 0.13)
                        text: "Projects, not numbered desktops"
                    }
                }
            }
        }
    }
}
