pragma ComponentBehavior: Bound
// WindowSwitcher — Alt+Tab (SMP-1405 WP-02; Omarchy K30-K35, matrix row J14).
//
// HOW A SWITCH HAPPENS. The compositor owns the keys and counts: each Tab
// press of one Alt hold sends `step <gesture> <steps>`, and releasing Alt
// sends `commit <gesture> <steps>` (punar-binds.lua). Every call carries the
// whole state, so two quick processes landing out of order still reach the
// same answer: a commit for a gesture this surface already finished is
// ignored, and a commit that arrives before its snapshot waits for it. A
// quick tap is `step 1` + `commit 1`: the previous window, as on every
// desktop. The chosen window is focused with `punarctl window focus
// --address` — the verb a terminal uses — so the switcher is never a second
// path into the compositor.
//
// WHAT IT SHOWS. The windows of every workspace, most recently used first,
// read once per gesture from `punarctl window list` (the compositor's own
// focus history). Each card draws its window's workspace with the OVERVIEW'S
// live wireframe (Overview/WorkspaceWireframe.qml) and that window ruled in
// ink, so the switcher shows where the window is, not a thumbnail of it: no
// screen capture, no image buffers, nothing a screen-share policy would have
// to reason about.
//
// NO FLASH, NO FOCUS THEFT. The strip appears only if Alt is still held
// 150 ms after the first Tab, so a quick switch draws nothing. The surface
// never takes the keyboard (the compositor's release bind finishes the
// gesture), and only the strip itself takes the pointer: clicking a card
// chooses it. If a release is ever missed, the gesture finishes on its own
// five seconds after the last Tab, with the window that was shown selected.
//
// Deferred like every user-invoked surface (shell.qml): nothing is resident
// until the first Alt+Tab, and the object is destroyed after it closes.
//
// Driven from a check script via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call windowswitcher step <gesture> <steps>
//   qs -p /usr/share/punar/shell ipc call windowswitcher selected

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Hyprland
import "../Overview"
import "../Services"
import "../Theme"

DeferredSurfaceBase {
    id: root

    property bool openOnReady: false
    property bool windowVisible: false

    // The gesture on screen, the highest one finished, and its Tab count.
    property double gesture: -1
    property double committedGesture: 0
    property int steps: 1
    // A commit waiting for its snapshot, by gesture.
    property double pendingCommit: -1

    // The snapshot: windows in most-recently-used order, taken once per
    // gesture so each Tab walks a list that does not reorder under it.
    property var windows: []
    property bool snapshotReady: false

    // Told to the shell root, which outlives this surface: a late `step` for
    // a gesture that already finished must not open a new one after this
    // object has been destroyed.
    signal finished(double gesture)

    readonly property int selectedIndex: root.windows.length === 0 ? -1
        : (((root.steps % root.windows.length) + root.windows.length) % root.windows.length)
    readonly property var selectedWindow: root.selectedIndex < 0 ? null : root.windows[root.selectedIndex]

    // Meta-row grammar (DESIGN_LANGUAGE.md §1), as in the Overview.
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        textFormat: Text.PlainText
        elide: Text.ElideRight
    }

    function workspaceById(id: int): var {
        var all = Hyprland.workspaces.values;
        for (var i = 0; i < all.length; i++) {
            if (all[i].id === id)
                return all[i];
        }
        return null;
    }

    function takeSnapshot(): void {
        root.snapshotReady = false;
        root.windows = [];
        // The wireframes read each client's at/size from lastIpcObject.
        Hyprland.refreshWorkspaces();
        Hyprland.refreshToplevels();
        if (!listProbe.running)
            listProbe.running = true;
    }

    function parseWindows(body: string): void {
        var doc = null;
        try {
            doc = JSON.parse(body);
        } catch (e) {
            doc = null;
        }
        var list = [];
        var raw = doc !== null && Array.isArray(doc.windows) ? doc.windows : [];
        for (var i = 0; i < raw.length; i++) {
            var w = raw[i];
            if (w === null || typeof w !== "object" || typeof w.address !== "string")
                continue;
            if (!/^0x[0-9a-fA-F]{1,16}$/.test(w.address))
                continue;
            // Special workspaces (scratchpads) have their own keys, and an
            // unmapped window is not one a person can see.
            var wsId = w.workspace && typeof w.workspace.id === "number" ? w.workspace.id : -1;
            if (wsId < 1 || w.mapped === false || w.hidden === true)
                continue;
            list.push({
                "address": w.address,
                "appClass": typeof w.class === "string" ? w.class : "",
                "title": typeof w.title === "string" ? w.title : "",
                "workspaceId": wsId,
                "history": typeof w.focusHistoryID === "number" ? w.focusHistoryID : 1000 + i
            });
        }
        list.sort(function (a, b) {
            return a.history - b.history;
        });
        root.windows = list;
        root.snapshotReady = true;
        if (root.pendingCommit === root.gesture)
            root.finish();
    }

    Process {
        id: listProbe
        command: ["punarctl", "--json", "window", "list"]
        stdout: StdioCollector {
            id: listOut
            waitForEnd: true
            onStreamFinished: root.parseWindows(listOut.text)
        }
    }

    function ipcStep(gesture: string, steps: string): string {
        var g = Number(gesture);
        var n = Number(steps);
        if (!isFinite(g) || !isFinite(n) || g <= root.committedGesture)
            return "stale";
        if (g !== root.gesture) {
            root.gesture = g;
            root.pendingCommit = -1;
            root.takeSnapshot();
            revealTimer.restart();
        }
        root.steps = Math.round(n);
        dwellTimer.restart();
        return "shown";
    }

    function ipcCommit(gesture: string, steps: string): string {
        var g = Number(gesture);
        var n = Number(steps);
        if (!isFinite(g) || !isFinite(n) || g <= root.committedGesture)
            return "stale";
        if (g !== root.gesture) {
            root.gesture = g;
            root.takeSnapshot();
        }
        root.steps = Math.round(n);
        root.committedGesture = g;
        if (!root.snapshotReady) {
            root.pendingCommit = g;
            return "pending";
        }
        root.finish();
        return "committed";
    }

    // Focus the selection (unless it already has focus) and close.
    function finish(): void {
        root.pendingCommit = -1;
        revealTimer.stop();
        dwellTimer.stop();
        var chosen = root.selectedWindow;
        if (chosen !== null && root.selectedIndex !== 0)
            HyprlandActions.focusWindowAddress(chosen.address);
        root.finished(root.gesture);
        root.dismiss();
    }

    function choose(index: int): void {
        root.steps = index;
        if (root.gesture > root.committedGesture)
            root.committedGesture = root.gesture;
        root.finish();
    }

    function ipcSelected(): string {
        var chosen = root.selectedWindow;
        return chosen === null ? "" : chosen.address;
    }

    // Appear only for a held Alt: a quick switch never flashes the strip.
    Timer {
        id: revealTimer
        interval: 150
        repeat: false
        onTriggered: {
            if (root.gesture > root.committedGesture)
                root.show();
        }
    }

    // The missed-release fallback; one shot, restarted by each Tab.
    Timer {
        id: dwellTimer
        interval: 5000
        repeat: false
        onTriggered: {
            if (root.gesture <= root.committedGesture)
                return;
            root.committedGesture = root.gesture;
            if (root.snapshotReady)
                root.finish();
            else
                root.pendingCommit = root.gesture;
        }
    }

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("windowswitcher");
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
    }

    // A plain open (the command center, a check script) is a one-Tab gesture
    // that waits for a click or the five-second finish.
    function toggle(): void {
        if (root.open) {
            root.dismiss();
            return;
        }
        root.ipcStep(String(root.committedGesture + 1), "1");
        root.show();
    }

    function dismiss(): void {
        revealTimer.stop();
        if (!root.open) {
            root.unloadRequested();
            return;
        }
        root.open = false;
        hideTimer.restart();
    }

    function ipcState(): string {
        return root.open ? "open" : "closed";
    }

    Component.onCompleted: {
        SurfaceTiming.constructed("windowswitcher");
        if (root.openOnReady)
            root.toggle();
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: {
            root.windowVisible = false;
            root.unloadRequested();
        }
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
        color: "transparent"
        // Only the strip takes the pointer; everything else passes through.
        mask: Region {
            item: strip
        }
        WlrLayershell.namespace: "punar-windowswitcher"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: WlrKeyboardFocus.None

        readonly property int cardWidth: 208
        readonly property int visibleCards: Math.max(1, Math.min(root.windows.length,
            Math.floor((win.width * 0.9 - 32) / (win.cardWidth + 10))))

        Rectangle {
            id: strip

            anchors.centerIn: parent
            width: Math.max(260, win.visibleCards * (win.cardWidth + 10) + 22)
            height: 226
            radius: Theme.radius
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder
            opacity: root.open ? 1 : 0

            Behavior on opacity {
                NumberAnimation {
                    duration: Theme.durMicro
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }

            Meta {
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.leftMargin: 16
                anchors.topMargin: 12
                color: Theme.shellFg
                text: root.windows.length === 0 && root.snapshotReady ? "No windows to switch to"
                    : "Windows · " + root.windows.length
            }

            Meta {
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.rightMargin: 16
                anchors.topMargin: 12
                font.weight: 500
                text: "Tab next · Shift+Tab back · release Alt"
            }

            ListView {
                id: cards

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: 11
                anchors.rightMargin: 11
                anchors.bottomMargin: 12
                height: 180
                orientation: ListView.Horizontal
                spacing: 10
                clip: true
                interactive: false
                model: root.windows
                currentIndex: root.selectedIndex
                highlightFollowsCurrentItem: true
                highlightMoveDuration: Theme.durMicro

                delegate: Item {
                    id: card

                    required property int index
                    required property var modelData
                    readonly property bool sel: card.index === root.selectedIndex

                    width: win.cardWidth
                    height: cards.height

                    Rectangle {
                        anchors.fill: parent
                        radius: Theme.radius
                        color: card.sel ? Theme.shellMuted : "transparent"

                        // The 2 px ink rule (the Overview's selection grammar).
                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 2
                            radius: 1
                            color: Theme.shellFg
                            visible: card.sel
                        }
                    }

                    Column {
                        anchors.fill: parent
                        anchors.margins: 8
                        anchors.leftMargin: 10
                        spacing: 6

                        WorkspaceWireframe {
                            width: parent.width
                            height: Math.round(width * 10 / 16)
                            workspace: root.workspaceById(card.modelData.workspaceId)
                            highlightAddress: card.modelData.address
                        }

                        Meta {
                            width: parent.width
                            color: card.sel ? Theme.shellFg : Theme.shellInk3
                            text: SafeText.plain(card.modelData.appClass, 48) + " · " + card.modelData.workspaceId
                        }

                        Text {
                            width: parent.width
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 12
                            color: card.sel ? Theme.shellFg : Theme.shellInk2
                            text: SafeText.plain(card.modelData.title, 160)
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: root.choose(card.index)
                    }
                }
            }
        }
    }
}
