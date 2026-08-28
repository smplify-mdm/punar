pragma ComponentBehavior: Bound
// WindowActions — a small, deliberate app-lifecycle surface.
//
// Punar keeps two operations visibly distinct:
//
//   CLOSE WINDOW   asks the client to close normally. The application can
//                  save work, ask the user, refuse, or keep another window
//                  and its background process alive.
//   FORCE QUIT APP kills the process owning the selected window. It bypasses
//                  application cleanup and can lose unsaved work, so it is
//                  never a one-step action.
//
// The surface snapshots `hyprctl -j activewindow` once when it opens and
// validates the address before enabling either action. Both dispatchers then
// target that exact address; neither acts on whatever happens to be focused
// later. A focus change dismisses the surface as a second guard against stale
// targets. There is no polling and no resident helper process.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Services"
import "../Theme"

DeferredSurfaceBase {
    id: root

    property bool openOnReady: false
    property bool windowVisible: false
    property string phase: "idle"
    property string targetAddress: ""
    property string targetApp: ""
    property string targetTitle: ""
    property string failure: ""
    property bool forceArmed: false

    readonly property bool ready: root.phase === "ready"

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 10
        font.weight: 600
        font.letterSpacing: Theme.tracking(10, 0.12)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        textFormat: Text.PlainText
    }

    component KeyCap: Rectangle {
        id: cap

        property string label: ""
        property color tone: Theme.shellInputBorder

        implicitWidth: keyLabel.implicitWidth + 10
        implicitHeight: keyLabel.implicitHeight + 5
        radius: Theme.radiusTag
        color: "transparent"
        border.width: Theme.hairline
        border.color: cap.tone

        Text {
            id: keyLabel

            anchors.centerIn: parent
            text: cap.label
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            color: cap.tone
            textFormat: Text.PlainText
        }
    }

    component ActionRow: Rectangle {
        id: action

        property string label: ""
        property string detail: ""
        property string binding: ""
        property color tone: Theme.shellFg
        property bool enabledLook: true
        property bool filled: false

        signal activated

        implicitHeight: 58
        radius: Theme.radiusTag
        color: action.filled ? action.tone
                             : (actionMouse.containsMouse ? Theme.shellMuted : "transparent")
        border.width: Theme.hairline
        border.color: action.tone
        opacity: action.enabledLook ? 1 : 0.42

        Column {
            anchors.left: parent.left
            anchors.right: keycap.left
            anchors.leftMargin: 13
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 3

            Meta {
                width: parent.width
                text: action.label
                color: action.filled ? Theme.shellActionFg : action.tone
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                text: action.detail
                font.family: Theme.fontSans
                font.pixelSize: 12
                font.weight: 400
                color: action.filled ? Theme.shellActionFg : Theme.shellInk3
                elide: Text.ElideRight
                textFormat: Text.PlainText
            }
        }

        KeyCap {
            id: keycap

            anchors.right: parent.right
            anchors.rightMargin: 13
            anchors.verticalCenter: parent.verticalCenter
            label: action.binding
            tone: action.filled ? Theme.shellActionFg : action.tone
        }

        MouseArea {
            id: actionMouse

            anchors.fill: parent
            enabled: action.enabledLook
            hoverEnabled: true
            cursorShape: action.enabledLook ? Qt.PointingHandCursor : Qt.ArrowCursor
            onClicked: action.activated()
        }
    }

    function resetTarget(): void {
        root.phase = "loading";
        root.targetAddress = "";
        root.targetApp = "";
        root.targetTitle = "";
        root.failure = "";
        root.forceArmed = false;
    }

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("windowactions");
        hideTimer.stop();
        root.resetTarget();
        root.windowVisible = true;
        root.open = true;

        if (snapshotProc.running)
            snapshotProc.running = false;
        try {
            snapshotProc.command = ["hyprctl", "-j", "activewindow"];
            snapshotProc.running = true;
        } catch (e) {
            root.phase = "failed";
            root.failure = "Window details are unavailable. Nothing was changed.";
        }
    }

    Component.onCompleted: {
        SurfaceTiming.constructed("windowactions");
        if (root.openOnReady)
            root.show();
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        root.forceArmed = false;
        if (snapshotProc.running)
            snapshotProc.running = false;
        hideTimer.restart();
    }

    function toggle(): void {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    function ipcState(): string {
        if (!root.open)
            return "closed";
        if (root.forceArmed)
            return "confirming";
        return root.phase;
    }

    function finishSnapshot(): void {
        if (!root.open || snapshotProc.running)
            return;

        var parsed = null;
        try {
            parsed = JSON.parse(String(snapshotOut.text));
        } catch (e) {
            parsed = null;
        }

        if (parsed === null || typeof parsed !== "object") {
            root.phase = "failed";
            root.failure = "The compositor returned no readable window details. Nothing was changed.";
            return;
        }

        var address = typeof parsed.address === "string" ? parsed.address : "";
        if (!/^0x[0-9a-fA-F]+$/.test(address)) {
            root.phase = "empty";
            root.failure = "No application window is focused.";
            return;
        }

        var app = typeof parsed.class === "string" ? parsed.class.trim() : "";
        if (app === "" && typeof parsed.initialClass === "string")
            app = parsed.initialClass.trim();

        root.targetAddress = address;
        root.targetApp = app === "" ? "Application" : app;
        root.targetTitle = typeof parsed.title === "string" ? parsed.title.trim() : "";
        root.phase = "ready";
    }

    function closeWindow(): void {
        if (!root.ready || dispatchProc.running)
            return;
        var address = root.targetAddress;
        // The Lua dispatcher sends the normal compositor close request. It
        // does not send a process signal. The address is safe to interpolate
        // because finishSnapshot() accepts hexadecimal addresses only.
        root.runDispatcher("hl.dsp.window.close({ window = 'address:" + address + "' })");
    }

    function armForceQuit(): void {
        if (root.ready)
            root.forceArmed = true;
    }

    function cancelForceQuit(): void {
        root.forceArmed = false;
    }

    function forceQuit(): void {
        if (!root.ready || !root.forceArmed || dispatchProc.running)
            return;
        var address = root.targetAddress;
        // The kill dispatcher is intentionally confined to this confirmed
        // path. It sends SIGKILL to the process owning the exact snapshotted
        // window.
        root.runDispatcher("hl.dsp.window.kill({ window = 'address:" + address + "' })");
    }

    function runDispatcher(expression: string): void {
        if (dispatchProc.running)
            return;
        try {
            // Hyprland 0.56's request socket accepts Lua dispatchers, but
            // Quickshell 0.3 can race an asynchronously opened socket with a
            // deferred surface unloading. Keep this short-lived process
            // owned until its result is known instead.
            dispatchProc.command = ["hyprctl", "dispatch", expression];
            dispatchProc.running = true;
        } catch (e) {
            root.forceArmed = false;
            root.phase = "failed";
            root.failure = "The compositor action could not be started. Nothing was changed.";
        }
    }

    Timer {
        id: hideTimer

        interval: Theme.durStandard
        onTriggered: {
            root.windowVisible = false;
            root.unloadRequested();
        }
    }

    Process {
        id: snapshotProc

        stdout: StdioCollector {
            id: snapshotOut

            waitForEnd: true
            onStreamFinished: root.finishSnapshot()
        }
        onRunningChanged: if (!snapshotProc.running)
            root.finishSnapshot()
    }

    Process {
        id: dispatchProc

        stdout: StdioCollector {
            id: dispatchOut
            waitForEnd: true
        }
        stderr: StdioCollector {
            id: dispatchErr
            waitForEnd: true
        }

        Component.onCompleted: dispatchProc.exited.connect(function (exitCode) {
            var response = String(dispatchOut.text).trim();
            if (exitCode === 0 && response === "ok") {
                root.dismiss();
                return;
            }

            root.forceArmed = false;
            root.phase = "failed";
            var detail = String(dispatchErr.text).trim();
            root.failure = detail === ""
                ? "The compositor refused that action. Nothing was changed."
                : "The compositor refused that action. Nothing was changed: " + detail;
        })
    }

    // If another application receives focus while the panel is open, the
    // original snapshot is no longer the user's visible context. Dismiss it;
    // the user can reopen against the newly focused app.
    Connections {
        target: ToplevelManager

        function onActiveToplevelChanged(): void {
            if (root.open && root.phase !== "loading")
                root.dismiss();
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
        WlrLayershell.namespace: "punar-window-actions"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

        onVisibleChanged: if (win.visible)
            keyFocus.forceActiveFocus()

        Item {
            id: keyFocus

            anchors.fill: parent
            focus: root.open

            Keys.onPressed: function (event) {
                switch (event.key) {
                case Qt.Key_Escape:
                    if (root.forceArmed)
                        root.cancelForceQuit();
                    else
                        root.dismiss();
                    event.accepted = true;
                    break;
                case Qt.Key_C:
                    if (root.ready && !root.forceArmed)
                        root.closeWindow();
                    event.accepted = true;
                    break;
                case Qt.Key_F:
                    if (root.ready) {
                        if (root.forceArmed)
                            root.forceQuit();
                        else
                            root.armForceQuit();
                    }
                    event.accepted = true;
                    break;
                }
            }

            MouseArea {
                anchors.fill: parent
                onClicked: root.dismiss()
            }

            Rectangle {
                id: card

                width: Math.min(412, win.width - 24)
                x: 12
                y: 38
                height: body.implicitHeight + 26
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

                MouseArea {
                    anchors.fill: parent
                    onClicked: function (mouse) {
                        mouse.accepted = true;
                    }
                }

                Column {
                    id: body

                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.leftMargin: 14
                    anchors.rightMargin: 14
                    anchors.topMargin: 13
                    spacing: 10

                    Item {
                        width: parent.width
                        height: Math.max(30, titleColumn.implicitHeight)

                        Column {
                            id: titleColumn

                            anchors.left: parent.left
                            anchors.right: dismissCap.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 3

                            Meta {
                                width: parent.width
                                text: root.forceArmed ? "Force quit " + root.targetApp + "?"
                                                      : (root.ready ? root.targetApp + " · Window actions"
                                                                    : "Window actions")
                                color: root.forceArmed ? Theme.shellStatusBad : Theme.shellFg
                                elide: Text.ElideRight
                            }
                            Text {
                                width: parent.width
                                visible: root.ready && !root.forceArmed && root.targetTitle !== ""
                                text: root.targetTitle
                                font.family: Theme.fontSans
                                font.pixelSize: 12
                                color: Theme.shellInk3
                                elide: Text.ElideRight
                                textFormat: Text.PlainText
                            }
                        }

                        KeyCap {
                            id: dismissCap

                            anchors.right: parent.right
                            anchors.top: parent.top
                            label: "Esc"
                        }
                    }

                    Rectangle {
                        width: parent.width
                        height: Theme.hairline
                        color: Theme.shellBorder
                    }

                    Meta {
                        width: parent.width
                        visible: root.phase === "loading"
                        font.weight: 500
                        text: "Reading the focused window…"
                    }

                    Column {
                        width: parent.width
                        visible: root.ready && !root.forceArmed
                        spacing: 8

                        ActionRow {
                            width: parent.width
                            label: "Close window"
                            detail: "Lets the app save, ask, or keep running."
                            binding: "C"
                            onActivated: root.closeWindow()
                        }

                        ActionRow {
                            width: parent.width
                            label: "Force quit app…"
                            detail: "Use when the app is frozen or will not close."
                            binding: "F"
                            tone: Theme.shellStatusBad
                            onActivated: root.armForceQuit()
                        }
                    }

                    Column {
                        width: parent.width
                        visible: root.ready && root.forceArmed
                        spacing: 8

                        Text {
                            width: parent.width
                            text: "This stops the process immediately. Unsaved work will be lost, and other windows from the same app may close."
                            font.family: Theme.fontSans
                            font.pixelSize: 12
                            lineHeight: 1.25
                            wrapMode: Text.WordWrap
                            color: Theme.shellInk2
                            textFormat: Text.PlainText
                        }

                        ActionRow {
                            width: parent.width
                            label: "Force quit now"
                            detail: "This action cannot be undone."
                            binding: "F"
                            tone: Theme.shellStatusBad
                            filled: true
                            onActivated: root.forceQuit()
                        }

                        ActionRow {
                            width: parent.width
                            label: "Cancel"
                            detail: "Return without changing the app."
                            binding: "Esc"
                            onActivated: root.cancelForceQuit()
                        }
                    }

                    Text {
                        width: parent.width
                        visible: root.phase === "empty" || root.phase === "failed"
                        text: root.failure
                        font.family: Theme.fontSans
                        font.pixelSize: 12
                        lineHeight: 1.25
                        wrapMode: Text.WordWrap
                        color: root.phase === "failed" ? Theme.shellStatusBad : Theme.shellInk3
                        textFormat: Text.PlainText
                    }

                    Meta {
                        width: parent.width
                        visible: root.ready
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.1)
                        text: root.forceArmed ? "F Confirm · Esc Cancel"
                                                   : "C Close normally · F Force quit · Esc Dismiss"
                    }
                }
            }
        }
    }
}
