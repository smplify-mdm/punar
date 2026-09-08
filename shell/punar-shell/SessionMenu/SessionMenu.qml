pragma ComponentBehavior: Bound
// SessionMenu — lock, end session, restart, shut down, in one place.
//
// WHY THIS IS A MENU AND NOT A BAR POPOVER. The obvious home was a slot in the
// status cluster, and Bar/SlotPopover.qml forbids it in its own header:
// "Nothing in a popover is destructive, and nothing in a popover is the only
// way to reach something." Shutting a machine down is destructive by any
// reading. So this follows WindowActions instead — an Overlay surface that
// takes the keyboard while it is open, prints a key on every row, and arms a
// destructive action before performing it.
//
// NOTHING HERE IS THE ONLY WAY TO REACH ANYTHING, which is the other half of
// that rule and is satisfied by construction: Lock is PUNAR+Escape, and End
// session, Restart and Shut down are all in System Control's Power view. This
// surface is a shortcut, not a sole route.
//
// ARM, THEN ACT. The three destructive rows relabel to "Press again to …" on
// first activation and only run on the second, which is the pattern System
// Control's Power view already uses and the reason a single stray click cannot
// end a session. Escape disarms before it dismisses, so backing out of a
// half-pressed shutdown never closes the menu by surprise. Lock is not
// destructive — the session is exactly where you left it — so it acts at once.
//
// THE VERBS ARE LOGIND'S AND THE COMPOSITOR'S, not punard's. There is no typed
// capability for power, and inventing a root RPC for it would be the generic
// execution primitive the spec forbids; polkit decides whether this session may
// act. Every argv here is fixed and none is built from anything a user typed.
//
// Driven from Hyprland or a gate via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call session toggle

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Theme"
import "../Services"

DeferredSurfaceBase {
    id: root

    property bool openOnReady: false
    property bool windowVisible: false

    /// "" | "sessionEnd" | "systemRestart" | "systemPowerOff"
    property string armed: ""

    /// The last fixed argv this surface ran, for the report a gate reads. Never
    /// carries anything a person typed, because nothing here is typed.
    property string lastAction: ""

    /// "" | "sessionEnd" | "systemRestart" | "systemPowerOff" — the action that
    /// has been launched and has not yet answered.
    property string pending: ""

    /// Why the last attempt failed, in the words the tool used. Empty when
    /// nothing has failed.
    property string failure: ""

    /// The exit status of the action in flight, or -1 while it is unknown.
    /// Recorded separately from settling because the two arrive out of order:
    /// `exited` fires when the process goes, `onStreamFinished` when its stderr
    /// is complete, and only the second one can quote what it said.
    property int lastExit: -1

    readonly property int rowCount: 4

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
        visible: cap.label !== ""

        Text {
            id: keyLabel

            anchors.centerIn: parent
            text: cap.label
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            font.letterSpacing: Theme.tracking(9, 0.1)
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

        signal activated

        implicitHeight: 52
        radius: Theme.radiusTag
        color: actionMouse.containsMouse ? Theme.shellMuted : "transparent"
        border.width: Theme.hairline
        border.color: action.tone

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
                color: action.tone
                elide: Text.ElideRight
            }
            Text {
                width: parent.width
                text: action.detail
                font.family: Theme.fontSans
                font.pixelSize: 12
                font.weight: 400
                color: Theme.shellInk3
                elide: Text.ElideRight
                textFormat: Text.PlainText
                visible: action.detail !== ""
            }
        }

        KeyCap {
            id: keycap

            anchors.right: parent.right
            anchors.rightMargin: 13
            anchors.verticalCenter: parent.verticalCenter
            label: action.binding
            tone: action.tone
        }

        MouseArea {
            id: actionMouse

            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: action.activated()
        }
    }

    // ---- behaviour ---------------------------------------------------------

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("session");
        root.armed = "";
        root.windowVisible = true;
        root.open = true;
    }

    function dismiss(): void {
        root.open = false;
        root.armed = "";
        root.failure = "";
        // `pending` too: this surface is unloaded on dismiss, and a reopen that
        // came back with a stale `pending` would find every destructive row
        // permanently inert — activate() returns early while it is set.
        root.pending = "";
        root.windowVisible = false;
        root.unloadRequested();
    }

    function toggle(): void {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    /// Lock is immediate: it destroys nothing and the session is exactly where
    /// it was left. Everything else arms first.
    function lockNow(): void {
        root.lastAction = "lock";
        root.dismiss();
        lockRequested();
    }

    signal lockRequested

    function activate(kind: string): void {
        if (kind === "lock") {
            root.lockNow();
            return;
        }
        if (root.pending !== "")
            return;
        if (root.armed !== kind) {
            root.armed = kind;
            return;
        }
        root.armed = "";
        root.lastAction = kind;
        root.failure = "";
        root.pending = kind;
        // Fixed argv, chosen by a switch over a closed set — never assembled
        // from a string that reached this surface from anywhere else. Absolute
        // paths: this surface must not depend on whatever PATH the login
        // manager happened to hand the session.
        root.lastExit = -1;
        // exec() can throw before anything is started at all. Unguarded, that
        // left `pending` set with no process to ever clear it, and every row
        // dead for the life of the surface — a silent failure of exactly the
        // kind this surface was rewritten to stop having.
        try {
            if (kind === "sessionEnd")
                power.exec(["/usr/bin/hyprctl", "dispatch", "exit"]);
            else if (kind === "systemRestart")
                power.exec(["/usr/bin/systemctl", "reboot"]);
            else if (kind === "systemPowerOff")
                power.exec(["/usr/bin/systemctl", "poweroff"]);
        } catch (e) {
            root.settle(127);
        }
    }

    /// THE MENU DOES NOT CLOSE ON THE SECOND PRESS, and that is deliberate.
    ///
    /// It closed immediately before, which meant a refused reboot looked
    /// exactly like an accepted one: the surface went away and the machine
    /// stayed up, with the reason — logind's, polkit's, or a missing binary's —
    /// written to a stderr nobody was collecting. A power action either takes
    /// the machine down, in which case nothing is left to look at, or it fails,
    /// in which case the failure is the only thing worth showing.
    function settle(exitCode: int): void {
        var kind = root.pending;
        root.pending = "";
        if (kind === "")
            return;
        if (exitCode === 0) {
            root.dismiss();
            return;
        }
        var said = String(powerErr.text).trim().split("\n").filter(function (line) {
            return line.trim() !== "";
        });
        root.failure = said.length > 0
            ? said[said.length - 1]
            : (exitCode < 0
                ? "The command ended without saying why."
                : "The command exited " + exitCode + " without saying why.");
    }

    Process {
        id: power

        stderr: StdioCollector {
            id: powerErr

            waitForEnd: true
            // SETTLE HERE, not in `exited`. With waitForEnd the collector's
            // text is complete only once the stream closes, and `exited` can
            // arrive first — which is how the failure line this surface exists
            // to show came out empty. By the time stderr has ended the process
            // is gone and `lastExit` holds its status.
            onStreamFinished: root.settle(root.lastExit)
        }

        Component.onCompleted: power.exited.connect(function (exitCode) {
            root.lastExit = exitCode;
        })

        // A binary that cannot be started at all never emits `exited` and never
        // produces a stream to finish. settle() clears `pending` first, so
        // whichever path arrives first wins and the others are no-ops.
        onRunningChanged: if (!power.running && root.pending !== "")
            Qt.callLater(function () {
                if (root.pending !== "")
                    root.settle(root.lastExit);
            })
    }

    // ---- the surface -------------------------------------------------------

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
        // `punar-session`, matching the surface's IPC target name, because the
        // desktop gate asserts a mapped layer called `punar-<target>` for every
        // surface it opens. The old `punar-session-menu` spelling was the
        // reason this surface sat outside that loop and shipped unexercised.
        WlrLayershell.namespace: "punar-session"
        WlrLayershell.layer: WlrLayer.Overlay

        // THE SURFACE STEPS ASIDE THE MOMENT AN ACTION IS IN FLIGHT, and the
        // reason is the dialog it might have to make room for.
        //
        // `systemctl reboot` asks interactively. When polkit challenges the
        // action — which the shipped policy still does for the
        // `-ignore-inhibit` verbs this device deliberately does NOT grant —
        // hyprpolkitagent raises a password prompt, and systemctl blocks on the
        // answer. That prompt is an ordinary toplevel. An overlay layer surface
        // holding EXCLUSIVE keyboard focus takes the keyboard away from every
        // toplevel, and a full-output input region takes the pointer too: the
        // person would see the prompt and be unable to type into it or click
        // it, with the only way out being a click that cancels the reboot.
        //
        // So while `pending` is set the keyboard is released and the input
        // region shrinks to the card. The menu stays VISIBLE — that is the
        // whole point of not dismissing — but it stops being in the way.
        WlrLayershell.keyboardFocus: root.open && root.pending === ""
            ? WlrKeyboardFocus.Exclusive
            : WlrKeyboardFocus.None

        mask: root.pending === "" ? null : cardRegion

        Region {
            id: cardRegion
            item: card
        }

        onVisibleChanged: if (win.visible)
            keyFocus.forceActiveFocus()

        Item {
            id: keyFocus

            anchors.fill: parent
            focus: root.open

            Keys.onPressed: function (event) {
                switch (event.key) {
                case Qt.Key_Escape:
                    // Disarm before dismissing: backing out of a half-pressed
                    // shutdown must not also close the menu, or the second
                    // Escape someone reflexively presses lands somewhere else.
                    // A reported failure is dismissed the same way, and first,
                    // so Escape never throws away an explanation unread.
                    if (root.failure !== "")
                        root.failure = "";
                    else if (root.armed !== "")
                        root.armed = "";
                    else
                        root.dismiss();
                    event.accepted = true;
                    break;
                case Qt.Key_L:
                    root.activate("lock");
                    event.accepted = true;
                    break;
                case Qt.Key_E:
                    root.activate("sessionEnd");
                    event.accepted = true;
                    break;
                case Qt.Key_R:
                    root.activate("systemRestart");
                    event.accepted = true;
                    break;
                case Qt.Key_S:
                    root.activate("systemPowerOff");
                    event.accepted = true;
                    break;
                }
            }

            MouseArea {
                anchors.fill: parent
                // Disabled while an action is in flight: dismissing unloads
                // this surface, which destroys the Process and kills the
                // systemctl that is waiting on an authentication answer. A
                // stray click must not abort a reboot.
                enabled: root.pending === ""
                onClicked: root.dismiss()
            }

            Rectangle {
                id: card

                // Anchored under the bar at the RIGHT edge, beneath the glyph
                // that opens it, the way the clock's neighbourhood implies.
                width: Math.min(312, win.width - 24)
                x: Math.max(12, win.width - width - 12)
                y: 38
                height: body.implicitHeight + 26
                radius: Theme.radius
                color: Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellBorder

                MouseArea {
                    anchors.fill: parent
                    // The card absorbs its own clicks so the scrim beneath does
                    // not dismiss the menu the moment a row is pressed.
                    onClicked: {}
                }

                Column {
                    id: body

                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.leftMargin: 13
                    anchors.rightMargin: 13
                    anchors.topMargin: 13
                    spacing: 7

                    Meta {
                        width: parent.width
                        text: "Session · " + root.accountLabel
                        elide: Text.ElideRight
                    }

                    Rectangle {
                        width: parent.width
                        height: Theme.hairline
                        color: Theme.shellBorder
                    }

                    ActionRow {
                        width: parent.width
                        label: "Lock"
                        detail: "Your windows stay exactly where they are"
                        binding: "L"
                        onActivated: root.activate("lock")
                    }

                    ActionRow {
                        width: parent.width
                        label: root.pending === "sessionEnd"
                            ? "Ending session…"
                            : root.armed === "sessionEnd"
                                ? "Press again to end session" : "End session"
                        detail: root.armed === "sessionEnd"
                            ? "Open applications will close"
                            : "Sign out and return to the login screen"
                        binding: "E"
                        tone: root.armed === "sessionEnd" ? Theme.shellStatusWarn : Theme.shellFg
                        onActivated: root.activate("sessionEnd")
                    }

                    ActionRow {
                        width: parent.width
                        label: root.pending === "systemRestart"
                            ? "Restarting…"
                            : root.armed === "systemRestart"
                                ? "Press again to restart" : "Restart"
                        detail: root.armed === "systemRestart"
                            ? "The machine will reboot now" : ""
                        binding: "R"
                        tone: root.armed === "systemRestart" ? Theme.shellStatusWarn : Theme.shellFg
                        onActivated: root.activate("systemRestart")
                    }

                    ActionRow {
                        width: parent.width
                        label: root.pending === "systemPowerOff"
                            ? "Shutting down…"
                            : root.armed === "systemPowerOff"
                                ? "Press again to shut down" : "Shut down"
                        detail: root.armed === "systemPowerOff"
                            ? "The machine will power off now" : ""
                        binding: "S"
                        tone: root.armed === "systemPowerOff" ? Theme.shellStatusWarn : Theme.shellFg
                        onActivated: root.activate("systemPowerOff")
                    }

                    // Shown only when an action was refused. The tool's own last
                    // line is quoted rather than paraphrased: "Interactive
                    // authentication required" is a fixable sentence, and any
                    // wording of ours would be a guess about which of several
                    // refusals happened.
                    Text {
                        width: parent.width
                        visible: root.failure !== ""
                        text: root.failure
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        color: Theme.shellStatusWarn
                        textFormat: Text.PlainText
                    }

                    Text {
                        width: parent.width
                        text: "Esc closes · these also live in System Control · Power"
                        font.family: Theme.fontMono
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.1)
                        color: Theme.shellInputBorder
                        elide: Text.ElideRight
                        textFormat: Text.PlainText
                    }
                }
            }
        }
    }

    // The account this menu would act on, so "End session" names whose.
    readonly property string accountLabel: {
        var u = Quickshell.env("USER");
        return u ? String(u) : "this device";
    }

    function ipcState(): string {
        return root.open ? "open" : "closed";
    }
}
