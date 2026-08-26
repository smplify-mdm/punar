pragma ComponentBehavior: Bound
// LockSurface — the paper lock screen, one instance per output.
//
// Plate D-002 (docs/design/mockups/boot-greeter.html) drew the greeter;
// Plate D-012 Sect III (docs/design/mockups/identity-elevation.html) drew
// the lock as "the greeter's sibling", in its own words: *"Same masthead,
// same tabular clock, same underline passphrase field as Plate D-002 — the
// only difference is what is behind it: a running session instead of a
// fresh one, and the footer says so."* That is exactly what this file is.
//
// Grammar, straight from the two plates:
//   masthead   device identity left, trust state right, closed by the 2px
//              ink rule. Org rows and the compliance pill appear ONLY when
//              enrolled (DESIGN_LANGUAGE §8 — a personal lock is calm
//              paper with no absence to apologize for).
//   clock      display-weight tabular time, the surface's only large type,
//              with the tracked-mono date beneath.
//   identity   initials in a hairline circle, name, account.
//   passphrase mono, letter-spaced, over a single hairline — no box.
//   unlock     the one coloured element on the screen: a consequential
//              affirmative in the ok-green action fill (DESIGN_LANGUAGE §2
//              "Action color"), exactly as Sign in does on the greeter.
//   footer     hairline, then what is true: the session is still here.
//
// Deliberate deviation from D-002's words: the failed-unlock SHAKE is not
// drawn. Rejection is carried by the TRY AGAIN meta and, from the third
// attempt, the bad-red voice the plate specifies — motion here would be
// decorative rather than explanatory (DESIGN_LANGUAGE §4), and a lock
// screen is the last surface that should acquire an animation budget.

import QtQuick
import Quickshell.Wayland
import "../Theme"
import "../Services"

WlSessionLockSurface {
    id: surface

    // Identity and state, supplied by Lock.qml.
    property string displayName: ""
    property string accountName: ""
    property string hostName: ""
    property string timeText: "--:--"
    property string dateText: ""
    // The field-note masthead's right-hand data slot: MM · YYYY (D-002).
    property string monthYear: ""
    property int attempts: 0
    property bool busy: false
    property bool secure: false
    property string failure: ""

    signal submitted(string passphrase)

    color: Theme.shellSurface

    readonly property string initials: {
        var source = surface.displayName !== "" ? surface.displayName : surface.accountName;
        var words = String(source).trim().split(/\s+/);
        if (words.length >= 2 && words[0].length > 0 && words[1].length > 0)
            return String(words[0]).charAt(0).toUpperCase() + String(words[1]).charAt(0).toUpperCase();
        return String(source).substring(0, 2).toUpperCase();
    }

    // The plate's third-failure rule: red only once the machine has told
    // the reader twice. Before that, rejection is stated, not coloured.
    readonly property bool hardFailure: surface.attempts >= 3

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 10
        font.weight: 500
        font.letterSpacing: Theme.tracking(10, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    function clearField(): void {
        field.text = "";
    }

    function focusField(): void {
        field.forceActiveFocus();
    }

    Component.onCompleted: surface.focusField()

    // A rejected passphrase never stays in the field: the next keystroke
    // must start a fresh attempt, not append to the failed one. `attempts`
    // increments on every rejection, so this fires exactly once per
    // rejection even when the message text repeats.
    onAttemptsChanged: {
        if (surface.attempts > 0) {
            surface.clearField();
            surface.focusField();
        }
    }

    // ---- masthead ---------------------------------------------------------

    Item {
        id: masthead
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.leftMargin: parent.width * 0.045
        anchors.rightMargin: parent.width * 0.045
        anchors.topMargin: parent.height * 0.036
        height: Math.max(leftMeta.implicitHeight, rightMeta.implicitHeight) + 12

        Column {
            id: leftMeta
            anchors.left: parent.left
            anchors.top: parent.top
            spacing: 2

            Row {
                spacing: 0
                Meta {
                    text: "Punar"
                    color: Theme.shellFg
                    font.weight: 600
                }
                Meta {
                    text: surface.hostName !== "" ? " · " + surface.hostName : ""
                }
            }
            // Org identity is additive chrome — absent, not greyed, when
            // the device is not enrolled (DESIGN_LANGUAGE §8).
            Meta {
                visible: Status.enrolled && Status.orgName !== ""
                text: Status.orgName + " · Managed"
            }
        }

        Column {
            id: rightMeta
            anchors.right: parent.right
            anchors.top: parent.top
            spacing: 4

            Row {
                anchors.right: parent.right
                spacing: 7

                // Compliance pill: enrolled devices only.
                Rectangle {
                    visible: Status.enrolled
                    anchors.verticalCenter: parent.verticalCenter
                    width: pillRow.implicitWidth + 18
                    height: pillRow.implicitHeight + 8
                    radius: Theme.radiusTag
                    color: Theme.shellSurface
                    border.width: Theme.hairline
                    border.color: Theme.shellBorder

                    Row {
                        id: pillRow
                        anchors.centerIn: parent
                        spacing: 7

                        Rectangle {
                            anchors.verticalCenter: parent.verticalCenter
                            width: 6
                            height: 6
                            radius: 3
                            color: Status.color
                        }
                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            font.pixelSize: 9
                            font.weight: 600
                            font.letterSpacing: Theme.tracking(9, 0.13)
                            color: Theme.shellInk2
                            text: Status.label
                        }
                    }
                }

                Meta {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: !Status.enrolled
                    text: "Locked"
                }
            }

            Meta {
                anchors.right: parent.right
                text: surface.monthYear
            }
        }

        // The masthead rule: 2px ink, the field-note close (§3).
        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 2
            color: Theme.shellFg
        }
    }

    // ---- centre -----------------------------------------------------------

    Column {
        id: centre
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.verticalCenter: parent.verticalCenter
        width: Math.min(parent.width * 0.8, 520)
        spacing: 0

        Text {
            anchors.horizontalCenter: parent.horizontalCenter
            text: surface.timeText
            font.family: Theme.fontSans
            font.weight: 700
            font.pixelSize: Math.round(Math.max(44, Math.min(76, surface.width * 0.09)))
            font.letterSpacing: -0.028 * Math.max(44, Math.min(76, surface.width * 0.09))
            // Data is always tabular (DESIGN_LANGUAGE §1) — a clock must
            // not reflow as the digits change.
            font.features: ({
                    "tnum": 1
                })
            color: Theme.shellFg
        }

        Meta {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: 10
            bottomPadding: Math.round(surface.height * 0.045)
            font.letterSpacing: Theme.tracking(10, 0.18)
            text: surface.dateText
        }

        // Identity row.
        Row {
            anchors.horizontalCenter: parent.horizontalCenter
            spacing: 12

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 34
                height: 34
                radius: 17
                color: Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellFg

                Text {
                    anchors.centerIn: parent
                    text: surface.initials
                    font.family: Theme.fontMono
                    font.pixelSize: 12
                    font.weight: 600
                    color: Theme.shellFg
                }
            }

            Column {
                anchors.verticalCenter: parent.verticalCenter
                spacing: 2

                Text {
                    text: surface.displayName
                    font.family: Theme.fontSans
                    font.pixelSize: 16
                    font.weight: 500
                    color: Theme.shellFg
                }
                Meta {
                    font.pixelSize: 9
                    font.letterSpacing: Theme.tracking(9, 0.1)
                    text: surface.accountName
                }
            }
        }

        // Passphrase row.
        Row {
            anchors.horizontalCenter: parent.horizontalCenter
            topPadding: Math.round(surface.height * 0.03)
            spacing: 12

            Item {
                anchors.verticalCenter: parent.verticalCenter
                width: 220
                height: 34

                TextInput {
                    id: field
                    anchors.fill: parent
                    anchors.bottomMargin: 8
                    enabled: !surface.busy
                    echoMode: TextInput.Password
                    passwordCharacter: "•"
                    passwordMaskDelay: 0
                    horizontalAlignment: Text.AlignHCenter
                    verticalAlignment: Text.AlignVCenter
                    font.family: Theme.fontMono
                    font.pixelSize: 15
                    font.letterSpacing: Theme.tracking(15, 0.25)
                    color: Theme.shellFg
                    clip: true
                    focus: true
                    activeFocusOnTab: true

                    Keys.onPressed: function (event) {
                        switch (event.key) {
                        case Qt.Key_Return:
                        case Qt.Key_Enter:
                            if (!surface.busy && field.text !== "")
                                surface.submitted(field.text);
                            event.accepted = true;
                            break;
                        case Qt.Key_Escape:
                            field.text = "";
                            event.accepted = true;
                            break;
                        }
                    }
                }

                Meta {
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.verticalCenter: field.verticalCenter
                    visible: field.text === ""
                    font.pixelSize: 9
                    font.letterSpacing: Theme.tracking(9, 0.18)
                    color: Theme.shellInputBorder
                    text: "Passphrase"
                }

                // The single hairline the plate draws instead of a box —
                // 2px ink while the field holds the surface's focus, so the
                // focus state is visible and colour-independent
                // (DESIGN_LANGUAGE §9.4). Read from `focus` rather than
                // `activeFocus`: a session-lock surface always owns the
                // keyboard, so which of its two focusables is next in line
                // is the fact worth drawing, and it is true from the first
                // frame rather than from the first key event.
                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: field.focus ? 2 : Theme.hairline
                    color: field.focus ? Theme.shellFg : Theme.shellInputBorder

                    Behavior on height {
                        NumberAnimation {
                            duration: Theme.durMicro
                            easing.type: Easing.BezierSpline
                            easing.bezierCurve: Theme.easingCurve
                        }
                    }
                }
            }

            // Unlock: the one coloured element on the surface.
            Rectangle {
                id: unlockButton
                anchors.verticalCenter: parent.verticalCenter
                width: unlockRow.implicitWidth + 32
                height: unlockRow.implicitHeight + 16
                radius: Theme.radiusTag
                color: Theme.shellActionBg
                opacity: surface.busy ? 0.6 : 1
                activeFocusOnTab: true

                Behavior on opacity {
                    NumberAnimation {
                        duration: Theme.durStandard
                        easing.type: Easing.BezierSpline
                        easing.bezierCurve: Theme.easingCurve
                    }
                }

                Row {
                    id: unlockRow
                    anchors.centerIn: parent
                    spacing: 6

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: surface.busy ? "Checking" : "Unlock"
                        font.family: Theme.fontMono
                        font.pixelSize: 11
                        font.weight: 600
                        font.letterSpacing: Theme.tracking(11, 0.1)
                        font.capitalization: Font.AllUppercase
                        color: Theme.shellActionFg
                    }
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        visible: !surface.busy
                        text: "↵"
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        color: Theme.shellActionFg
                    }
                }

                // Keyboard focus ring: 2px ink, offset 2px, no colour
                // dependence (DESIGN_LANGUAGE §9.4).
                Rectangle {
                    anchors.fill: parent
                    anchors.margins: -4
                    visible: unlockButton.focus
                    color: "transparent"
                    radius: Theme.radiusTag + 2
                    border.width: 2
                    border.color: Theme.shellFg
                }

                Keys.onPressed: function (event) {
                    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Space) {
                        if (!surface.busy && field.text !== "")
                            surface.submitted(field.text);
                        event.accepted = true;
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    enabled: !surface.busy
                    onClicked: {
                        if (field.text !== "")
                            surface.submitted(field.text);
                        else
                            field.forceActiveFocus();
                    }
                }
            }
        }

        // Rejection, in the plate's voice.
        Item {
            anchors.horizontalCenter: parent.horizontalCenter
            width: parent.width
            height: 26

            Meta {
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.verticalCenter: parent.verticalCenter
                visible: surface.failure !== ""
                font.pixelSize: 9
                font.weight: 600
                font.letterSpacing: Theme.tracking(9, 0.14)
                color: surface.hardFailure ? Theme.shellStatusBad : Theme.shellInk3
                text: surface.failure
            }
        }
    }

    // ---- footer -----------------------------------------------------------

    Item {
        id: footer
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: parent.width * 0.045
        anchors.rightMargin: parent.width * 0.045
        anchors.bottomMargin: parent.height * 0.036
        height: 30

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            color: Theme.shellBorder
        }

        Meta {
            anchors.left: parent.left
            anchors.bottom: parent.bottom
            font.pixelSize: 9
            font.letterSpacing: Theme.tracking(9, 0.15)
            // `secure` is the compositor's own acknowledgement that the
            // session-lock protocol took effect and every output is
            // covered. Saying so is spec §1.22 at its most literal: a lock
            // that has not been confirmed must not claim it locked.
            text: surface.secure ? "Session locked · your windows are exactly where you left them" : "Lock not confirmed by the compositor"
            color: surface.secure ? Theme.shellInk3 : Theme.shellStatusBad
        }

        Meta {
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            font.pixelSize: 9
            font.letterSpacing: Theme.tracking(9, 0.15)
            text: "↵ Unlock · Tab Move · Esc Clear"
        }
    }
}
