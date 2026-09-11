// A thread, as its own window.
//
// THIS IS THE DESIGN'S SHARPEST DEPARTURE FROM THE REFERENCE, and the whole
// reason it is a separate file rather than a pane. Every mail client the
// reference included answers "open a message" with a reading pane inside the
// index window. Punar answers it with a second xdg-toplevel and lets the
// compositor arrange the two, because the window manager already knows how to
// put two things side by side and an application that reimplements that inside
// one window is refusing a grammar the desktop already has.
//
// It sets `title` and `minimumSize` and NOTHING positional — no geometry, no
// parentWindow, no float request, no window rule. parentWindow in particular
// would issue xdg_toplevel.set_parent, which marks the surface transient, and
// Hyprland's dialog handling would then float it as a centred card. A thread is
// a document, not a dialog: floating it would put back the stacked-card feeling
// that the original complaint about Evolution was about.

pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Theme

FloatingWindow {
    id: win

    required property var thread
    required property var messages
    required property string account
    required property string protocol

    title: win.thread === null ? "Thread" : win.thread.subject
    minimumSize: Qt.size(520, 380)
    implicitWidth: 820
    implicitHeight: 720
    color: Theme.shellSurface

    // Message index the keyboard is walking. -1 before anything is focused.
    property int cursor: 0

    signal closeRequested()

    function step(delta: int): void {
        var next = win.cursor + delta;
        if (next < 0 || next >= win.messages.length)
            return;
        win.cursor = next;
        body.positionViewAtIndex(next, ListView.Contain);
    }

    Item {
        anchors.fill: parent
        focus: true

        Keys.onEscapePressed: win.closeRequested()
        Keys.onPressed: function (event) {
            if (event.key === Qt.Key_N) {
                win.step(1);
                event.accepted = true;
            } else if (event.key === Qt.Key_P) {
                win.step(-1);
                event.accepted = true;
            }
        }

        // ---- masthead ------------------------------------------------
        Item {
            id: masthead

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: 52

            Column {
                anchors.left: parent.left
                anchors.leftMargin: 16
                anchors.verticalCenter: parent.verticalCenter
                spacing: 3

                Text {
                    text: "Thread"
                    font.family: Theme.fontSans
                    font.pixelSize: 15
                    font.weight: 600
                    color: Theme.shellFg
                }
                Text {
                    text: win.account.toUpperCase() + " · " + win.protocol
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.13)
                    color: Theme.shellInk3
                }
            }

            Column {
                anchors.right: parent.right
                anchors.rightMargin: 16
                anchors.verticalCenter: parent.verticalCenter
                spacing: 3

                Text {
                    anchors.right: parent.right
                    // Singular and plural are both written out. "1 messages" is
                    // the kind of small lie that tells a reader nobody looked.
                    text: win.messages.length === 1 ? "1 message"
                        : win.messages.length + " messages"
                    font.family: Theme.fontSans
                    font.pixelSize: 12
                    color: Theme.shellInk3
                }
                Text {
                    anchors.right: parent.right
                    text: "FIXTURE DATA"
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.13)
                    color: Theme.shellInk3
                }
            }
        }

        Rectangle {
            id: mastheadRule

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: masthead.bottom
            height: 2
            color: Theme.shellFg
        }

        // ---- the subject, as a display line --------------------------
        // The one place in this application where type gets to be large. A
        // thread has exactly one thing it is about, and the window says it once
        // rather than repeating it above every message.
        Text {
            id: subjectLine

            anchors.left: parent.left
            anchors.leftMargin: 16
            anchors.right: parent.right
            anchors.rightMargin: 16
            anchors.top: mastheadRule.bottom
            anchors.topMargin: 18
            text: win.thread === null ? "" : win.thread.subject
            textFormat: Text.PlainText
            wrapMode: Text.WordWrap
            maximumLineCount: 2
            elide: Text.ElideRight
            font.family: Theme.fontSans
            font.pixelSize: 22
            font.weight: 600
            color: Theme.shellFg
        }

        // ---- messages -------------------------------------------------
        ListView {
            id: body

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: subjectLine.bottom
            anchors.topMargin: 16
            anchors.bottom: footerRule.top
            clip: true
            boundsBehavior: Flickable.StopAtBounds
            model: win.messages
            spacing: 0

            delegate: Item {
                id: msg

                required property int index
                required property var modelData

                width: body.width
                implicitHeight: msgColumn.implicitHeight + 30

                // Focus is the same statement the index uses: a 2px ink rule on
                // the left edge. No fill, because a message is long and a filled
                // block of text reads as quoted rather than as selected.
                Rectangle {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    anchors.bottom: parent.bottom
                    width: 2
                    color: Theme.shellFg
                    visible: msg.index === win.cursor
                }

                Column {
                    id: msgColumn

                    anchors.left: parent.left
                    anchors.leftMargin: 16
                    anchors.right: parent.right
                    anchors.rightMargin: 16
                    anchors.top: parent.top
                    anchors.topMargin: 14
                    spacing: 8

                    Item {
                        width: parent.width
                        height: from.implicitHeight

                        Text {
                            id: from

                            text: msg.modelData.from
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 13
                            font.weight: 500
                            color: Theme.shellFg
                        }
                        Text {
                            anchors.left: from.right
                            anchors.leftMargin: 8
                            anchors.right: when.left
                            anchors.rightMargin: 12
                            anchors.baseline: from.baseline
                            text: msg.modelData.address
                            textFormat: Text.PlainText
                            elide: Text.ElideRight
                            font.family: Theme.fontSans
                            font.pixelSize: 12
                            color: Theme.shellInk3
                        }
                        Text {
                            id: when

                            anchors.right: parent.right
                            anchors.baseline: from.baseline
                            text: msg.modelData.date
                            font.family: Theme.fontMono
                            font.pixelSize: 10
                            color: Theme.shellInk3
                        }
                    }

                    Text {
                        width: parent.width
                        text: msg.modelData.body
                        // PLAIN TEXT, ALWAYS. Qt's AutoText promotes a string
                        // containing markup to rich text, which over IMAP means
                        // a sender chooses the renderer.
                        textFormat: Text.PlainText
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 13
                        lineHeight: 1.45
                        color: Theme.shellInk2
                    }

                    // AFTER THE FACT, ON THE MESSAGE IT HAPPENED TO. A setting
                    // buried in preferences saying "remote content is blocked"
                    // is a claim; this is a receipt. Dashed, because it names
                    // something that did NOT run.
                    Loader {
                        active: msg.modelData.remote === true
                        width: parent.width
                        sourceComponent: RemoteNotice {}
                    }
                }

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    anchors.leftMargin: 16
                    anchors.rightMargin: 16
                    height: Theme.hairline
                    color: Theme.shellBorder
                    visible: msg.index < win.messages.length - 1
                }
            }
        }

        // ---- footer ---------------------------------------------------
        Rectangle {
            id: footerRule

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: footer.top
            height: Theme.hairline
            color: Theme.shellBorder
        }

        Item {
            id: footer

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: 29

            Text {
                anchors.left: parent.left
                anchors.leftMargin: 16
                anchors.verticalCenter: parent.verticalCenter
                text: "N/P MESSAGE · ESC CLOSE"
                font.family: Theme.fontMono
                font.pixelSize: 8
                font.weight: 500
                font.letterSpacing: Theme.tracking(8, 0.13)
                color: Theme.shellInk3
            }
            Text {
                anchors.right: parent.right
                anchors.rightMargin: 16
                anchors.verticalCenter: parent.verticalCenter
                text: "FIXTURE DATA · NOTHING IS CONNECTED"
                font.family: Theme.fontMono
                font.pixelSize: 8
                font.weight: 500
                font.letterSpacing: Theme.tracking(8, 0.13)
                color: Theme.shellInk3
            }
        }
    }

    component RemoteNotice: Canvas {
        id: notice

        height: 30
        onPaint: {
            var ctx = notice.getContext("2d");
            ctx.reset();
            ctx.strokeStyle = Theme.shellBorder;
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.strokeRect(0.5, 0.5, notice.width - 1, notice.height - 1);
        }

        Text {
            anchors.left: parent.left
            anchors.leftMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            text: "REMOTE CONTENT BLOCKED · NOTHING WAS FETCHED FOR THIS MESSAGE"
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 500
            font.letterSpacing: Theme.tracking(9, 0.12)
            color: Theme.shellInk3
        }
    }
}
