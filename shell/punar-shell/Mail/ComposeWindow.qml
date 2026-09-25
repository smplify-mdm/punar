// Writing a message, as its own window.
//
// The third and last window class: index, document, nothing else. Compose is a
// DOCUMENT, not a dialog — a plain FloatingWindow with title and minimumSize
// and nothing positional, exactly like a thread. No parentWindow, which would
// mark the surface transient and let Hyprland float it as a centred card; and
// no modal anywhere in v1, because the complaint that started this whole design
// was a modal stacked on an assistant.
//
// IT COMPOSES text/plain, ONE PART, AND THAT IS A SECURITY DECISION RATHER THAN
// A SIMPLIFICATION. An HTML composer is how a mail client comes to add tracking
// pixels, remote stylesheets and a renderer that a recipient did not ask for.
// Refusing the capability makes "this client adds no tracking pixels" true by
// construction instead of true by policy, and the footer says so where it
// cannot be missed rather than in a preference nobody opens.
//
// Nothing is connected, so nothing can be sent. Ctrl+Return says that plainly
// instead of animating a send and discarding the message.

pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Theme

FloatingWindow {
    id: win

    required property string account
    required property string protocol

    title: subjectField.text === "" ? "New message" : subjectField.text
    minimumSize: Qt.size(480, 360)
    implicitWidth: 720
    implicitHeight: 620
    color: Theme.shellSurface

    // Set when a send is attempted. It is a receipt for what did NOT happen.
    property string note: ""

    signal closeRequested()

    Item {
        anchors.fill: parent

        // THE CARET STARTS IN THE FIRST FIELD. `focus: true` on the Field
        // wrapper does not reach the TextInput inside it — the wrapper is a
        // plain Item and focus does not forward — so a compose window would
        // open with nowhere to type and no visible reason why. A person who
        // presses C and then types should be writing an address.
        Component.onCompleted: toField.input.forceActiveFocus()

        Keys.onEscapePressed: win.closeRequested()

        // ---- masthead ----------------------------------------------
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
                    text: "New message"
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
                    text: "Plain text"
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

        // ---- header fields ------------------------------------------
        // The underline field: the greeter's passphrase grammar, reused. A box
        // around an input is chrome; a rule under it is structure, and this
        // language draws structure with rules.
        Column {
            id: headerFields

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: mastheadRule.bottom
            spacing: 0

            Field {
                id: toField

                width: headerFields.width
                label: "TO"
                placeholder: "someone@example.com"
                nextItem: subjectField.input
            }
            Field {
                id: subjectField

                width: headerFields.width
                label: "SUBJECT"
                placeholder: "What it is about"
                nextItem: bodyInput
            }
        }

        // ---- body ----------------------------------------------------
        Flickable {
            id: bodyScroll

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: headerFields.bottom
            anchors.bottom: noticeRow.top
            anchors.margins: 16
            clip: true
            contentWidth: width
            contentHeight: bodyInput.implicitHeight
            boundsBehavior: Flickable.StopAtBounds

            TextEdit {
                id: bodyInput

                width: bodyScroll.width
                wrapMode: TextEdit.Wrap
                // PLAIN, and the property says it as well as the footer does.
                textFormat: TextEdit.PlainText
                font.family: Theme.fontSans
                font.pixelSize: 13
                color: Theme.shellFg
                selectionColor: Theme.shellFg
                selectedTextColor: Theme.shellSurface
                selectByMouse: true

                Keys.onPressed: function (event) {
                    if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter)
                            && (event.modifiers & Qt.ControlModifier)) {
                        win.note = "NOT SENT · NO ACCOUNT IS CONFIGURED · NOTHING LEFT THIS DEVICE";
                        event.accepted = true;
                    }
                }

                Text {
                    anchors.left: parent.left
                    anchors.top: parent.top
                    visible: bodyInput.text === ""
                    text: "Write the message."
                    font.family: Theme.fontSans
                    font.pixelSize: 13
                    color: Theme.shellInk3
                }
            }
        }

        // ---- the receipt ---------------------------------------------
        Item {
            id: noticeRow

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: footerRule.top
            height: win.note === "" ? 0 : 34
            visible: win.note !== ""

            Canvas {
                id: noticeFrame

                anchors.fill: parent
                anchors.leftMargin: 16
                anchors.rightMargin: 16
                anchors.bottomMargin: 8
                onPaint: {
                    var ctx = noticeFrame.getContext("2d");
                    ctx.reset();
                    ctx.strokeStyle = Theme.shellBorder;
                    ctx.lineWidth = 1;
                    ctx.setLineDash([4, 4]);
                    ctx.strokeRect(0.5, 0.5, noticeFrame.width - 1, noticeFrame.height - 1);
                }

                Text {
                    anchors.left: parent.left
                    anchors.leftMargin: 10
                    anchors.verticalCenter: parent.verticalCenter
                    text: win.note
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.12)
                    color: Theme.shellInk3
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
                // CTRL+RETURN, and it is the one place this application breaks
                // its own bare-key rule. It has to: the body is a text field,
                // and the grammar says bare keys are dead inside one. PUNAR+
                // Return is already the terminal.
                text: "CTRL+↵ SEND · ESC CLOSE"
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
                text: "TEXT/PLAIN · NO HTML · NO TRACKING PIXELS ADDED"
                font.family: Theme.fontMono
                font.pixelSize: 8
                font.weight: 500
                font.letterSpacing: Theme.tracking(8, 0.13)
                color: Theme.shellInk3
            }
        }
    }

    // The header fields both live here so the label column cannot drift between
    // them: one definition, one width, one rule.
    component Field: Item {
        id: fieldRow

        required property string label
        required property string placeholder
        // Where Tab goes. Set from the call site so the order lives where the
        // fields are declared, in the order a person reads them.
        property var nextItem: null
        property alias text: fieldInput.text
        property alias input: fieldInput

        height: 44

        Text {
            anchors.left: parent.left
            anchors.leftMargin: 16
            anchors.verticalCenter: parent.verticalCenter
            width: 64
            text: fieldRow.label
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            font.letterSpacing: Theme.tracking(9, 0.14)
            color: Theme.shellInk3
        }

        TextInput {
            id: fieldInput

            anchors.left: parent.left
            anchors.leftMargin: 88
            anchors.right: parent.right
            anchors.rightMargin: 16
            anchors.verticalCenter: parent.verticalCenter
            height: 24
            font.family: Theme.fontSans
            font.pixelSize: 13
            color: Theme.shellFg
            selectionColor: Theme.shellFg
            selectedTextColor: Theme.shellSurface
            selectByMouse: true
            KeyNavigation.tab: fieldRow.nextItem

            Text {
                anchors.verticalCenter: parent.verticalCenter
                visible: fieldInput.text === ""
                text: fieldRow.placeholder
                font.family: Theme.fontSans
                font.pixelSize: 13
                color: Theme.shellInk3
            }
        }

        // A rule under the field, not a box around it: this language draws
        // structure with rules, and a box would be chrome.
        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.leftMargin: 16
            anchors.rightMargin: 16
            height: Theme.hairline
            color: Theme.shellBorder
        }
    }
}
