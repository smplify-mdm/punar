//@ pragma Env QML_IMPORT_PATH = /usr/share/punar/shell
//@ pragma AppId org.punar.Mail
// Punar Mail — the first Punar surface that is an APPLICATION WINDOW.
//
// BOTH PRAGMAS ABOVE ARE LOAD-BEARING and must stay at the very top.
//
// Env QML_IMPORT_PATH — Theme is a shared package module one directory above
// this configuration root, and an independent QML engine will not resolve its
// colour properties without that root on the import path. The greeter exports
// it from its session script, and copying that would have been the obvious
// move and the wrong one: this wrapper is NOT the only launch path. Every
// m*-check.sh in this repository drives a surface with a bare
// `qs -p /usr/share/punar/shell/...`, so a wrapper-only export leaves Theme
// unresolved in exactly the CI path that is supposed to prove the surface
// works. quickshell applies Env pragmas with qputenv before it constructs the
// QQmlEngine (launch.cpp:88-110, :185-190), so the requirement lives in the
// file that depends on it and cannot be bypassed.
//
// AppId — quickshell hands this to QGuiApplication::setDesktopFileName
// (launch.cpp:293), which is what Qt sends as the xdg-toplevel app_id on
// Wayland. Left at the default every Quickshell process announces itself as
// `org.quickshell`: window rules could not target this window, the bar and the
// overview could not name it, startup notification would never match the
// launcher, and the greeter, the shell and this window would be
// indistinguishable to the compositor.
//
// IT IS REVERSE-DNS, AND THE DESKTOP FILE HAS TO MATCH IT EXACTLY.
// Apps.displayNameForAppId joins a runtime app id to a desktop entry by the
// entry's FILE ID and nothing else — not StartupWMClass, which the shell never
// reads. So `org.punar.Mail` requires org.punar.Mail.desktop; naming the file
// punar-mail.desktop while the window announced org.punar.Mail would put the
// raw id back in the bar, which is the bug that was fixed this morning.
// tests/desktop/mail-identity-contract-test.sh asserts all three agree.
//
// WHAT THIS IS AND IS NOT. This is the window spike named in
// docs/design/mail-calendar-contacts.md §4 as the gate every estimate past it
// depended on: until an xdg-toplevel existed in this repository, the cost of a
// first-party client was a guess. It is not a mail client. It reads no mail,
// speaks to no server, and stores nothing, and it says so on its own face in
// the honesty grammar rather than drawing a convincing empty inbox.
//
// THE QUESTION IT ANSWERS. Every one of the seventeen shell surfaces is a
// layer-shell PanelWindow (plus Lock, a WlSessionLock); FloatingWindow,
// ApplicationWindow, xdg_toplevel and any GUI crate appear nowhere in the tree.
// The capability was nevertheless already shipped: quickshell 0.3.0 registers
// FloatingWindow (src/window/floatingwindow.hpp:107) with title, minimumSize,
// maximumSize, minimized, maximized, fullscreen and parentWindow over
// ProxyWindowBase. So a first-party application needs no new toolkit, no new
// language, no new binding and no new dependency.
//
// THE PROCESS MODEL IS THE GREETER'S, verbatim. Greeter/shell.qml is already a
// separate Quickshell configuration run as its own process, reaching the shared
// design system through QML_IMPORT_PATH=/usr/share/punar/shell
// (usr/lib/punar/greeter-session.sh:16). `Theme` is therefore imported as a
// real QML module rather than by relative path: a parent-directory singleton
// import leaves its colour properties unresolved in an independent engine,
// which the greeter learned the hard way and recorded in its own header.
//
// Launched by /usr/lib/punar/punar-mail.sh, which sets that import path and
// execs `qs -p /usr/share/punar/shell/Mail`.

pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Theme

ShellRoot {
    id: root

    // A real xdg-toplevel. The compositor tiles it like any other client, which
    // is the point: Punar's window grammar already knows how to arrange
    // windows, and an application that invents its own panes inside one window
    // is refusing that grammar. docs/design/mail-calendar-contacts.md §5 makes
    // this explicit for threads — opening one is a compositor act.
    FloatingWindow {
        id: win

        title: "Punar Mail"
        // Two column-widths of readable text plus the rail, at the type ramp
        // below. Smaller than this and the masthead has to truncate, which is
        // the one thing the masthead may never do.
        minimumSize: Qt.size(720, 480)
        implicitWidth: 1100
        implicitHeight: 720
        color: Theme.shellSurface

        // ESC CLOSES, and on day one that is the whole keyboard contract. The
        // in-app grammar (bare keys, no modifier, because every OS chord
        // carries the Punar key) is specified in the design and deliberately
        // not invented here: a spike that grows a keymap stops being a spike.
        Item {
            id: frame

            anchors.fill: parent
            focus: true

            // ---- model -------------------------------------------------
            Fixtures {
                id: fixtures
            }

            // The list is flat and carries its own group heads, because a
            // section header that scrolls with its section is one item in one
            // list — and a ListView with sticky headers would need a second
            // model and a delegate that outlives its section.
            readonly property var rows: {
                var out = [];
                var group = "";
                var pending = -1;
                for (var i = 0; i < fixtures.threads.length; i++) {
                    var t = fixtures.threads[i];
                    if (t.group !== group) {
                        group = t.group;
                        out.push({ "head": group, "count": 0, "thread": null });
                        pending = out.length - 1;
                    }
                    out[pending].count += 1;
                    out.push({ "head": "", "count": 0, "thread": t });
                }
                return out;
            }

            property int cursor: 1

            function step(delta: int): void {
                var next = frame.cursor;
                for (var guard = 0; guard < frame.rows.length; guard++) {
                    next += delta;
                    if (next < 0 || next >= frame.rows.length)
                        return;
                    // Group heads are not stops. The cursor walks threads.
                    if (frame.rows[next].thread !== null) {
                        frame.cursor = next;
                        list.positionViewAtIndex(next, ListView.Contain);
                        return;
                    }
                }
            }

            Keys.onEscapePressed: win.visible = false
            Keys.onPressed: function (event) {
                if (event.key === Qt.Key_J || event.key === Qt.Key_Down) {
                    frame.step(1);
                    event.accepted = true;
                } else if (event.key === Qt.Key_K || event.key === Qt.Key_Up) {
                    frame.step(-1);
                    event.accepted = true;
                }
            }

            // ---- masthead ----------------------------------------------
            // Two lines each side over a 2px ink rule: identity left, state
            // right. The shell's own grammar, and the reason every screen in
            // the design is specified as "L1 / L2 | R1 / R2".
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
                        text: "PUNAR · MAIL · INBOX"
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        font.weight: 600
                        font.letterSpacing: Theme.tracking(10, 0.15)
                        color: Theme.shellFg
                    }
                    Text {
                        text: fixtures.account.toUpperCase() + " · " + fixtures.protocol
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
                        text: "IN:INBOX"
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        font.weight: 600
                        font.letterSpacing: Theme.tracking(10, 0.15)
                        color: Theme.shellFg
                    }
                    Text {
                        anchors.right: parent.right
                        // FIXTURE, and the footer says so. A real client prints
                        // the sync clock; this one prints a constant, because a
                        // surface that invents a plausible timestamp is lying
                        // in the one register this design cares most about.
                        text: fixtures.unreadCount + " UNREAD · FIXTURE DATA"
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

            // ---- rail ---------------------------------------------------
            // 208px, a 1px right rule, tracked-mono section heads, no icons,
            // no search row, no settings foot. It is a DISPLAY: it never takes
            // keyboard focus, and `v` will later open the same model as a
            // bounded instrument over the list.
            Item {
                id: rail

                anchors.left: parent.left
                anchors.top: mastheadRule.bottom
                anchors.bottom: footerRule.top
                width: 208

                Column {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.topMargin: 14
                    spacing: 0

                    component RailHead: Text {
                        font.family: Theme.fontMono
                        font.pixelSize: 9
                        font.weight: 600
                        font.letterSpacing: Theme.tracking(9, 0.14)
                        color: Theme.shellInk3
                        leftPadding: 16
                        topPadding: 14
                        bottomPadding: 6
                    }

                    // A rail row prints a name and, when it has one, a count.
                    // A count of zero is ABSENT rather than rendered as "0":
                    // nothing is not a quantity.
                    component RailRow: Item {
                        id: railRow

                        required property string label
                        required property int tally
                        required property bool current
                        required property bool verbatim

                        width: rail.width
                        height: 24

                        Rectangle {
                            anchors.fill: parent
                            color: Theme.shellMuted
                            visible: railRow.current
                        }
                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 2
                            color: Theme.shellFg
                            visible: railRow.current
                        }

                        Text {
                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.right: tallyText.left
                            anchors.rightMargin: 8
                            anchors.verticalCenter: parent.verticalCenter
                            // Server strings print verbatim; Punar's own view
                            // names are product vocabulary and take the
                            // masthead's sentence case.
                            text: railRow.label
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 12
                            font.weight: railRow.current ? 500 : 400
                            color: railRow.current ? Theme.shellFg : Theme.shellInk2
                        }

                        Text {
                            id: tallyText

                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            visible: railRow.tally > 0
                            text: railRow.tally
                            font.family: Theme.fontMono
                            font.pixelSize: 10
                            font.weight: 500
                            color: Theme.shellInk3
                        }
                    }

                    RailHead {
                        text: "ACCOUNT"
                        topPadding: 0
                    }
                    RailRow {
                        label: fixtures.account
                        tally: 0
                        current: false
                        verbatim: true
                    }

                    RailHead {
                        text: "VIEWS"
                    }
                    Repeater {
                        model: fixtures.views

                        RailRow {
                            required property var modelData

                            label: modelData.name
                            tally: modelData.count
                            current: modelData.current
                            verbatim: false
                        }
                    }

                    RailHead {
                        text: "FOLDERS · IMAP"
                    }
                    Repeater {
                        model: fixtures.folders

                        RailRow {
                            required property string modelData

                            label: modelData
                            tally: 0
                            current: false
                            verbatim: true
                        }
                    }
                }
            }

            Rectangle {
                id: railRule

                anchors.left: rail.right
                anchors.top: mastheadRule.bottom
                anchors.bottom: footerRule.top
                width: Theme.hairline
                color: Theme.shellBorder
            }

            // ---- thread list --------------------------------------------
            ListView {
                id: list

                anchors.left: railRule.right
                anchors.right: parent.right
                anchors.top: mastheadRule.bottom
                anchors.bottom: footerRule.top
                clip: true
                boundsBehavior: Flickable.StopAtBounds
                model: frame.rows

                delegate: Item {
                    id: row

                    required property int index
                    required property var modelData

                    width: list.width
                    height: row.modelData.thread === null ? 34 : 40

                    // GROUP HEAD. Its hairline is the only horizontal line in
                    // the whole field — there are no rules between rows, and
                    // separation is the gutter. Per-row rules turn a list into
                    // a table, which is the spreadsheet feeling this refuses.
                    Item {
                        anchors.fill: parent
                        visible: row.modelData.thread === null

                        Text {
                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.bottom: headRule.top
                            anchors.bottomMargin: 5
                            text: row.modelData.head.toUpperCase()
                            font.family: Theme.fontMono
                            font.pixelSize: 11
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(11, 0.12)
                            color: Theme.shellInk3
                        }
                        Text {
                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.bottom: headRule.top
                            anchors.bottomMargin: 5
                            text: row.modelData.count
                            font.family: Theme.fontMono
                            font.pixelSize: 11
                            font.weight: 500
                            color: Theme.shellInk3
                        }
                        Rectangle {
                            id: headRule

                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: 6
                            height: Theme.hairline
                            color: Theme.shellBorder
                        }
                    }

                    // THREAD ROW — six columns on a fixed grid so the eye
                    // reads down a column rather than tracking a ragged edge.
                    Item {
                        id: threadRow

                        anchors.fill: parent
                        visible: row.modelData.thread !== null

                        readonly property var t: row.modelData.thread
                        readonly property bool focused: row.index === frame.cursor

                        // FOCUS is a ground lift plus a 2px ink rule on the
                        // left edge — the same selection statement the
                        // groupbar's active tab and D-007's overview use.
                        Rectangle {
                            anchors.fill: parent
                            color: Theme.shellMuted
                            visible: threadRow.focused
                        }
                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 2
                            color: Theme.shellFg
                            visible: threadRow.focused
                        }

                        // [00] mark gutter — the key that made the mark is the
                        // mark. Nothing is marked in the fixture.
                        Text {
                            id: mark

                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            width: 16
                            visible: threadRow.t.marked === true
                            text: "\u00d7"
                            font.family: Theme.fontMono
                            font.pixelSize: 12
                            color: Theme.shellFg
                        }

                        // [01] correspondent — unread is WEIGHT, never a dot.
                        Text {
                            id: who

                            anchors.left: parent.left
                            anchors.leftMargin: 32
                            anchors.verticalCenter: parent.verticalCenter
                            width: 168
                            text: threadRow.t.correspondent
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 12.5
                            font.weight: threadRow.t.unread ? 500 : 400
                            color: threadRow.t.unread ? Theme.shellFg : Theme.shellInk2
                        }

                        // [02] depth — absent when the thread is one message.
                        Text {
                            id: depth

                            anchors.left: who.right
                            anchors.leftMargin: 4
                            anchors.verticalCenter: parent.verticalCenter
                            width: 24
                            visible: threadRow.t.depth > 1
                            text: threadRow.t.depth
                            font.family: Theme.fontMono
                            font.pixelSize: 10
                            color: Theme.shellInk3
                        }

                        // [03] subject · preview — elides as ONE string with a
                        // single ellipsis, so the line never breaks twice.
                        Text {
                            anchors.left: depth.right
                            anchors.leftMargin: 8
                            anchors.right: chips.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 12.5
                            font.weight: threadRow.t.unread ? 500 : 400
                            color: threadRow.t.unread ? Theme.shellFg : Theme.shellInk2
                            text: threadRow.t.subject + "   " + threadRow.t.preview
                        }

                        // [04] chips, right-aligned, never wrapping. A third
                        // label collapses to +n rather than pushing the time.
                        Row {
                            id: chips

                            anchors.right: when.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 4

                            component Chip: Rectangle {
                                id: chipRoot

                                required property string text
                                required property bool derived

                                height: 17
                                width: chipText.implicitWidth + 12
                                radius: Theme.radiusTag
                                color: "transparent"
                                border.width: Theme.hairline
                                border.color: Theme.shellBorder

                                Text {
                                    id: chipText

                                    anchors.centerIn: parent
                                    text: chipRoot.text
                                    font.family: Theme.fontMono
                                    font.pixelSize: 9.5
                                    font.weight: 600
                                    font.letterSpacing: Theme.tracking(9.5, 0.12)
                                    // The attachment chip is the one DERIVED
                                    // chip and is distinguished from a label by
                                    // weight of ink, not by a second silhouette.
                                    color: chipRoot.derived ? Theme.shellInk3 : Theme.shellFg
                                }
                            }

                            Repeater {
                                model: Math.min(2, threadRow.t.labels.length)

                                Chip {
                                    required property int index

                                    text: threadRow.t.labels[index].toUpperCase()
                                    derived: false
                                }
                            }
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                visible: threadRow.t.labels.length > 2
                                text: "+" + (threadRow.t.labels.length - 2)
                                font.family: Theme.fontMono
                                font.pixelSize: 9.5
                                color: Theme.shellInk3
                            }
                            Chip {
                                visible: threadRow.t.attachment !== ""
                                text: threadRow.t.attachment
                                derived: true
                            }
                        }

                        // [05] time — fixed width so the column never jitters.
                        Text {
                            id: when

                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            width: 56
                            horizontalAlignment: Text.AlignRight
                            text: threadRow.t.time
                            font.family: Theme.fontMono
                            font.pixelSize: 10
                            color: Theme.shellInk3
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        enabled: row.modelData.thread !== null
                        onClicked: frame.cursor = row.index
                    }
                }
            }

            // ---- footer meta row -----------------------------------------
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
                    text: "J/K MOVE · ESC CLOSE"
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
                    // THE ONLY HONEST THING THIS SURFACE CAN SAY. Every string
                    // above is written by hand; no account exists, no server
                    // was contacted, and nothing was read from disk.
                    text: "FIXTURE DATA · NO ACCOUNT · NOTHING IS CONNECTED"
                    font.family: Theme.fontMono
                    font.pixelSize: 8
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(8, 0.13)
                    color: Theme.shellInk3
                }
            }
        }
    }
}
