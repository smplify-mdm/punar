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

    IdentityRing {
        id: identity
    }

    // The mood decision lives here, with the surface that knows it, rather than
    // in the palette. On panel, panelInk3 measures 3.39:1 against a panel tint
    // and fails the 4.5 text floor, so panel steps up to panelInk2 at 5.81:1;
    // paper has headroom either way.
    function labelTint(slot: int): color {
        var i = slot >= 0 && slot < 8 ? slot : identity.neutralSlot;
        return Theme.moodPanel ? identity.panelTint[i] : identity.paperTint[i];
    }

    function labelInk(): color {
        return Theme.moodPanel ? Theme.panelInk2 : Theme.ink2;
    }

    // INLINE COMPONENTS LIVE ON THE FILE ROOT, AND THAT IS NOT A STYLE
    // CHOICE. An inline component is a file-scoped TYPE; declaring one
    // nested inside a Column or a Row makes the engine refuse the whole
    // file, and the only symptom is a window that never maps. Every one of
    // the twenty-odd inline components in the shipped shell sits at this
    // exact depth — a direct child of its file's root object — and this
    // file being the sole exception is what cost three CI cycles.

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

    component RailRow: Item {
        id: railRow

        required property string label
        required property int tally
        required property bool current
        required property bool verbatim

        width: parent.width
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

    component Chip: Rectangle {
        id: chipRoot

        required property string text
        // COLOURS ARE PASSED IN, not looked up. An inline component lives at
        // the file root and is its own scope, so reaching for an id declared
        // inside the window would be a cross-scope reference the engine cannot
        // resolve soundly. Handing the resolved values in keeps the chip a
        // pure renderer and lets the caller decide whether this chip carries a
        // person's identity or is derived from the message.
        required property color fill
        required property color textInk

        // A TINT, NOT AN OUTLINE. The reference fills its chips and draws no
        // border, and side by side an outlined chip reads as a CONTROL —
        // something to press — while a filled one reads as a property of the
        // row. Structure stays monochrome per §2, so this is `muted`: the same
        // raised ground the focused row uses, at an elevation the language
        // already ships. A per-label hue belongs here once labels carry
        // identity colour; the shape is ready for it.
        height: 16
        width: chipText.implicitWidth + 12
        radius: Theme.radiusTag
        color: chipRoot.fill
        border.width: 0

        Text {
            id: chipText

            anchors.centerIn: parent
            text: chipRoot.text
            font.family: Theme.fontMono
            font.pixelSize: Theme.metaSize
            font.weight: 600
            font.letterSpacing: Theme.tracking(Theme.metaSize, 0.12)
            // The attachment chip is the one DERIVED
            // chip and is distinguished from a label by
            // weight of ink, not by a second silhouette.
            color: chipRoot.textInk
        }
    }

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

                    // THE VIEW NAME LEADS, and the wordmark is gone. The bar
                    // already says PUNAR, permanently, three pixels above this
                    // one — repeating it inside the window spent the most
                    // valuable line on the screen restating what the desktop
                    // never stops saying. The reference gives this line to the
                    // view for the same reason.
                    Text {
                        text: "Inbox"
                        font.family: Theme.fontSans
                        font.pixelSize: 15
                        font.weight: 600
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
                        // ONE NUMBER, COMPUTED FROM WHAT IS ON SCREEN. The
                        // rail printed a hand-written 12 while this printed the
                        // fixture's real 3, so two numbers about the same thing
                        // disagreed in one window — the exact dishonesty this
                        // language exists to prevent. Both now read the model.
                        text: fixtures.unreadCount + " unread"
                        font.family: Theme.fontSans
                        font.pixelSize: 12
                        font.weight: 400
                        color: Theme.shellInk3
                    }
                    Text {
                        anchors.right: parent.right
                        // FIXTURE, and the footer says so. A real client prints
                        // the sync clock; this one prints a constant, because a
                        // surface that invents a plausible timestamp is lying
                        // in the one register this design cares most about.
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
                width: 260

                Column {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.topMargin: 14
                    spacing: 0


                    // A rail row prints a name and, when it has one, a count.
                    // A count of zero is ABSENT rather than rendered as "0":
                    // nothing is not a quantity.

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
                            // -1 means "ask the model", so the rail and the
                            // masthead cannot drift apart.
                            tally: modelData.count === -1 ? fixtures.unreadCount : modelData.count
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
                    height: row.modelData.thread === null ? 30 : 34

                    // GROUP HEAD. Its hairline is the only horizontal line in
                    // the whole field — there are no rules between rows, and
                    // separation is the gutter. Per-row rules turn a list into
                    // a table, which is the spreadsheet feeling this refuses.
                    Item {
                        anchors.fill: parent
                        visible: row.modelData.thread === null

                        // THE HEAD SITS ON ITS RULE. It was top-aligned with
                        // eleven pixels of air below it, so each head read as
                        // belonging to the group ABOVE — the rule looked like a
                        // divider between rows rather than an underline for the
                        // label. Three pixels of clearance is enough to say
                        // "this line belongs to what follows".
                        Text {
                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.bottom: headRule.top
                            anchors.bottomMargin: 3
                            text: row.modelData.head
                            font.family: Theme.fontSans
                            font.pixelSize: 11
                            font.weight: 500
                            color: Theme.shellInk3
                        }
                        // NO GROUP COUNT. The reference prints none, and it was
                        // the only number on the screen nobody asked for: the
                        // rows are right there to be counted, and a tally on a
                        // time bucket answers a question no one reading mail is
                        // holding.
                        Rectangle {
                            id: headRule

                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: 4
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
                            anchors.leftMargin: 14
                            anchors.verticalCenter: parent.verticalCenter
                            width: 12
                            visible: threadRow.t.marked === true
                            text: "\u00d7"
                            font.family: Theme.fontMono
                            font.pixelSize: 12
                            color: Theme.shellFg
                        }

                        // UNREAD DOT, restored. The recorded design said weight
                        // ALONE and dropped the dot; seeing the two side by side
                        // the reference is right that a scanner wants a mark at
                        // a fixed x, because weight is only legible once your
                        // eye is already on the word. Both are kept: the dot
                        // finds the row, the weight survives the dot being
                        // invisible to anyone who cannot separate it from the
                        // ground. It is INK, not the reference's brand blue.
                        Rectangle {
                            id: unread

                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            width: 5
                            height: 5
                            radius: 2.5
                            visible: threadRow.t.unread === true && !mark.visible
                            color: Theme.shellFg
                        }

                        // [01] correspondent — unread is WEIGHT, never a dot.
                        Text {
                            id: who

                            anchors.left: parent.left
                            anchors.leftMargin: 30
                            anchors.verticalCenter: parent.verticalCenter
                            width: 190
                            text: threadRow.t.correspondent
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 13
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
                            id: subject

                            anchors.left: depth.right
                            anchors.leftMargin: 8
                            anchors.verticalCenter: parent.verticalCenter
                            // Bounded, so a long subject cannot push the preview
                            // off the row; the preview takes whatever is left.
                            width: Math.min(implicitWidth,
                                (chips.x - depth.x - 8) * 0.62)
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 13
                            font.weight: threadRow.t.unread ? 500 : 400
                            color: threadRow.t.unread ? Theme.shellFg : Theme.shellInk2
                            // TWO TEXTS, NOT ONE STRING. The design asked for a
                            // separator between subject and preview and the
                            // first build used three spaces, so the two ran
                            // together as one sentence and the subject had no
                            // end. They are drawn separately now — subject in
                            // the row's own weight, preview always ink-3 and
                            // 400 — so the boundary is carried by contrast
                            // rather than by punctuation, and only the preview
                            // elides.
                            text: threadRow.t.subject
                        }

                        // THE PREVIEW IS A SEPARATE TEXT, always ink-3 and 400.
                        // The first build joined subject and preview with three
                        // spaces into one string, so they ran together as a
                        // single sentence and the subject had no end. The
                        // boundary is carried by contrast now rather than by
                        // punctuation, and only the preview elides.
                        Text {
                            anchors.left: subject.right
                            anchors.leftMargin: 8
                            anchors.right: chips.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            elide: Text.ElideRight
                            textFormat: Text.PlainText
                            font.family: Theme.fontSans
                            font.pixelSize: 13
                            font.weight: 400
                            color: Theme.shellInk3
                            text: threadRow.t.preview
                        }

                        // [04] chips, right-aligned, never wrapping. A third
                        // label collapses to +n rather than pushing the time.
                        Row {
                            id: chips

                            anchors.right: when.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 4


                            Repeater {
                                model: Math.min(2, threadRow.t.labels.length)

                                Chip {
                                    required property int index

                                    text: threadRow.t.labels[index].toUpperCase()
                                    fill: root.labelTint(fixtures.slotFor(threadRow.t.labels[index]))
                                    textInk: root.labelInk()
                                }
                            }
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                visible: threadRow.t.labels.length > 2
                                text: "+" + (threadRow.t.labels.length - 2)
                                font.family: Theme.fontMono
                                font.pixelSize: Theme.metaSize
                                color: Theme.shellInk3
                            }
                            Chip {
                                visible: threadRow.t.attachment !== ""
                                text: threadRow.t.attachment
                                // Derived from the message, not assigned by a
                                // person, so it carries no identity hue.
                                fill: Theme.shellMuted
                                textInk: Theme.shellInk3
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
