//@ pragma AppId punar-mail
// Punar Mail — the first Punar surface that is an APPLICATION WINDOW.
//
// THE PRAGMA ABOVE IS LOAD-BEARING and must stay on its own line at the top.
// quickshell parses `//@ pragma AppId <value>` out of this file before Qt
// starts (src/launch/launch.cpp:116) and hands it to
// QGuiApplication::setDesktopFileName, which is what becomes the xdg-toplevel
// app_id on Wayland. Without it every Quickshell process reports the default
// `org.quickshell`, so the bar, the window-actions surface and the launcher
// index would all see the toolkit rather than the product — and the greeter
// and the shell would be indistinguishable from this window. `punar-mail`
// matches punar-mail.desktop, which is how Apps.displayNameForAppId resolves
// it to the product name a person reads.
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
            anchors.fill: parent
            focus: true
            Keys.onEscapePressed: win.visible = false

            // ---- masthead ------------------------------------------------
            // The §5 grammar the whole shell shares: identity left, state
            // right, a 2px ink rule under it. Mono, tracked, uppercase.
            Item {
                id: masthead

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                height: 44

                Text {
                    anchors.left: parent.left
                    anchors.leftMargin: 16
                    anchors.verticalCenter: parent.verticalCenter
                    text: "PUNAR · MAIL"
                    font.family: Theme.fontMono
                    font.pixelSize: 10
                    font.weight: 600
                    font.letterSpacing: Theme.tracking(10, 0.15)
                    color: Theme.shellFg
                }

                // NO COUNT, NO CLOCK, NO SYNC TIME. Every one of those would be
                // a claim, and this window has no account to make one about.
                Text {
                    anchors.right: parent.right
                    anchors.rightMargin: 16
                    anchors.verticalCenter: parent.verticalCenter
                    text: "NO ACCOUNT"
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.13)
                    color: Theme.shellInk3
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

            // ---- body ----------------------------------------------------
            // DASHED, BECAUSE NOTHING HERE IS REAL YET. The design language
            // reserves a dashed outline for a capability that is drawn but not
            // operating; a solid one asserts the thing works. Drawing a plain
            // empty inbox here would be the exact dishonesty that grammar
            // exists to prevent.
            Item {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: mastheadRule.bottom
                anchors.bottom: footerRule.top

                Column {
                    anchors.centerIn: parent
                    width: Math.min(parent.width - 64, 560)
                    spacing: 14

                    Canvas {
                        id: dashed

                        width: parent.width
                        height: 128
                        onPaint: {
                            var ctx = dashed.getContext("2d");
                            ctx.reset();
                            ctx.strokeStyle = Theme.shellBorder;
                            ctx.lineWidth = 1;
                            ctx.setLineDash([5, 5]);
                            ctx.strokeRect(0.5, 0.5, dashed.width - 1, dashed.height - 1);
                        }

                        Column {
                            anchors.centerIn: parent
                            spacing: 8

                            Text {
                                anchors.horizontalCenter: parent.horizontalCenter
                                text: "NOT A MAIL CLIENT YET"
                                font.family: Theme.fontMono
                                font.pixelSize: 10
                                font.weight: 600
                                font.letterSpacing: Theme.tracking(10, 0.15)
                                color: Theme.shellInk3
                            }
                            Text {
                                anchors.horizontalCenter: parent.horizontalCenter
                                width: dashed.width - 48
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.WordWrap
                                text: "This window reads no mail, contacts no server "
                                    + "and stores nothing. It exists to prove that a "
                                    + "Punar application window works."
                                font.family: Theme.fontSans
                                font.pixelSize: 12
                                color: Theme.shellInk2
                            }
                        }
                    }

                    // What the spike actually proves, stated as facts rather
                    // than as a roadmap. Each line is true of the running
                    // process or it does not belong here.
                    Column {
                        width: parent.width
                        spacing: 4

                        Repeater {
                            model: [
                                "xdg-toplevel · Quickshell FloatingWindow",
                                "design system · Theme module over QML_IMPORT_PATH",
                                "process · its own qs -p, like the greeter",
                                "keyboard · Esc closes"
                            ]

                            Text {
                                required property string modelData

                                text: "· " + modelData
                                font.family: Theme.fontMono
                                font.pixelSize: 9
                                font.weight: 500
                                font.letterSpacing: Theme.tracking(9, 0.13)
                                color: Theme.shellInk3
                            }
                        }
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
                    text: "ESC CLOSE"
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
                    text: "Window spike · nothing is connected"
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
