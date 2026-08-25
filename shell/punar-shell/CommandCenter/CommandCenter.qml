pragma ComponentBehavior: Bound
// CommandCenter — the SUPER+Space overlay, implementing the command-center
// card of docs/design/mockups/command-approval.html (Sect I): centered
// 560px paper card on a warm ink-wash scrim, masthead row, sans input,
// glyph-tag result rows, selection = raise fill + 2px ink left rule,
// footer meta row carrying the principle line.
//
// M1 data sources: installed .desktop applications (DesktopEntries) plus a
// static table of punarctl action stubs. NO shell-string execution — every
// launch is DesktopEntry.execute() or a fixed argv from ACTIONS below
// (mockup register: "the command center never generates a shell string").
//
// M3 INTEGRATION POINT: ACTIONS below is replaced by rows from punard's
// capability registry (spec §41) over typed IPC; each row then carries the
// real typed capability it resolves to, and `meta` prints that contract.
//
// Toggled from Hyprland via Quickshell IPC:
//   qs ipc call commandcenter toggle   (equivalently: quickshell ipc call …)

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Theme"
import "../Services"

Scope {
    id: root

    property bool open: false
    property bool windowVisible: false

    // Meta-row / label grammar (DESIGN_LANGUAGE.md §1): mono, tracked,
    // uppercase. Sizes follow the mockup CSS, rounded to whole px
    // (font.pixelSize is integral: 8.5 → 9, 8 → 8).
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.ink3
    }

    function show() {
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
    }

    function dismiss() {
        if (!root.open)
            return;
        root.open = false;
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle() {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    // SUPER+Space entry point. Hyprland binds:
    //   bind = SUPER, Space, exec, qs ipc call commandcenter toggle
    IpcHandler {
        target: "commandcenter"

        function toggle(): void {
            root.toggle();
        }
        function open(): void {
            root.show();
        }
        function close(): void {
            root.dismiss();
        }
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: root.windowVisible = false
    }

    // ---- M1 static actions (fixed argv table — never a shell string) ----
    // Glyph codes follow the mockup's two-letter mono grammar.
    readonly property var staticActions: [
        {
            group: "Punar",
            glyph: "TE",
            name: "Open terminal",
            meta: "OpenTerminal() · foot",
            cap: true,
            kind: "exec",
            exec: ["foot"]
        },
        {
            group: "Punar",
            glyph: "SY",
            name: "System Control",
            meta: "SystemControl() · arrives M3",
            cap: true,
            kind: "stub"
        }
    ]

    function glyphFor(name: string): string {
        var words = name.trim().split(/\s+/);
        if (words.length >= 2 && words[0].length > 0 && words[1].length > 0) {
            // String() gives the linter a concrete string type for the
            // list elements (avoids a QJSPrimitiveValue false positive).
            return String(words[0]).charAt(0).toUpperCase()
                   + String(words[1]).charAt(0).toUpperCase();
        }
        return name.substring(0, 2).toUpperCase();
    }

    function buildResults(query: string, apps: var): var {
        var q = query.trim().toLowerCase();
        var out = [];
        for (var i = 0; i < root.staticActions.length; i++) {
            var a = root.staticActions[i];
            if (q === "" || a.name.toLowerCase().indexOf(q) !== -1)
                out.push(a);
        }
        var matched = [];
        for (var j = 0; j < apps.length; j++) {
            var e = apps[j]; // DesktopEntries pre-filters Hidden/NoDisplay
            var hay = (e.name + " " + (e.genericName || "") + " "
                       + (e.comment || "") + " "
                       + (e.keywords ? e.keywords.join(" ") : "")).toLowerCase();
            if (q === "" || hay.indexOf(q) !== -1)
                matched.push(e);
        }
        matched.sort(function (a, b) {
            return a.name.localeCompare(b.name);
        });
        for (var k = 0; k < matched.length; k++) {
            var m = matched[k];
            out.push({
                group: "Applications",
                glyph: root.glyphFor(m.name),
                name: m.name,
                meta: (m.genericName && m.genericName !== "") ? m.genericName : "Application",
                cap: false,
                kind: "app",
                entry: m
            });
        }
        return out;
    }

    function activate(item: var) {
        if (item === null || item === undefined)
            return;
        if (item.kind === "app")
            item.entry.execute(); // parsed Exec via Quickshell — no shell string
        else if (item.kind === "exec")
            Quickshell.execDetached(item.exec); // fixed argv table
        // kind === "stub": placeholder until the M3 capability registry.
        root.dismiss();
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
        // Fully clear backing surface (not a design color): the scrim and
        // card below own all visible pixels.
        color: "transparent"
        WlrLayershell.namespace: "punar-commandcenter"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

        onVisibleChanged: {
            if (win.visible) {
                queryInput.text = "";
                queryInput.forceActiveFocus();
            }
        }

        readonly property var results: root.buildResults(queryInput.text,
                                                         DesktopEntries.applications.values)
        onResultsChanged: list.currentIndex = win.results.length > 0 ? 0 : -1

        // Warm ink-wash scrim at 22% (mockup .scrim) — motion is the 300ms
        // token curve, only on show/hide (§4: fluid, not decorative).
        Rectangle {
            id: scrim
            anchors.fill: parent
            color: Theme.inkWash
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

        // ---- the command card (mockup .cc) ----
        Rectangle {
            id: card

            width: Math.min(560, win.width * 0.78)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? win.height * 0.11 : (win.height * 0.11) - 10
            height: cardColumn.implicitHeight
            color: Theme.paperSurface
            border.width: Theme.hairline
            border.color: Theme.border
            radius: Theme.radius
            clip: true
            opacity: root.open ? 1 : 0
            // NOTE: the mockup's soft drop shadow is deliberately omitted in
            // M1 — blur effects are costly on the llvmpipe VM path and the
            // scrim already separates the card (PERFORMANCE_BUDGETS.md).

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
                id: cardColumn
                width: parent.width

                // Masthead row (mockup .cc .head): PUNAR · COMMAND | context.
                Item {
                    width: parent.width
                    height: 32

                    Row {
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 0

                        Meta {
                            text: "Punar"
                            color: Theme.ink
                        }
                        Meta {
                            text: " · Command"
                        }
                    }

                    Row {
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 5

                        Rectangle {
                            anchors.verticalCenter: parent.verticalCenter
                            width: 5
                            height: 5
                            radius: 2.5
                            color: Status.color // stub — M5 wires punard
                        }
                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            text: Status.project + " · " + Status.label
                        }
                    }

                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: Theme.hairline
                        color: Theme.border
                    }
                }

                // Input row (mockup .cc input: Instrument Sans 16.5/500).
                Item {
                    width: parent.width
                    height: 47

                    TextInput {
                        id: queryInput
                        anchors.fill: parent
                        anchors.leftMargin: 16
                        anchors.rightMargin: 16
                        anchors.topMargin: 14
                        anchors.bottomMargin: 12
                        font.family: Theme.fontSans
                        font.pixelSize: 17 // mockup 16.5px
                        font.weight: 500
                        color: Theme.ink
                        clip: true

                        Keys.onPressed: function (event) {
                            switch (event.key) {
                            case Qt.Key_Escape:
                                root.dismiss();
                                event.accepted = true;
                                break;
                            case Qt.Key_Down:
                                list.incrementCurrentIndex();
                                event.accepted = true;
                                break;
                            case Qt.Key_Up:
                                list.decrementCurrentIndex();
                                event.accepted = true;
                                break;
                            case Qt.Key_Return:
                            case Qt.Key_Enter:
                                root.activate(list.currentIndex >= 0
                                              ? win.results[list.currentIndex] : null);
                                event.accepted = true;
                                break;
                            }
                        }
                    }

                    Text {
                        anchors.fill: queryInput
                        visible: queryInput.text === ""
                        text: "Type — an app, a setting, a project, or plain intent"
                        font.family: Theme.fontSans
                        font.pixelSize: 17
                        font.weight: 400
                        color: Theme.inputBorder
                        elide: Text.ElideRight
                    }
                }

                // Results (mockup .cc .body, max-height 300).
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.border
                }

                ListView {
                    id: list

                    width: parent.width
                    height: Math.min(contentHeight, 300)
                    clip: true
                    interactive: contentHeight > height
                    keyNavigationWraps: false
                    model: win.results
                    highlightMoveDuration: Theme.durStandard // selection movement — the
                    highlightMoveVelocity: -1                // only other animated thing
                    highlightResizeDuration: 0

                    // Group headers (mockup .grp .gh).
                    section.property: "group"
                    section.delegate: Item {
                        id: sectionRow
                        required property string section
                        width: list.width
                        height: 24

                        Meta {
                            anchors.left: parent.left
                            anchors.leftMargin: 16
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: 4
                            font.letterSpacing: Theme.tracking(9, 0.16)
                            text: sectionRow.section
                        }
                    }

                    // Selection = raise fill + 2px ink left rule (mockup .row.sel;
                    // register 02: "no color spent").
                    highlight: Rectangle {
                        color: Theme.muted

                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 2
                            color: Theme.ink
                        }
                    }

                    delegate: Item {
                        id: row

                        required property int index
                        required property var modelData

                        readonly property bool sel: row.ListView.isCurrentItem

                        width: list.width
                        height: 42

                        Row {
                            anchors.left: parent.left
                            anchors.leftMargin: 14
                            anchors.right: rowMeta.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 12

                            // Glyph tag: two-letter mono code in a bordered
                            // square — icons stay out, the surface stays
                            // monochrome (mockup register 02).
                            Rectangle {
                                anchors.verticalCenter: parent.verticalCenter
                                width: 26
                                height: 26
                                radius: Theme.radiusTag
                                color: Theme.paperSurface
                                border.width: Theme.hairline
                                border.color: row.sel ? Theme.ink : Theme.border

                                Text {
                                    anchors.centerIn: parent
                                    text: row.modelData.glyph
                                    font.family: Theme.fontMono
                                    font.pixelSize: 8
                                    font.weight: 600
                                    font.letterSpacing: Theme.tracking(8, 0.06)
                                    color: row.sel ? Theme.ink : Theme.ink2
                                }
                            }

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                width: Math.max(0, parent.width - 38)
                                text: row.modelData.name
                                font.family: Theme.fontSans
                                font.pixelSize: 15 // mockup 14.5px
                                font.weight: 500
                                color: Theme.ink
                                elide: Text.ElideRight
                            }
                        }

                        // Right meta: typed capability (ink-2) or app role (ink-3).
                        Meta {
                            id: rowMeta
                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(9, 0.1)
                            horizontalAlignment: Text.AlignRight
                            text: row.modelData.meta
                            color: row.modelData.cap ? Theme.ink2 : Theme.ink3
                        }

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                list.currentIndex = row.index;
                                root.activate(row.modelData);
                            }
                        }
                    }
                }

                // Explicit empty state — silence is not support.
                Item {
                    width: parent.width
                    height: 36
                    visible: win.results.length === 0

                    Meta {
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.weight: 500
                        text: "No matches"
                    }
                }

                // Footer meta row (mockup .cc .foot) with the principle line.
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.border
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
                        text: "↑↓ Navigate · ↵ Run · Esc Close"
                    }
                    Meta {
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 8
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(8, 0.13)
                        text: "Natural language resolves to typed capabilities"
                    }
                }
            }
        }
    }
}
