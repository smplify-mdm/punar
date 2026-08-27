pragma ComponentBehavior: Bound
// Shortcuts — the persistent shortcut help surface (Plate D-017,
// docs/design/mockups/shortcuts.html; Sect II·04, Sect III, Sect V·01).
//
// Spec §12.3 asks for two things — hold SUPER and see the chords, press
// `?` and read them all — and then states the requirement plainly: do not
// make people memorise dozens of undocumented shortcuts. Punar ships
// seventy-two described binds — a number this comment is not the source
// of: the surface counts what `hyprctl binds -j` actually returns, and
// `ipc call shortcuts rows` prints that count, so the config is the only
// authority. Until this file there was no surface naming a single one.
//
// WHAT SHIPS HERE, AND WHAT DOES NOT — stated up front, because D-017
// Sect V·03 marked the hold overlay TO VERIFY and this is the answer:
//
//   SHIPS · the persistent help surface. Opened with SUPER + / from
//   anywhere, and with `?` from the bar's focused status cluster — which
//   is the ONE other surface that implements that key today (see
//   Bar/StatusCluster.qml `Qt.Key_Question`). The full-screen sheets bind
//   `?` to nothing: SystemControl and Overview already spend the
//   unmodified letter row on search, so a bare `?` there would be typed
//   text, not a chord. No surface PRINTS a `?` hint it does not honour.
//   All rows, every layer, every mode, on paper, generated from the
//   compositor's own binding table.
//
//   DOES NOT SHIP · the transient HOLD-SUPER overlay. Hyprland 0.56.2
//   emits no "modifier held" event, and of the three candidates D-017
//   named, the one flag that exists (`bindo`, the `o` long-press flag —
//   src/config/legacy/ConfigManager.cpp handleBind case 'o') fires after
//   the KEYBOARD REPEAT DELAY and exposes no delay of its own
//   (src/managers/KeybindManager.cpp: `m_longPressTimer->updateTimeout(
//   PACTIVEKEEB->m_repeatDelay)`), so D-017's argued 400 ms is
//   unobtainable without moving `input:repeat_delay` for all typing on
//   the machine. The release half (`bindr` on `SUPER_L`) is real and
//   documented in the compositor's own source, but it is SHADOWED after
//   any chord (`shadowKeybinds`), which is precisely the "stranded
//   overlay" failure mode D-017 Sect V·04 feared. A fourth mechanism —
//   `global` + hyprland-global-shortcuts-v1, which is never shadowed and
//   would let the shell own the 400 ms itself — looks correct on paper
//   and has been observed by NOBODY on this compositor, and it needs a
//   bind on the bare SUPER_L keysym in the production config underneath
//   fifty-eight chords built on SUPER. §7 is explicit that implementation
//   alone does not earn a solid line, so the overlay stays a compositor
//   task with a written-down recipe, and half of a discoverability
//   requirement met honestly beats a hold overlay that works on three
//   machines out of four.
//
// HELP DOES NOT EXECUTE (Sect II·05): ↵ on a selected row does nothing,
// and no row offers it. The help surface teaches a chord; it never runs
// one. Running it would mean the shell dispatching the row's dispatcher
// itself — a second execution path alongside the compositor's own — and
// it would teach the wrong lesson, because the key the user pressed was
// not the chord they came to learn. The surface that RUNS things by name
// is one chord away: the command center, SUPER+Space.
//
// NOTHING ORG-SPECIFIC (Sect III·06): no section, no row and no footer
// here knows whether the machine is enrolled. The keyboard grammar is the
// operating system's, identical on a personal laptop and a fleet device.
//
// Toggled from Hyprland via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call shortcuts toggle

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Services"
import "../Theme"

Scope {
    id: root

    property bool open: false
    property bool openOnReady: false
    property bool windowVisible: false
    property string query: ""
    property int selected: 0

    // Meta-row / label grammar (DESIGN_LANGUAGE.md §1) — the same
    // component grammar as Bar, CommandCenter and Overview.
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    BindTable {
        id: table
    }

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("shortcuts");
        // The one query per session, lazily, on first open.
        table.ensure();
        hideTimer.stop();
        root.query = "";
        root.selected = 0;
        root.windowVisible = true;
        root.open = true;
    }

    Component.onCompleted: {
        SurfaceTiming.constructed("shortcuts");
        if (root.openOnReady)
            root.show();
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle(): void {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    IpcHandler {
        target: "shortcuts"

        function toggle(): void {
            root.toggle();
        }
        function open(): void {
            root.show();
        }
        function close(): void {
            root.dismiss();
        }
        // Read-only probe (the `overview` / `aipanel` precedent).
        function state(): string {
            return root.open ? "open" : "closed";
        }
        function latency(): string {
            return SurfaceTiming.sample("shortcuts");
        }
        // The manual half of the invalidation policy: `configreloaded`
        // drops the cache on its own, and this is here for a human who
        // wants to force it.
        function reload(): string {
            table.invalidate();
            table.ensure();
            return "reloading";
        }
        // The acceptance line of D-017 Sect V·07, answerable from CI:
        // rename a description in the config, reload, and see the count
        // and the label change without touching QML.
        function rows(): string {
            return String(table.rowCount);
        }
        function undescribed(): string {
            return String(table.undescribed);
        }
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: root.windowVisible = false
    }

    // ---- layout (Sect II·06) ----------------------------------------

    function matches(row: var, q: string): bool {
        if (q === "")
            return true;
        return (row.label + " " + row.chord + " " + row.dispatcher)
            .toLowerCase().indexOf(q) >= 0;
    }

    // Three real columns, not a multi-column flow: a multi-column body
    // with a vertical scroll silently pushes late sections out of view,
    // and a shortcut reference may not lose rows. Sections stay whole;
    // the body is the single vertical scroll when the tallest column
    // overflows, and filtering is the real overflow answer — two letters
    // usually beat any amount of scrolling.
    function buildLayout(columnCount: int): var {
        var q = root.query.trim().toLowerCase();
        var cols = [];
        var load = [];
        var i;
        for (i = 0; i < columnCount; i++) {
            cols.push([]);
            load.push(0);
        }

        function place(block, weight) {
            var t = 0;
            for (var c = 1; c < cols.length; c++) {
                if (load[c] < load[t])
                    t = c;
            }
            cols[t].push(block);
            load[t] += weight;
        }

        var globals = [];
        for (i = 0; i < table.rows.length; i++) {
            if (root.matches(table.rows[i], q))
                globals.push(table.rows[i]);
        }
        var inMode = [];
        for (i = 0; i < table.modeRows.length; i++) {
            if (root.matches(table.modeRows[i], q))
                inMode.push(table.modeRows[i]);
        }

        var modeBlock = inMode.length === 0 ? null : {
            "kind": "mode",
            "title": table.modeName === "" ? "Mode" : "Mode · " + table.modeName,
            "subtitle": "bare keys · both exits shown",
            "rows": inMode
        };
        var modePlaced = false;

        // Section order is fixed in the shell; row order inside a section
        // is the config's.
        for (var s = 0; s < table.sectionOrder.length; s++) {
            var name = table.sectionOrder[s];
            var bucket = [];
            for (i = 0; i < globals.length; i++) {
                if (globals[i].section === name)
                    bucket.push(globals[i]);
            }
            // OTHER renders only when it is non-empty — and its being
            // non-empty is the alarm, not a category.
            if (bucket.length === 0)
                continue;
            place({
                "kind": "section",
                "title": name,
                "subtitle": "",
                "rows": bucket
            }, bucket.length + 1);
            if (name === "WINDOWS" && modeBlock !== null) {
                place(modeBlock, modeBlock.rows.length + 2);
                modePlaced = true;
            }
        }
        if (!modePlaced && modeBlock !== null)
            place(modeBlock, modeBlock.rows.length + 2);

        // Flat display order, so ↑↓ walk exactly what the eye reads.
        var flat = 0;
        var out = [];
        for (var c2 = 0; c2 < cols.length; c2++) {
            var blocks = [];
            for (var b = 0; b < cols[c2].length; b++) {
                var src = cols[c2][b];
                var rows = [];
                for (var r = 0; r < src.rows.length; r++) {
                    var row = src.rows[r];
                    rows.push({
                        "chord": row.chord,
                        "label": row.label,
                        "mods": row.submap === "" ? table.modNames(row.modmask) : [],
                        "keyText": row.keyText,
                        "isMode": row.isMode,
                        "repeat": row.repeat,
                        "flatIndex": flat++
                    });
                }
                blocks.push({
                    "kind": src.kind,
                    "title": src.title,
                    "subtitle": src.subtitle,
                    "rows": rows
                });
            }
            out.push(blocks);
        }
        return {
            "columns": out,
            "shown": flat
        };
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
        WlrLayershell.namespace: "punar-shortcuts"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

        readonly property int columnCount: win.width > 1200 ? 3 : (win.width > 900 ? 2 : 1)
        readonly property var page: root.buildLayout(win.columnCount)

        onVisibleChanged: {
            if (win.visible)
                queryInput.forceActiveFocus();
        }

        // Keyboard selection scrolls itself into view.
        function reveal(y: real, h: real): void {
            if (h <= 0 || body.height <= 0)
                return;
            if (y < body.contentY)
                body.contentY = Math.max(0, y - 8);
            else if (y + h > body.contentY + body.height)
                body.contentY = Math.min(Math.max(0, body.contentHeight - body.height),
                                         y + h - body.height + 8);
        }

        function step(delta: int): void {
            var n = win.page.shown;
            if (n <= 0)
                return;
            var next = root.selected + delta;
            if (next < 0)
                next = 0;
            if (next > n - 1)
                next = n - 1;
            root.selected = next;
        }

        Rectangle {
            anchors.fill: parent
            color: Theme.shellScrim
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

        Rectangle {
            id: sheet

            width: Math.min(1180, win.width * 0.92)
            height: Math.min(760, win.height * 0.86)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? (win.height - height) / 2 : (win.height - height) / 2 - 10
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder
            radius: Theme.radius
            clip: true
            opacity: root.open ? 1 : 0
            // Drop shadow deliberately omitted — the same llvmpipe
            // deviation the command center and overview make.

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

            // ---- masthead ----
            Row {
                id: mastLeft

                anchors.left: parent.left
                anchors.leftMargin: 20
                anchors.top: parent.top
                anchors.topMargin: 16
                spacing: 0

                Meta {
                    text: "Punar"
                    color: Theme.shellFg
                }
                Meta {
                    text: " · Shortcuts"
                }
            }

            Meta {
                anchors.right: parent.right
                anchors.rightMargin: 20
                anchors.top: parent.top
                anchors.topMargin: 16
                font.weight: 500
                text: "Super + / · Esc closes"
            }

            Rectangle {
                id: mastRule

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                anchors.top: mastLeft.bottom
                anchors.topMargin: 10
                height: 2
                color: Theme.shellFg
            }

            // ---- filter row ----
            Item {
                id: queryRow

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                anchors.top: mastRule.bottom
                anchors.topMargin: 10
                height: 30

                Text {
                    id: prompt

                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    text: "/"
                    font.family: Theme.fontMono
                    font.pixelSize: 14
                    font.weight: 600
                    color: Theme.shellFg
                }

                TextInput {
                    id: queryInput

                    anchors.left: prompt.right
                    anchors.leftMargin: 10
                    anchors.right: hint.left
                    anchors.rightMargin: 12
                    anchors.verticalCenter: parent.verticalCenter
                    font.family: Theme.fontMono
                    font.pixelSize: 14
                    font.letterSpacing: Theme.tracking(14, 0.08)
                    color: Theme.shellFg
                    clip: true
                    onTextChanged: {
                        root.query = queryInput.text;
                        root.selected = 0;
                    }

                    // The filter owns the keyboard for as long as the
                    // surface is open, which is why `/` needs no separate
                    // focus step: two letters usually beat any amount of
                    // scrolling, so typing is the default posture. ↑↓
                    // walk the visible rows; Esc closes and returns focus
                    // to the window that had it.
                    Keys.onPressed: function (event) {
                        switch (event.key) {
                        case Qt.Key_Escape:
                            root.dismiss();
                            event.accepted = true;
                            break;
                        case Qt.Key_Down:
                            win.step(1);
                            event.accepted = true;
                            break;
                        case Qt.Key_Up:
                            win.step(-1);
                            event.accepted = true;
                            break;
                        default:
                            // ↵ is deliberately NOT handled: this surface
                            // teaches a chord, it never runs one.
                            break;
                        }
                    }

                    Text {
                        anchors.fill: parent
                        visible: queryInput.text === ""
                        text: "Type to filter"
                        font: queryInput.font
                        color: Theme.shellInputBorder
                    }
                }

                Meta {
                    id: hint

                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    font.weight: 500
                    text: "↑↓ select · Esc close"
                }

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: Theme.hairline
                    color: queryInput.activeFocus ? Theme.shellFg : Theme.shellInputBorder
                }
            }

            // ---- body ----
            Flickable {
                id: body

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: queryRow.bottom
                anchors.bottom: footRule.top
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                anchors.topMargin: 12
                anchors.bottomMargin: 10
                contentWidth: width
                contentHeight: columns.implicitHeight
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                Row {
                    id: columns

                    width: parent.width
                    spacing: 24

                    Repeater {
                        model: win.page.columns

                        delegate: Column {
                            id: columnItem

                            required property var modelData

                            width: (columns.width - columns.spacing * (win.columnCount - 1))
                                   / win.columnCount
                            spacing: 10

                            Repeater {
                                model: columnItem.modelData

                                delegate: Column {
                                    id: blockItem

                                    required property var modelData

                                    width: columnItem.width
                                    spacing: 0

                                    // A submap is a MODE (Sect III·04):
                                    // its keys render in a bounded block
                                    // with the mode named at its head and
                                    // no modifier cap on any key, because
                                    // those keys mean nothing outside it.
                                    // The block's border is what says
                                    // "only in here".
                                    Rectangle {
                                        width: parent.width
                                        height: blockBody.implicitHeight
                                            + (blockItem.modelData.kind === "mode" ? 16 : 0)
                                        color: "transparent"
                                        radius: Theme.radius
                                        border.width: blockItem.modelData.kind === "mode"
                                            ? Theme.hairline : 0
                                        border.color: Theme.shellInputBorder

                                        Column {
                                            id: blockBody

                                            anchors.left: parent.left
                                            anchors.right: parent.right
                                            anchors.top: parent.top
                                            anchors.margins: blockItem.modelData.kind === "mode" ? 8 : 0
                                            spacing: 4

                                            Meta {
                                                width: parent.width
                                                font.pixelSize: 10
                                                font.weight: 500
                                                font.letterSpacing: Theme.tracking(10, 0.14)
                                                color: blockItem.modelData.kind === "mode"
                                                    ? Theme.shellFg : Theme.shellInk3
                                                text: blockItem.modelData.title
                                            }

                                            Meta {
                                                width: parent.width
                                                visible: blockItem.modelData.subtitle !== ""
                                                font.pixelSize: 9
                                                font.weight: 500
                                                text: blockItem.modelData.subtitle
                                            }

                                            Rectangle {
                                                width: parent.width
                                                visible: blockItem.modelData.kind !== "mode"
                                                height: Theme.hairline
                                                color: Theme.shellBorder
                                            }

                                            Repeater {
                                                model: blockItem.modelData.rows

                                                delegate: BindRow {
                                                    required property var modelData

                                                    width: blockBody.width
                                                    chordMods: modelData.mods
                                                    keyText: modelData.keyText
                                                    label: modelData.label
                                                    isMode: modelData.isMode
                                                    repeats: modelData.repeat
                                                    selected: root.selected === modelData.flatIndex

                                                    onRevealRequested: win.reveal(
                                                        mapToItem(columns, 0, 0).y, height)
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // The calm empty state: a malformed, empty or unreachable
            // binding table renders a sentence, never an exception and
            // never an invented row.
            Column {
                anchors.centerIn: parent
                width: parent.width * 0.6
                spacing: 8
                visible: win.page.shown === 0

                Meta {
                    width: parent.width
                    color: Theme.shellFg
                    text: table.problem !== "" ? "No binding table" : "No match"
                }
                Text {
                    width: parent.width
                    wrapMode: Text.WordWrap
                    font.family: Theme.fontSans
                    font.pixelSize: 15
                    color: Theme.shellInk2
                    text: table.problem !== "" ? table.problem
                        : "Nothing in the binding table matches this."
                }
            }

            Rectangle {
                id: footRule

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                anchors.bottom: foot.top
                anchors.bottomMargin: 8
                height: Theme.hairline
                color: Theme.shellBorder
            }

            Item {
                id: foot

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                anchors.bottomMargin: 12
                height: 16

                // Every number here is computed from the same table the
                // rows are, so the footer and the surface cannot disagree
                // — and the fold is auditable at a glance because both
                // numbers are printed.
                Meta {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    font.weight: 500
                    // The undescribed and unmapped counts are the alarms,
                    // and they are drawn in ink rather than in red: a
                    // keyboard reference has no status to report, so this
                    // surface spends no status colour at all (Sect IV·06).
                    color: (table.undescribed > 0 || table.unmapped > 0) ? Theme.shellFg : Theme.shellInk3
                    text: root.query.trim() === ""
                        ? table.rawCount + " binds · " + table.rowCount + " rows · "
                          + table.undescribed + " undescribed · " + table.unmapped + " unmapped"
                        : win.page.shown + " of " + table.rowCount + " rows · query "
                          + "\"" + root.query.trim() + "\""
                }

                Meta {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    font.weight: 500
                    text: "Source · hyprctl binds -j · cached at session start"
                }
            }
        }
    }
}
