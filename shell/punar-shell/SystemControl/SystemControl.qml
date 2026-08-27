pragma ComponentBehavior: Bound
// SystemControl — the SUPER+S full-surface settings panel, implementing
// docs/design/mockups/system-control.html (Plate D-004, the acceptance
// reference) and spec §63: one keyboard-first paper sheet for the whole
// machine, with the §63 taxonomy verbatim in the rail (System, Security,
// AI, Developer, Privacy, Organization), the §40 explain card as the
// managed-control anatomy, and the §1.22 honesty grammar for everything
// simulated or not yet drawn.
//
// THE PLATE'S CLAIM, KEPT: "A managed setting explains itself. It never
// grays out." A control punard owns renders LIVE with a MANAGED pill and
// an explain card naming the effective value, the winning source, whether
// the user may override, and its drift/compliance state — never a disabled
// switch. A control that cannot be changed *yet* renders read-only with
// the reason and its milestone. Nothing on this surface is a dead switch.
//
// THIS FILE IS THE SURFACE ONLY. What the panel knows — every file watch,
// every punarctl call, every honest "not yet" and the whole view model —
// lives in ControlData.qml next door, so the rendering and the claims can
// be reviewed apart from each other. This file spends colour, draws
// hairlines and owns the keyboard; it decides nothing.
//
// LAYOUT (D-004 .sc): masthead meta rows closed by the 2 px ink rule; body
// split into the left TAXONOMY RAIL (a `/` search field over five personal
// sections, plus Organization only while enrolled; selection as raise-fill
// plus a 2 px ink left rule, status dots only where there is status) and the
// right DETAIL pane (title with the live
// state toggle and ownership pill, tracked-mono subtitle, fact rows, list
// rows, the §40 explain card, the dashed honesty panel, a §73 paragraph
// and the keyed action row); footer meta row carrying the parity line.
//
// KEYBOARD (spec §12; no pointer is required anywhere):
//   ↑↓ / J K   walk the rail          Home End   ends of the rail
//   /          focus the search       Esc        clear search, else close
//   PgUp PgDn  scroll the detail pane
//   E S R P O  the actions the pane prints, each on its own tag — the
//              D-003 approval-card grammar ([A] APPROVE / [D] DENY)
// The focus state is a 2 px ink underline or the rail's ink left rule —
// no colour dependence (DESIGN_LANGUAGE §9.4).
//
// COST: no timer runs at rest. Three exist and all three are gated — the
// §48 grant countdown (open + a live grant + the Privilege view on
// screen), the 300 ms exit-animation one-shot, and the masthead's minute
// clock (`enabled: root.open`). Expect
// ~4-6 MB RSS added to the shell process (seven small FileViews, a rail of
// 22 rows, one detail pane); the shell is a user process and is not
// counted by the spec §6.2 daemon RSS gate, but it must not bloat, so the
// window's layer surface exists only while the panel is up.
//
// Toggled from Hyprland via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call systemcontrol toggle
// Hyprland bind: bindd = $mod, S, System control, exec, qs -p /usr/share/punar/shell ipc call systemcontrol toggle

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "." as Local
import "../Theme"
import "../Services"

Scope {
    id: root

    property bool open: false
    property bool openOnReady: false
    property bool windowVisible: false

    // Re-emitted from ControlData so the shell root may wire the AI
    // section straight to the SUPER+A panel (the AlertStack precedent).
    signal aiPanelRequested

    // Everything this surface knows. It holds no colour and draws
    // nothing; the data contract is the header of ControlData.qml.
    Local.ControlData {
        id: ctl

        onAiPanelRequested: root.aiPanelRequested()
    }

    // ---------------------------------------------------------------
    // Type grammar (DESIGN_LANGUAGE.md §1). Mockup fractional sizes
    // round to whole px — font.pixelSize is integral (8.5 → 9, 9.5 → 10).
    // ---------------------------------------------------------------

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.13)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    // Bordered mono pill (mockup .pill / .cpill). The dot appears only
    // when the caller supplied a tone — §2: no status, no colour.
    component Pill: Rectangle {
        id: pill

        property string label: ""
        property string dotTone: ""

        implicitWidth: pillRow.implicitWidth + 18
        implicitHeight: 21
        radius: Theme.radiusTag
        color: Theme.shellMuted
        border.width: Theme.hairline
        border.color: Theme.shellBorder

        Row {
            id: pillRow
            anchors.centerIn: parent
            spacing: 7

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                visible: pill.dotTone !== ""
                width: 6
                height: 6
                radius: 3
                color: root.toneColor(pill.dotTone)
            }
            Meta {
                anchors.verticalCenter: parent.verticalCenter
                font.pixelSize: 9
                font.letterSpacing: Theme.tracking(9, 0.12)
                color: Theme.shellInk2
                text: pill.label
            }
        }
    }

    // The §1.22 honesty tag: a dashed border means "outside the current
    // production claim" (DESIGN_LANGUAGE §7 stroke semantics).
    component SimTag: Item {
        id: simTag

        property string label: ""

        implicitWidth: simText.implicitWidth + 16
        implicitHeight: 18

        Canvas {
            anchors.fill: parent
            onPaint: {
                var ctx = getContext("2d");
                ctx.clearRect(0, 0, width, height);
                ctx.strokeStyle = String(Theme.shellInputBorder);
                ctx.lineWidth = 1;
                ctx.setLineDash([3, 3]);
                ctx.beginPath();
                ctx.roundedRect(0.5, 0.5, width - 1, height - 1, Theme.radiusTag, Theme.radiusTag);
                ctx.stroke();
            }
            onVisibleChanged: if (visible)
                requestPaint()
            onWidthChanged: requestPaint()
        }
        Meta {
            id: simText
            anchors.centerIn: parent
            font.pixelSize: 8
            font.letterSpacing: Theme.tracking(8, 0.1)
            color: Theme.shellInk3
            text: simTag.label
        }
    }

    // A dashed panel — the mockup's .undrawn, generalised so it carries
    // the whole what / why / when answer, because "silence is not
    // support" (DESIGN_LANGUAGE §7 explicit coverage).
    component DashedPanel: Item {
        id: dashed

        property string what: ""
        property string why: ""
        property string until: ""

        implicitHeight: dashedColumn.implicitHeight + 40

        Canvas {
            anchors.fill: parent
            onPaint: {
                var ctx = getContext("2d");
                ctx.clearRect(0, 0, width, height);
                ctx.strokeStyle = String(Theme.shellInputBorder);
                ctx.lineWidth = 1;
                ctx.setLineDash([5, 5]);
                ctx.beginPath();
                ctx.roundedRect(0.5, 0.5, width - 1, height - 1, Theme.radius, Theme.radius);
                ctx.stroke();
            }
            onVisibleChanged: if (visible)
                requestPaint()
            onWidthChanged: requestPaint()
            onHeightChanged: requestPaint()
        }

        Column {
            id: dashedColumn

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            anchors.leftMargin: 18
            anchors.rightMargin: 18
            spacing: 9

            Meta {
                width: parent.width
                font.pixelSize: 10
                font.letterSpacing: Theme.tracking(10, 0.16)
                color: Theme.shellInk3
                text: dashed.what
                wrapMode: Text.WordWrap
            }
            Text {
                width: parent.width
                visible: dashed.why !== ""
                text: dashed.why
                font.family: Theme.fontSans
                font.pixelSize: 13
                color: Theme.shellInk3
                wrapMode: Text.WordWrap
                lineHeight: 1.5
            }
            Meta {
                width: parent.width
                visible: dashed.until !== ""
                font.pixelSize: 9
                font.weight: 500
                font.letterSpacing: Theme.tracking(9, 0.14)
                color: Theme.shellInputBorder
                text: dashed.until
                wrapMode: Text.WordWrap
            }
        }
    }

    // One key/value fact (mockup .kv): tracked mono label, ink value.
    component KvRow: Item {
        id: kvRow

        property string k: ""
        property string v: ""
        property bool mono: true
        property color valueColor: Theme.shellFg

        implicitHeight: Math.max(kvKey.implicitHeight, kvValue.implicitHeight) + 20

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            color: Theme.shellBorder
        }
        Meta {
            id: kvKey
            anchors.left: parent.left
            anchors.top: parent.top
            anchors.topMargin: 12
            width: 150
            font.pixelSize: 10
            font.weight: 500
            color: Theme.shellInk3
            text: kvRow.k
            wrapMode: Text.WordWrap
        }
        Text {
            id: kvValue
            anchors.left: kvKey.right
            anchors.leftMargin: 16
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.topMargin: kvRow.mono ? 12 : 10
            text: kvRow.v
            color: kvRow.valueColor
            // Data is mono and tabular; prose values are sans (§1).
            font.family: kvRow.mono ? Theme.fontMono : Theme.fontSans
            font.pixelSize: kvRow.mono ? 11 : 14
            font.weight: 500
            wrapMode: Text.WordWrap
        }
    }

    // One list row (mockup .rowline): dot, name, right-hand meta.
    component RowLine: Item {
        id: rowLine

        property string name: ""
        property string meta: ""
        property string tone: "" // "" = no status, so no colour (§2)
        property string tag: ""

        implicitHeight: Math.max(30, rowName.implicitHeight + 18)

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            color: Theme.shellBorder
        }
        Rectangle {
            id: rowDot
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            visible: rowLine.tone !== ""
            width: 6
            height: 6
            radius: 3
            color: root.toneColor(rowLine.tone)
        }
        Text {
            id: rowName
            anchors.left: rowLine.tone === "" ? parent.left : rowDot.right
            anchors.leftMargin: rowLine.tone === "" ? 0 : 10
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, parent.width * 0.36)
            text: rowLine.name
            font.family: Theme.fontSans
            font.pixelSize: 14
            font.weight: 500
            color: rowLine.tone === "bad" ? Theme.shellStatusBad : Theme.shellFg
            elide: Text.ElideRight
        }
        SimTag {
            id: rowTag
            anchors.right: rowMeta.left
            anchors.rightMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            visible: rowLine.tag !== ""
            label: rowLine.tag
        }
        Meta {
            id: rowMeta
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, parent.width * 0.52 - (rowLine.tag === "" ? 0 : rowTag.width + 10))
            font.pixelSize: 9
            font.weight: 500
            font.letterSpacing: Theme.tracking(9, 0.1)
            horizontalAlignment: Text.AlignRight
            color: rowLine.tone === "bad" ? Theme.shellStatusBad : Theme.shellInk3
            text: rowLine.meta
            elide: Text.ElideLeft
        }
    }

    // One line of the §40 explain card: tracked mono label, middle dot,
    // the value in ink.
    component ExplainLine: Row {
        id: line

        property string k: ""
        property string v: ""
        property color vColor: Theme.shellFg

        spacing: 0
        height: 21

        Meta {
            anchors.verticalCenter: parent.verticalCenter
            font.pixelSize: 10
            font.weight: 500
            font.letterSpacing: Theme.tracking(10, 0.1)
            color: Theme.shellInk3
            text: line.k + " · "
        }
        Meta {
            anchors.verticalCenter: parent.verticalCenter
            font.pixelSize: 10
            font.letterSpacing: Theme.tracking(10, 0.1)
            color: line.vColor
            text: line.v
        }
    }

    // The §40 explain card (mockup .explain): the exact information set
    // `punarctl policy explain` prints, in the exact same order. Same
    // data, same order, both surfaces — that is the whole point.
    component ExplainCard: Rectangle {
        id: explain

        property string capability: ""
        property string effective: ""
        property string source: ""
        property string policyId: ""
        property string override: ""
        property string stateKey: ""
        property string compliance: ""
        property string complianceTone: ""

        implicitHeight: explainColumn.implicitHeight + 26
        radius: Theme.radius
        color: Theme.shellMuted
        border.width: Theme.hairline
        border.color: Theme.shellBorder

        Column {
            id: explainColumn

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.leftMargin: 15
            anchors.rightMargin: 15
            anchors.topMargin: 13
            spacing: 1

            ExplainLine {
                k: "Capability"
                v: explain.capability
            }
            ExplainLine {
                k: "Effective value"
                v: explain.effective
            }
            ExplainLine {
                k: "Source"
                v: explain.source + (explain.policyId === "" ? "" : " · " + explain.policyId)
            }
            ExplainLine {
                k: "User override"
                v: explain.override
            }
            ExplainLine {
                k: explain.stateKey
                v: explain.compliance
                vColor: explain.complianceTone === "" ? Theme.shellFg : root.toneColor(explain.complianceTone)
            }
        }
    }

    // The managed switch (mockup .toggle). It renders the LIVE state and
    // never greys out: ownership is stated by the pill beside it and the
    // card below it, not by taking the state away from the reader.
    component StateToggle: Rectangle {
        id: toggleBox

        property bool on: false

        width: 34
        height: 18
        radius: 9
        color: "transparent"
        border.width: Theme.hairline
        border.color: toggleBox.on ? Theme.shellFg : Theme.shellInputBorder

        Rectangle {
            width: 12
            height: 12
            radius: 6
            y: 2
            x: toggleBox.on ? toggleBox.width - width - 2 : 2
            color: toggleBox.on ? Theme.shellFg : Theme.shellInputBorder

            Behavior on x {
                NumberAnimation {
                    duration: Theme.durStandard
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }
        }
    }

    // An action, keyed like the D-003 approval card so the surface works
    // without a pointer; also clickable. `tone`: "ghost" neutral ink ·
    // "amber" the approval_required voice · "danger" destructive ghost.
    component ActionTag: Rectangle {
        id: actionTag

        property string label: ""
        property string hotkey: ""
        property string tone: "ghost"

        readonly property color inkColor: actionTag.tone === "amber" ? Theme.shellStatusWarn : (actionTag.tone === "danger" ? Theme.shellDestructive : Theme.shellFg)

        signal triggered

        implicitWidth: actionRow.implicitWidth + 22
        implicitHeight: 26
        radius: Theme.radiusTag
        color: "transparent"
        border.width: Theme.hairline
        border.color: actionTag.inkColor

        Row {
            id: actionRow
            anchors.centerIn: parent
            spacing: 8

            Meta {
                anchors.verticalCenter: parent.verticalCenter
                font.pixelSize: 9
                font.letterSpacing: Theme.tracking(9, 0.12)
                color: actionTag.inkColor
                text: "[" + actionTag.hotkey + "]"
            }
            Meta {
                anchors.verticalCenter: parent.verticalCenter
                font.pixelSize: 9
                font.letterSpacing: Theme.tracking(9, 0.1)
                color: actionTag.inkColor
                text: actionTag.label
            }
        }

        MouseArea {
            anchors.fill: parent
            onClicked: actionTag.triggered()
        }
    }

    // The only place a tone becomes colour (DESIGN_LANGUAGE §2 · §9.1).
    function toneColor(tone: string): color {
        switch (tone) {
        case "ok":
            return Theme.shellStatusOk;
        case "warn":
            return Theme.shellStatusWarn;
        case "bad":
            return Theme.shellStatusBad;
        default:
            return Theme.shellInk3;
        }
    }

    // ---------------------------------------------------------------
    // Lifecycle
    // ---------------------------------------------------------------

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("systemcontrol");
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
        // Freshness on user action, not on a clock.
        ctl.refreshAll();
    }

    Component.onCompleted: {
        SurfaceTiming.constructed("systemcontrol");
        if (root.openOnReady)
            root.show();
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        ctl.reasonForCapability = "";
        ctl.query = "";
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle(): void {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    // SUPER+S entry point. Hyprland bind:
    //   bindd = $mod, S, System control, exec, qs -p /usr/share/punar/shell ipc call systemcontrol toggle
    IpcHandler {
        target: "systemcontrol"

        function toggle(): void {
            root.toggle();
        }
        function open(): void {
            root.show();
        }
        function close(): void {
            root.dismiss();
        }
        // Read-only, for CI probes (the `overview` / `aipanel` precedent).
        function state(): string {
            return root.open ? "open" : "closed";
        }
        function latency(): string {
            return SurfaceTiming.sample("systemcontrol");
        }
        // Read-only semantic probes for the live in-VM unmanaged-first gate.
        // They expose the same view model this window renders; they do not
        // create a second label table or mutate selection.
        function rail(): string {
            return JSON.stringify(ctl.railItems);
        }
        function model(id: string): string {
            return JSON.stringify(ctl.buildView(id));
        }
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: root.windowVisible = false
    }

    // The one clock on this surface. It exists because a §48 grant has
    // something to count down, and it stops the moment the window closes,
    // the reader leaves the Privilege view, or the last grant expires — a
    // UI clock with a visible consumer, not the continuous polling spec
    // §6.3 prohibits.
    Timer {
        interval: 1000
        repeat: true
        running: root.open && root.windowVisible && ctl.hasLiveGrant && ctl.selectedId === "privilege"
        onTriggered: ctl.nowMs = Date.now()
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
        color: "transparent" // scrim + sheet own all visible pixels
        WlrLayershell.namespace: "punar-systemcontrol"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive : WlrKeyboardFocus.None

        function indexOfSelected(): int {
            for (var i = 0; i < ctl.railItems.length; i++) {
                if (ctl.railItems[i].id === ctl.selectedId)
                    return i;
            }
            return -1;
        }

        function syncRail(): void {
            var idx = win.indexOfSelected();
            if (idx < 0 && ctl.railItems.length > 0) {
                // The filter hid the selection: move to the first row
                // that survived, so the pane never renders a hidden item.
                ctl.select(ctl.railItems[0].id);
                idx = 0;
            }
            rail.currentIndex = idx;
        }

        function moveSel(delta: int): void {
            if (ctl.railItems.length === 0)
                return;
            var idx = (rail.currentIndex < 0 ? 0 : rail.currentIndex) + delta;
            idx = Math.max(0, Math.min(ctl.railItems.length - 1, idx));
            ctl.select(ctl.railItems[idx].id);
            rail.currentIndex = idx;
        }

        function focusRail(): void {
            win.syncRail();
            rail.forceActiveFocus();
        }

        onVisibleChanged: if (win.visible)
            win.focusRail()

        Connections {
            target: root
            // Re-arm keyboard focus on every open, not only on window
            // creation: a reopen inside the 300 ms hide animation keeps
            // the same visible window, so onVisibleChanged never fires
            // and the rail would come back focus-less, swallowing Esc.
            function onOpenChanged(): void {
                if (root.open)
                    win.focusRail();
            }
        }

        Connections {
            target: ctl
            function onRailItemsChanged(): void {
                win.syncRail();
            }
            function onSelectedIdChanged(): void {
                pane.contentY = 0;
            }
        }

        // Warm ink-wash scrim at 22% — 300 ms token curve, show/hide only.
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

        // ---- the System Control sheet (Plate D-004 .sc) ----
        Rectangle {
            id: sheet

            width: Math.min(1100, win.width * 0.92)
            height: Math.min(700, win.height * 0.9)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? Math.round(win.height * 0.05) : Math.round(win.height * 0.05) - 10
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder
            radius: Theme.radius
            clip: true
            opacity: root.open ? 1 : 0
            // Soft drop shadow deliberately omitted (llvmpipe budget; the
            // scrim + hairline carry separation — the M1/M2 deviation).

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

            // ---- masthead (mockup .sc .mast + .scrule) ----
            Item {
                id: masthead

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: 58

                Column {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 3

                    Row {
                        spacing: 0

                        Meta {
                            font.letterSpacing: Theme.tracking(9, 0.15)
                            color: Theme.shellFg
                            text: "Punar"
                        }
                        Meta {
                            font.letterSpacing: Theme.tracking(9, 0.15)
                            text: " · System Control"
                        }
                    }
                    // Device identity, with the org name appended only
                    // while enrolled — its absence is calm paper, never
                    // an "unenrolled" warning (§8).
                    Meta {
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.14)
                        text: {
                            var parts = [];
                            var host = ctl.str(ctl.statusData, "hostname", "");
                            var dev = ctl.str(ctl.statusData, "device_id", "");
                            if (host !== "")
                                parts.push(host);
                            if (dev !== "")
                                parts.push(dev);
                            if (Status.enrolled && Status.orgName !== "")
                                parts.push(Status.orgName);
                            return parts.length === 0 ? "This device" : parts.join(" · ");
                        }
                    }
                }

                // Right-hand data block. Explicit anchors rather than a
                // Column: right-anchored children inside a width-from-
                // children positioner is a binding loop.
                Item {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    width: Math.max(mastPill.width, mastDate.implicitWidth)
                    height: mastPill.height + 5 + mastDate.implicitHeight

                    // §8: the compliance pill is org chrome, so it is
                    // drawn only while enrolled.
                    Pill {
                        id: mastPill
                        anchors.right: parent.right
                        anchors.top: parent.top
                        visible: Status.enrolled
                        dotTone: Status.state
                        label: Status.label
                    }
                    Meta {
                        id: mastDate
                        anchors.right: parent.right
                        anchors.top: mastPill.bottom
                        anchors.topMargin: 5
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.14)
                        text: Qt.formatDateTime(clock.date, "MM · yyyy")
                    }
                }
            }

            // The 2 px ink rule that closes the masthead (mockup .scrule).
            Rectangle {
                id: mastRule
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: masthead.bottom
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: 2
                color: Theme.shellFg
            }

            // ---- rail (mockup .rail) ----
            Item {
                id: railBox

                anchors.left: parent.left
                anchors.top: mastRule.bottom
                anchors.bottom: footRule.top
                anchors.leftMargin: 22
                anchors.topMargin: 14
                anchors.bottomMargin: 8
                width: 212

                // `/` search — the greeter's underline-input grammar.
                Item {
                    id: searchBox

                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.rightMargin: 14
                    height: 26

                    TextInput {
                        id: searchInput

                        anchors.left: parent.left
                        anchors.right: slashKey.left
                        anchors.rightMargin: 8
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 6
                        font.family: Theme.fontMono
                        font.pixelSize: 11
                        font.letterSpacing: Theme.tracking(11, 0.08)
                        font.capitalization: Font.AllUppercase
                        color: Theme.shellFg
                        clip: true
                        onTextChanged: ctl.query = searchInput.text

                        Keys.onPressed: function (event) {
                            switch (event.key) {
                            case Qt.Key_Escape:
                                searchInput.text = "";
                                win.focusRail();
                                event.accepted = true;
                                break;
                            case Qt.Key_Down:
                                win.moveSel(1);
                                event.accepted = true;
                                break;
                            case Qt.Key_Up:
                                win.moveSel(-1);
                                event.accepted = true;
                                break;
                            case Qt.Key_Return:
                            case Qt.Key_Enter:
                                win.focusRail();
                                event.accepted = true;
                                break;
                            }
                        }
                    }

                    Text {
                        anchors.fill: searchInput
                        visible: searchInput.text === ""
                        text: "Search"
                        font.family: Theme.fontMono
                        font.pixelSize: 11
                        font.letterSpacing: Theme.tracking(11, 0.08)
                        font.capitalization: Font.AllUppercase
                        color: Theme.shellInputBorder
                    }

                    Rectangle {
                        id: slashKey
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 4
                        width: 16
                        height: 16
                        radius: 4
                        color: "transparent"
                        border.width: Theme.hairline
                        border.color: searchInput.activeFocus ? Theme.shellFg : Theme.shellBorder

                        Meta {
                            anchors.centerIn: parent
                            font.pixelSize: 9
                            color: searchInput.activeFocus ? Theme.shellFg : Theme.shellInk3
                            text: "/"
                        }
                    }

                    // Focus state: a 2 px ink underline, no colour
                    // dependence (DESIGN_LANGUAGE §9.4).
                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: searchInput.activeFocus ? 2 : Theme.hairline
                        color: searchInput.activeFocus ? Theme.shellFg : Theme.shellInputBorder
                    }
                }

                ListView {
                    id: rail

                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: searchBox.bottom
                    anchors.bottom: parent.bottom
                    anchors.topMargin: 10
                    clip: true
                    focus: true
                    interactive: contentHeight > height
                    keyNavigationWraps: false
                    model: ctl.railItems
                    highlightMoveDuration: Theme.durMicro
                    highlightMoveVelocity: -1
                    highlightResizeDuration: 0
                    currentIndex: -1

                    // Keyboard-first (spec §12): arrows walk the rail,
                    // `/` searches, Esc closes, and the letter keys the
                    // pane prints fire that view's actions.
                    Keys.onPressed: function (event) {
                        if (event.key === Qt.Key_Slash) {
                            searchInput.forceActiveFocus();
                            event.accepted = true;
                            return;
                        }
                        switch (event.key) {
                        case Qt.Key_Escape:
                            root.dismiss();
                            event.accepted = true;
                            return;
                        case Qt.Key_Down:
                        case Qt.Key_J:
                            win.moveSel(1);
                            event.accepted = true;
                            return;
                        case Qt.Key_Up:
                        case Qt.Key_K:
                            win.moveSel(-1);
                            event.accepted = true;
                            return;
                        case Qt.Key_Home:
                            win.moveSel(-ctl.railItems.length);
                            event.accepted = true;
                            return;
                        case Qt.Key_End:
                            win.moveSel(ctl.railItems.length);
                            event.accepted = true;
                            return;
                        case Qt.Key_PageDown:
                            pane.flick(0, -900);
                            event.accepted = true;
                            return;
                        case Qt.Key_PageUp:
                            pane.flick(0, 900);
                            event.accepted = true;
                            return;
                        }
                        if (event.text !== "") {
                            var a = ctl.actionByHotkey(String(event.text).toUpperCase());
                            if (a !== null) {
                                ctl.runAction(a);
                                event.accepted = true;
                            }
                        }
                    }

                    section.property: "section"
                    section.delegate: Item {
                        id: railSection

                        required property string section

                        width: rail.width
                        height: 24

                        Meta {
                            anchors.left: parent.left
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: 5
                            font.pixelSize: 9
                            font.letterSpacing: Theme.tracking(9, 0.16)
                            text: railSection.section
                        }
                    }

                    // Selection = raise fill + 2 px ink left rule (the
                    // command-center grammar; no colour spent on it).
                    highlight: Rectangle {
                        color: Theme.shellMuted
                        radius: 0

                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 2
                            color: Theme.shellFg
                        }
                    }

                    delegate: Item {
                        id: railRow

                        required property int index
                        required property var modelData

                        readonly property string tone: ctl.dotFor(railRow.modelData.id)

                        width: rail.width - 14
                        height: 28

                        Text {
                            anchors.left: parent.left
                            anchors.leftMargin: 10
                            anchors.right: railDot.left
                            anchors.rightMargin: 8
                            anchors.verticalCenter: parent.verticalCenter
                            text: railRow.modelData.name
                            font.family: Theme.fontSans
                            font.pixelSize: 14
                            font.weight: 500
                            color: rail.currentIndex === railRow.index ? Theme.shellFg : Theme.shellInk2
                            elide: Text.ElideRight
                        }
                        Rectangle {
                            id: railDot
                            anchors.right: parent.right
                            anchors.rightMargin: 8
                            anchors.verticalCenter: parent.verticalCenter
                            width: 5
                            height: 5
                            radius: 2.5
                            visible: railRow.tone !== ""
                            color: root.toneColor(railRow.tone)
                        }
                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                ctl.select(railRow.modelData.id);
                                rail.currentIndex = railRow.index;
                                rail.forceActiveFocus();
                            }
                        }
                    }
                }
            }

            // The rail's right-hand hairline (mockup .rail border-right).
            Rectangle {
                anchors.left: railBox.right
                anchors.top: mastRule.bottom
                anchors.bottom: footRule.top
                anchors.topMargin: 10
                anchors.bottomMargin: 8
                width: Theme.hairline
                color: Theme.shellBorder
            }

            // ---- detail pane (mockup .pane) ----
            Flickable {
                id: pane

                anchors.left: railBox.right
                anchors.right: parent.right
                anchors.top: mastRule.bottom
                anchors.bottom: footRule.top
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                anchors.topMargin: 16
                anchors.bottomMargin: 10
                clip: true
                contentWidth: width
                contentHeight: paneColumn.implicitHeight
                interactive: contentHeight > height
                boundsBehavior: Flickable.StopAtBounds

                Column {
                    id: paneColumn

                    width: pane.width
                    spacing: 0

                    // Title row: name, the live state toggle, ownership.
                    Item {
                        width: parent.width
                        height: 30

                        Text {
                            id: paneTitle
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            text: ctl.view.title
                            font.family: Theme.fontSans
                            font.pixelSize: 20
                            font.weight: 500
                            color: Theme.shellFg
                        }
                        SimTag {
                            anchors.left: paneTitle.right
                            anchors.leftMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            visible: ctl.view.simTag !== undefined
                            label: ctl.view.simTag === undefined ? "" : ctl.view.simTag
                        }
                        Row {
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 10

                            StateToggle {
                                anchors.verticalCenter: parent.verticalCenter
                                visible: ctl.view.toggle !== undefined
                                on: ctl.view.toggle !== undefined && ctl.view.toggle.on === true

                                // Pressing the switch runs whatever the
                                // action row below it prints — [S] on a
                                // control this session may write, [E] on
                                // one policy owns. Never a dead switch,
                                // and never a hidden second path either:
                                // it is the same call, and the pane names
                                // it in full underneath.
                                MouseArea {
                                    anchors.fill: parent
                                    enabled: ctl.toggleAction() !== null
                                    onClicked: ctl.runAction(ctl.toggleAction())
                                }
                            }
                            Pill {
                                anchors.verticalCenter: parent.verticalCenter
                                visible: ctl.view.pill !== undefined && ctl.view.pill !== null
                                label: (ctl.view.pill === undefined || ctl.view.pill === null) ? "" : String(ctl.view.pill.label)
                                dotTone: (ctl.view.pill === undefined || ctl.view.pill === null || ctl.view.pill.dotTone === undefined) ? "" : String(ctl.view.pill.dotTone)
                            }
                        }
                    }

                    Meta {
                        width: parent.width
                        topPadding: 2
                        bottomPadding: 14
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.13)
                        text: ctl.view.sub === undefined ? "" : ctl.view.sub
                        wrapMode: Text.WordWrap
                    }

                    // Facts.
                    Repeater {
                        model: ctl.view.kv === undefined ? [] : ctl.view.kv

                        KvRow {
                            required property var modelData

                            width: paneColumn.width
                            k: modelData.k
                            v: modelData.v
                            mono: modelData.mono === undefined ? true : modelData.mono
                            valueColor: (modelData.tone === undefined || modelData.tone === "") ? Theme.shellFg : root.toneColor(modelData.tone)
                        }
                    }

                    // Lists.
                    Repeater {
                        model: ctl.view.rows === undefined ? [] : ctl.view.rows

                        RowLine {
                            required property var modelData

                            width: paneColumn.width
                            name: modelData.name
                            meta: modelData.meta
                            tone: modelData.tone === undefined ? "" : modelData.tone
                            tag: modelData.tag === undefined ? "" : modelData.tag
                        }
                    }

                    // A list that is genuinely empty says so — blank space
                    // would read as "not loaded", which is a claim.
                    Item {
                        width: parent.width
                        visible: ctl.view.rows !== undefined && ctl.view.rows.length === 0 && ctl.view.emptyRows !== undefined
                        height: visible ? 44 : 0

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            height: Theme.hairline
                            color: Theme.shellBorder
                        }
                        Meta {
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            font.pixelSize: 9
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(9, 0.12)
                            text: ctl.view.emptyRows === undefined ? "" : ctl.view.emptyRows
                        }
                    }

                    // Closing hairline under a fact or list block.
                    Rectangle {
                        width: parent.width
                        height: (ctl.view.kv !== undefined || ctl.view.rows !== undefined) ? Theme.hairline : 0
                        color: Theme.shellBorder
                    }

                    // The §40 explain cards.
                    Repeater {
                        model: ctl.view.explains === undefined ? [] : ctl.view.explains

                        Item {
                            id: explainSlot

                            required property var modelData

                            width: paneColumn.width
                            implicitHeight: explainCard.implicitHeight + 16

                            ExplainCard {
                                id: explainCard
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.top: parent.top
                                anchors.topMargin: 16
                                capability: explainSlot.modelData.capability
                                effective: explainSlot.modelData.effective
                                source: explainSlot.modelData.source
                                policyId: explainSlot.modelData.policyId
                                override: explainSlot.modelData.override
                                stateKey: explainSlot.modelData.stateKey
                                compliance: explainSlot.modelData.compliance
                                complianceTone: explainSlot.modelData.tone
                            }
                        }
                    }

                    // The live §48 grant chip — the one place this surface
                    // spends the ok colour on a permission rather than on
                    // a compliance state.
                    Item {
                        width: parent.width
                        visible: ctl.view.grant !== undefined && ctl.view.grant !== null
                        height: visible ? 34 : 0

                        Meta {
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            font.pixelSize: 9
                            font.letterSpacing: Theme.tracking(9, 0.12)
                            color: Theme.shellStatusOk
                            text: {
                                var g = ctl.view.grant;
                                if (g === undefined || g === null)
                                    return "";
                                var mins = ctl.minutesLeft(ctl.str(g, "expires_at", ""));
                                return "Grant live · " + ctl.str(g, "grant_id", "") + (mins < 0 ? "" : " · " + mins + " min left");
                            }
                        }
                    }

                    // The dashed honesty panel.
                    Item {
                        width: parent.width
                        visible: ctl.view.dashed !== undefined
                        height: visible ? dashedPanel.implicitHeight + 18 : 0

                        DashedPanel {
                            id: dashedPanel
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.topMargin: 18
                            what: ctl.view.dashed === undefined ? "" : ctl.view.dashed.what
                            why: ctl.view.dashed === undefined ? "" : ctl.view.dashed.why
                            until: ctl.view.dashed === undefined ? "" : ctl.view.dashed.when_
                        }
                    }

                    // The plain-sentence paragraph (§73 voice).
                    Text {
                        width: parent.width
                        visible: ctl.view.note !== undefined
                        topPadding: 16
                        text: ctl.view.note === undefined ? "" : ctl.view.note
                        font.family: Theme.fontSans
                        font.pixelSize: 13
                        color: Theme.shellInk3
                        wrapMode: Text.WordWrap
                        lineHeight: 1.5
                    }

                    // Action row.
                    Item {
                        width: parent.width
                        visible: ctl.view.actions !== undefined && ctl.view.actions.length > 0
                        height: visible ? 52 : 0

                        Row {
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 10

                            Repeater {
                                model: ctl.view.actions === undefined ? [] : ctl.view.actions

                                ActionTag {
                                    required property var modelData

                                    hotkey: modelData.hotkey
                                    label: modelData.label
                                    tone: modelData.tone
                                    onTriggered: ctl.runAction(modelData)
                                }
                            }
                        }
                    }

                    // The §48 reason field. It appears only after [E], and
                    // it is required — a grant with no reason is not a
                    // thing this device issues.
                    Item {
                        id: reasonBox

                        width: parent.width
                        visible: ctl.reasonForCapability !== ""
                        height: visible ? 68 : 0

                        onVisibleChanged: if (reasonBox.visible)
                            reasonInput.forceActiveFocus()

                        Meta {
                            id: reasonLabel
                            anchors.left: parent.left
                            anchors.top: parent.top
                            font.pixelSize: 9
                            font.letterSpacing: Theme.tracking(9, 0.12)
                            color: Theme.shellStatusWarn
                            text: "Why do you need " + ctl.reasonForCapability + "? · ↵ sends · Esc cancels"
                        }
                        TextInput {
                            id: reasonInput
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: reasonLabel.bottom
                            anchors.topMargin: 12
                            font.family: Theme.fontSans
                            font.pixelSize: 15
                            color: Theme.shellFg
                            clip: true

                            Keys.onPressed: function (event) {
                                switch (event.key) {
                                case Qt.Key_Escape:
                                    reasonInput.text = "";
                                    ctl.reasonForCapability = "";
                                    win.focusRail();
                                    event.accepted = true;
                                    break;
                                case Qt.Key_Return:
                                case Qt.Key_Enter:
                                    ctl.submitReason(reasonInput.text);
                                    reasonInput.text = "";
                                    win.focusRail();
                                    event.accepted = true;
                                    break;
                                }
                            }
                        }
                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: reasonInput.bottom
                            anchors.topMargin: 6
                            height: reasonInput.activeFocus ? 2 : Theme.hairline
                            color: reasonInput.activeFocus ? Theme.shellFg : Theme.shellInputBorder
                        }
                    }

                    // What punarctl was asked, and what it answered —
                    // verbatim. spec §10: one capability layer, one voice.
                    Item {
                        width: parent.width
                        visible: ctl.lastActionArgv !== ""
                        height: visible ? actionEcho.implicitHeight + 34 : 0

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.topMargin: 18
                            height: Theme.hairline
                            color: Theme.shellBorder
                        }
                        Column {
                            id: actionEcho
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.topMargin: 30
                            spacing: 6

                            // The argv keeps its real case: the meta
                            // grammar uppercases labels, never evidence.
                            Meta {
                                width: parent.width
                                font.pixelSize: 9
                                font.weight: 500
                                font.letterSpacing: Theme.tracking(9, 0.1)
                                font.capitalization: Font.MixedCase
                                text: "$ " + ctl.lastActionArgv
                                wrapMode: Text.WrapAnywhere
                            }
                            Meta {
                                width: parent.width
                                font.pixelSize: 9
                                font.letterSpacing: Theme.tracking(9, 0.12)
                                color: ctl.lastActionPending ? Theme.shellInk3 : (ctl.lastActionExit === 0 ? Theme.shellStatusOk : Theme.shellStatusBad)
                                text: ctl.lastActionPending ? "Sent · waiting for the daemon" : (ctl.lastActionExit === 0 ? "Accepted · exit 0" : "Exit " + ctl.lastActionExit)
                            }
                            Text {
                                width: parent.width
                                visible: ctl.lastActionError !== ""
                                text: ctl.lastActionError
                                font.family: Theme.fontSans
                                font.pixelSize: 13
                                color: Theme.shellInk2
                                wrapMode: Text.WordWrap
                                lineHeight: 1.45
                            }
                        }
                    }

                    Item {
                        width: parent.width
                        height: 20
                    }
                }
            }

            // ---- footer (mockup .scfoot) ----
            Rectangle {
                id: footRule
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: footer.top
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: Theme.hairline
                color: Theme.shellBorder
            }

            Item {
                id: footer

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: 22
                anchors.rightMargin: 22
                height: 32

                Meta {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.14)
                    text: "↑↓ Navigate · / Search · Esc Close"
                }
                Meta {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    font.pixelSize: 9
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(9, 0.14)
                    text: ctl.daemonAnswered ? "Same capabilities as punarctl" : "Awaiting punard · nothing measured is shown"
                }
            }
        }

        // The masthead's month · year. `enabled` is bound to the panel
        // being open (the AiPanel precedent), because a closed sheet has
        // no masthead to keep current and spec §6.3 counts every wakeup:
        // ungated, this clock woke the shell once a minute for the whole
        // session to re-render a string nobody was looking at.
        SystemClock {
            id: clock
            enabled: root.open
            precision: SystemClock.Minutes
        }
    }
}
