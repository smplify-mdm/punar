pragma ComponentBehavior: Bound
// AiPanel — the SUPER+A "AI on this device" surface (Milestone 7),
// implementing docs/design/mockups/ai-panel.html (Plate D-005, the
// acceptance reference) and spec §25: the agent registry (§19), the
// authority model (§20) and the ledger boundary (§21) on one
// keyboard-first paper sheet.
//
// Layout (D-005 .sc): masthead meta rows closed by the 2 px ink rule;
// body split into the left AGENT RAIL (one row per registry session and
// per detection — managed calm with the green presence dot, observed
// quiet, unknown in the red voice, the only red on the surface) and the
// right DETAIL pane (attribution masthead, AUTHORITY · WHAT IT MAY
// ACCESS with §20 decision words as tracked mono, LEDGER · WHAT IT
// ACCESSED as the dashed Milestone-8 placeholder); footer meta row.
//
// HONESTY (spec §1.22, §23):
//   - every authority row carries its `declared · M9/M12` enforcement
//     label exactly as the launcher recorded it — nothing here is
//     enforced in M7 and the surface says so on every row;
//   - the ledger section is a DASHED placeholder reading NOT YET
//     RECORDED · MILESTONE 8 — dashed means "not real yet", the same
//     grammar the overview uses for empty workspaces;
//   - detections are rendered as SUSPECTED, never certain, and the
//     Inspect / Block network / Register actions of the mockup are NOT
//     drawn: those capabilities arrive with M9/M10 and this release
//     ships no dead buttons.
//
// UNMANAGED-FIRST (DESIGN_LANGUAGE.md §8): the org name appears in the
// masthead only while `Status.enrolled`; a personal device cites
// PERSONAL DEFAULTS as the authority source and shows no org chrome.
//
// DATA (milestone-7.md §8.2, docs/api/ipc.md §11): the Agents singleton
// follows `/run/punar/agents.json` with an inotify FileView — no socket
// client in the shell, no polling, no timers. Opening the panel fires
// ONE detached `punarctl agents list --json` (fixed argv, never a shell
// string) so agentd's staleness-gated scan refreshes the file; the
// FileView delivers the rewrite. A missing or unparsable file renders
// the calm empty panel — fail closed, never an error surface.
//
// Toggled from Hyprland via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call aipanel toggle
// Hyprland bind: bind = SUPER, A, exec, qs -p /usr/share/punar/shell ipc call aipanel toggle

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

    // Session/detection id under the cursor. Kept across agents.json
    // rewrites so a rescan does not move the reader's selection.
    property string selectedId: ""

    // ---- shared type grammar (DESIGN_LANGUAGE.md §1) ----

    // Meta rows / labels: Geist Mono, tracked, uppercase. Mockup
    // fractional sizes round to whole px (8.5 → 9, 9.5 → 10).
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.ink3
    }

    // Section header + right-hand tagline (mockup .sect): the question
    // the section answers lives in the tagline — "what it may access"
    // vs "what it accessed" is §21's core distinction, made structural.
    component Sect: Item {
        id: sect

        property string title: ""
        property string tagline: ""

        height: 30

        Meta {
            anchors.left: parent.left
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 3
            font.letterSpacing: Theme.tracking(9, 0.16)
            text: sect.title
        }
        Meta {
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 4
            font.pixelSize: 8
            font.weight: 500
            font.letterSpacing: Theme.tracking(8, 0.1)
            color: Theme.inputBorder
            text: sect.tagline
        }
    }

    // One authority row (mockup .kv): human zone label + the raw policy
    // zone on the left, the §20 decision word wearing its status color
    // on the right, with the enforcement milestone label beneath it.
    // Reading down the right edge tells the whole story.
    component AuthorityRow: Item {
        id: arow

        property string label: ""
        property string zone: ""
        property string decision: ""
        property string enforcement: ""
        property bool topRule: false

        height: 40

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            visible: arow.topRule
            color: Theme.border
        }

        Column {
            anchors.left: parent.left
            anchors.right: valueColumn.left
            anchors.rightMargin: 16
            anchors.verticalCenter: parent.verticalCenter
            spacing: 2

            Text {
                width: parent.width
                text: arow.label
                font.family: Theme.fontSans
                font.pixelSize: 13
                font.weight: 500
                color: Theme.ink
                elide: Text.ElideRight
            }
            Meta {
                width: parent.width
                visible: arow.zone !== ""
                font.pixelSize: 8
                font.weight: 500
                font.letterSpacing: Theme.tracking(8, 0.1)
                color: Theme.inputBorder
                text: arow.zone
                elide: Text.ElideRight
            }
        }

        Column {
            id: valueColumn

            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: Math.min(230, arow.width * 0.46)
            spacing: 2

            Meta {
                width: parent.width
                font.pixelSize: 10
                font.letterSpacing: Theme.tracking(10, 0.11)
                horizontalAlignment: Text.AlignRight
                color: root.decisionColor(arow.decision)
                text: root.decisionWord(arow.decision)
            }
            // The enforcement label is not decoration: in M7 nothing
            // above is enforced, and no surface may render a decision
            // without saying which milestone will honour it.
            Meta {
                width: parent.width
                visible: arow.enforcement !== ""
                font.pixelSize: 8
                font.weight: 500
                font.letterSpacing: Theme.tracking(8, 0.1)
                horizontalAlignment: Text.AlignRight
                color: Theme.inputBorder
                text: arow.enforcement
                elide: Text.ElideRight
            }
        }
    }

    // A plain fact row (mockup .kv, single line): label left, observed
    // value right in mono. Used by the unknown-agent identity card.
    component FactRow: Item {
        id: frow

        property string label: ""
        property string value: ""
        property color valueColor: Theme.ink3
        property bool topRule: false
        // Case-sensitive data (a filesystem path) keeps its real case:
        // the meta grammar uppercases labels, never evidence.
        property bool verbatim: false

        height: 30

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            visible: frow.topRule
            color: Theme.border
        }

        Text {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, parent.width * 0.36)
            text: frow.label
            font.family: Theme.fontSans
            font.pixelSize: 13
            font.weight: 500
            color: Theme.ink
            elide: Text.ElideRight
        }
        Meta {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, parent.width * 0.62)
            font.pixelSize: 10
            font.letterSpacing: Theme.tracking(10, 0.11)
            font.capitalization: frow.verbatim ? Font.MixedCase : Font.AllUppercase
            horizontalAlignment: Text.AlignRight
            color: frow.valueColor
            text: frow.value
            elide: Text.ElideLeft // paths stay readable from the tail
        }
    }

    // Bordered mono pill (mockup .pill): classification badge.
    component Pill: Rectangle {
        id: pill

        property string text: ""
        property bool loud: false // red voice — unknown / suspected

        implicitWidth: pillText.implicitWidth + 18
        implicitHeight: 20
        radius: Theme.radiusTag
        color: pill.loud ? "transparent" : Theme.muted
        border.width: Theme.hairline
        border.color: pill.loud ? Theme.statusBad : Theme.border

        Meta {
            id: pillText
            anchors.centerIn: parent
            font.pixelSize: 9
            font.letterSpacing: Theme.tracking(9, 0.12)
            color: pill.loud ? Theme.statusBad : Theme.ink2
            text: pill.text
        }
    }

    // ---- display helpers (pure JS over the ipc.md §11 objects) ----

    function classWord(cls: string): string {
        switch (cls) {
        case "managed":
            return "Managed";
        case "observed":
            return "Observed";
        case "unknown":
            return "Unknown";
        default:
            return "Unclassified";
        }
    }

    // Rail presence dot (mockup: managed green, idle/ended the border
    // grey, unknown bad-red). Observed stays quiet ink — a known agent
    // outside the managed runtime is information, not an alarm.
    function toneColor(tone: string): color {
        switch (tone) {
        case "ok":
            return Theme.statusOk;
        case "bad":
            return Theme.statusBad;
        case "quiet":
            return Theme.ink3;
        default:
            return Theme.border;
        }
    }

    // §20 decision values (allow / deny / approval_required) plus the
    // filesystem and credential words the §20 example uses. An
    // unrecognised value is printed verbatim rather than guessed at.
    function decisionWord(decision: string): string {
        switch (decision) {
        case "":
            return "Not recorded";
        case "allow":
            return "Allowed";
        case "deny":
            return "Denied";
        case "approval_required":
        case "request":
            return "Approval required";
        case "read_write":
            return "Read / Write";
        case "read":
            return "Read";
        case "none":
            return "None issued";
        default:
            return decision.replace(/_/g, " ");
        }
    }

    function decisionColor(decision: string): color {
        switch (decision) {
        case "allow":
        case "read_write":
            return Theme.statusOk;
        case "deny":
            return Theme.statusBad;
        case "approval_required":
        case "request":
            return Theme.statusWarn;
        default:
            return Theme.ink3; // read / none / unrecorded / unknown: no color spent
        }
    }

    // Zone group prefix ("filesystem.project" → "filesystem"); drives
    // the hairline that separates the mockup's stacked .kv blocks.
    function zoneGroup(zone: string): string {
        var i = zone.indexOf(".");
        return i > 0 ? zone.substring(0, i) : zone;
    }

    // Human label for a policy zone leaf, with the acronyms the §20
    // example uses spelled the way a person writes them.
    readonly property var zoneWords: ({
        "ssh": "SSH keys",
        "aws": "AWS",
        "aws_dev": "AWS dev",
        "aws_prod": "AWS production",
        "github": "GitHub",
        "mcp": "MCP tools",
        "vpn": "VPN",
        "corp_dev": "Corp dev",
        "corp_prod": "Corp production"
    })

    function zoneLabel(zone: string): string {
        var i = zone.lastIndexOf(".");
        var leaf = i >= 0 ? zone.substring(i + 1) : zone;
        if (leaf === "")
            return zone;
        var known = root.zoneWords[leaf];
        if (known !== undefined)
            return String(known);
        var words = leaf.replace(/[_-]/g, " ");
        return words.charAt(0).toUpperCase() + words.substring(1);
    }

    // RFC 3339 → HH:MM, local. Unparsable timestamps print verbatim:
    // showing the raw string beats inventing a time.
    function shortTime(iso: string): string {
        if (iso === "")
            return "unknown";
        var d = new Date(iso);
        var t = d.getTime();
        if (t !== t) // NaN — not a timestamp we understand
            return iso;
        return Qt.formatDateTime(d, "HH:mm");
    }

    function str(obj: var, key: string): string {
        if (obj === null || obj === undefined || typeof obj !== "object")
            return "";
        var v = obj[key];
        return typeof v === "string" ? v : "";
    }

    // Authority citation for a session: what the launcher recorded,
    // else the file-level citation, else the honest default for this
    // device — PERSONAL DEFAULTS while unenrolled (DESIGN_LANGUAGE §8:
    // authority always names a source, and a personal device's source
    // is not an org policy).
    function policyCitation(sess: var): string {
        var a = (sess !== null && sess !== undefined && typeof sess === "object")
            ? sess.authority : null;
        var c = root.str(a, "policy_citation");
        if (c === "")
            c = Agents.policyCitation;
        if (c === "")
            c = Status.enrolled ? "unrecorded" : "personal-defaults";
        // An org policy id is an identifier and is cited verbatim
        // (POLICY · ENG-AI-V3). Only the personal sentinel is spelled
        // as the words DESIGN_LANGUAGE §8 uses: POLICY · PERSONAL
        // DEFAULTS — the unenrolled device's named authority source.
        return c === "personal-defaults" ? "personal defaults" : c;
    }

    // Flatten `authority.rows[]` into renderable rows. Objects are the
    // ipc.md §10.2 shape; a bare string is rendered as a label with no
    // decision rather than dropped (never silently hide policy data).
    function authorityRows(sess: var): var {
        var out = [];
        var a = (sess !== null && sess !== undefined && typeof sess === "object")
            ? sess.authority : null;
        if (a === null || a === undefined || typeof a !== "object")
            return out;
        var rows = a.rows;
        if (!Array.isArray(rows))
            return out;
        var prev = "";
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            if (r === null || r === undefined)
                continue;
            if (typeof r === "string") {
                out.push({
                    zone: "",
                    label: String(r),
                    decision: "",
                    enforcement: "",
                    topRule: out.length === 0
                });
                prev = "";
                continue;
            }
            if (typeof r !== "object")
                continue;
            var zone = root.str(r, "zone");
            var group = root.zoneGroup(zone);
            out.push({
                zone: zone,
                label: root.zoneLabel(zone),
                decision: root.str(r, "decision"),
                enforcement: root.str(r, "enforcement"),
                topRule: out.length === 0 || group !== prev
            });
            prev = group;
        }
        return out;
    }

    // Attribution chain (spec §22/§47), the D-005 detail masthead:
    // AGT_… · USER · ENVIRONMENT · STARTED HH:MM. Fields absent from
    // the summary file are simply not printed.
    function sessionSub(sess: var): string {
        var parts = [];
        var id = root.str(sess, "session_id");
        if (id !== "")
            parts.push(id);
        var user = root.str(sess, "user");
        if (user !== "")
            parts.push(user);
        var env = root.str(sess, "environment");
        if (env !== "")
            parts.push(env);
        var started = root.str(sess, "started_at");
        if (started !== "")
            parts.push("started " + root.shortTime(started));
        return parts.join(" · ");
    }

    function detectionSub(det: var): string {
        var seen = root.str(det, "observed_at");
        if (seen === "")
            seen = root.str(det, "started_at");
        var when = seen === "" ? "time unknown"
                               : "first observed " + root.shortTime(seen);
        return when + " · not launched through the managed runtime";
    }

    // ---- the rail model: registry sessions, then detections ----

    readonly property var rows: {
        var out = [];
        var ss = Array.isArray(Agents.sessions) ? Agents.sessions : [];
        for (var i = 0; i < ss.length; i++) {
            var s = ss[i];
            if (s === null || s === undefined || typeof s !== "object")
                continue;
            var cls = root.str(s, "classification");
            var ended = root.str(s, "status") === "ended";
            var project = root.str(s, "project");
            var id = root.str(s, "session_id");
            // D-005 register 01 — name, project, session id, classification.
            // Split across two meta lines: a real `agt_` id is twelve hex
            // digits and would elide away on one 216 px line, and a
            // truncated identifier is worse than a taller row.
            var sub = (project === "" ? "no project" : project)
                    + " · " + (id === "" ? "no session id" : id);
            var sub2 = root.classWord(cls) + " · " + (ended ? "Ended" : "Active");
            out.push({
                group: "Sessions",
                kind: "session",
                id: id,
                name: root.str(s, "agent") === "" ? "unnamed agent" : root.str(s, "agent"),
                sub: sub,
                sub2: sub2,
                tone: cls === "unknown" ? "bad"
                                        : (ended ? "idle" : (cls === "observed" ? "quiet" : "ok")),
                loud: cls === "unknown",
                data: s
            });
        }
        var ds = Array.isArray(Agents.detections) ? Agents.detections : [];
        for (var j = 0; j < ds.length; j++) {
            var d = ds[j];
            if (d === null || d === undefined || typeof d !== "object")
                continue;
            out.push({
                group: "Unknown",
                kind: "detection",
                id: root.str(d, "session_id"),
                name: root.str(d, "agent") === "" ? "unnamed process" : root.str(d, "agent"),
                sub: "Unknown · Suspected",
                sub2: "",
                tone: "bad",
                loud: true,
                data: d
            });
        }
        return out;
    }

    // Masthead counts. Personal reads "N sessions"; an enrolled device
    // reads "N managed" (the mockup's two modes) — additive chrome, not
    // a different surface. A known agent running OUTSIDE the managed
    // runtime is never folded into the managed count: when any observed
    // session exists the split is spelled out in both modes.
    function countsHead(): string {
        var managed = Agents.managedCount;
        var observed = Agents.observedCount;
        if (observed > 0)
            return managed + " managed · " + observed + " observed";
        if (Status.enrolled)
            return managed + " managed";
        return managed + (managed === 1 ? " session" : " sessions");
    }

    function show(): void {
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
        // Freshness on user action, not on a clock: re-read the file the
        // watch may have armed before agentd existed, and ask punarctl
        // for a list, whose staleness rule (ipc.md §10.2) triggers one
        // scan. Fixed argv — the shell never composes a shell string.
        Agents.refresh();
        try {
            Quickshell.execDetached(["punarctl", "agents", "list", "--json"]);
        } catch (e) {
            // No punarctl on a dev machine: the panel still renders
            // whatever agents.json holds (or the calm empty state).
            console.warn("punar-shell: agents refresh unavailable:", e);
        }
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

    // SUPER+A entry point. Hyprland bind:
    //   bind = SUPER, A, exec, qs -p /usr/share/punar/shell ipc call aipanel toggle
    IpcHandler {
        target: "aipanel"

        function toggle(): void {
            root.toggle();
        }
        function open(): void {
            root.show();
        }
        function close(): void {
            root.dismiss();
        }
        // Read-only, for the m7-check CI probe (the `overview` precedent).
        function state(): string {
            return root.open ? "open" : "closed";
        }
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: root.windowVisible = false
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
        WlrLayershell.namespace: "punar-aipanel"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive
                                               : WlrKeyboardFocus.None

        // The focused rail row, and the object it renders.
        readonly property var current: (rail.currentIndex >= 0
                                        && rail.currentIndex < root.rows.length)
            ? root.rows[rail.currentIndex] : null
        readonly property var entry: win.current !== null ? win.current.data : null
        readonly property bool isDetection: win.current !== null
                                            && win.current.kind === "detection"

        onVisibleChanged: {
            if (win.visible) {
                win.restoreSelection();
                rail.forceActiveFocus();
            }
        }

        // Keep the reader's place across an agents.json rewrite: re-find
        // the selected id, else fall back to the first row.
        function restoreSelection(): void {
            if (root.rows.length === 0) {
                rail.currentIndex = -1;
                return;
            }
            var idx = 0;
            for (var i = 0; i < root.rows.length; i++) {
                if (root.rows[i].id !== "" && root.rows[i].id === root.selectedId) {
                    idx = i;
                    break;
                }
            }
            rail.currentIndex = idx;
        }

        function moveSel(delta: int): void {
            if (root.rows.length === 0)
                return;
            var idx = (rail.currentIndex < 0 ? 0 : rail.currentIndex) + delta;
            rail.currentIndex = Math.max(0, Math.min(root.rows.length - 1, idx));
        }

        Connections {
            target: root
            function onRowsChanged(): void {
                win.restoreSelection();
            }
            // Re-arm keyboard focus on every open, not only when the
            // window is (re)created: closing drops the layer surface's
            // keyboard focus (WlrKeyboardFocus.None), and a reopen that
            // lands inside the 300 ms hide animation keeps the same
            // visible window — so `onVisibleChanged` never fires and the
            // rail would come back focus-less, swallowing Esc.
            function onOpenChanged(): void {
                if (root.open) {
                    win.restoreSelection();
                    rail.forceActiveFocus();
                }
            }
        }

        // Warm ink-wash scrim at 22% — 300 ms token curve, show/hide only.
        Rectangle {
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

        // ---- the AI panel sheet (Plate D-005 .sc) ----
        Rectangle {
            id: sheet

            width: Math.min(1040, win.width * 0.9)
            height: Math.min(660, win.height * 0.86)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? Math.round(win.height * 0.07)
                         : Math.round(win.height * 0.07) - 10
            color: Theme.paperSurface
            border.width: Theme.hairline
            border.color: Theme.border
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
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                height: 56

                Column {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 3

                    Row {
                        spacing: 0

                        Meta {
                            text: "Punar"
                            color: Theme.ink
                        }
                        Meta {
                            text: " · AI on this device"
                        }
                    }
                    // Unmanaged-first: the org name renders only while
                    // enrolled; a personal device reads PERSONAL and
                    // carries no org chrome at all.
                    Meta {
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.14)
                        text: Status.enrolled ? Status.orgName : "Personal"
                    }
                }

                // Right-hand data block. Laid out with explicit anchors
                // rather than a Column: right-anchored children inside a
                // width-from-children positioner is a binding loop.
                Item {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    width: Math.max(countRow.width, mastDate.implicitWidth)
                    height: countRow.height + 3 + mastDate.implicitHeight

                    Row {
                        id: countRow
                        anchors.right: parent.right
                        anchors.top: parent.top
                        spacing: 0

                        Meta {
                            color: Theme.ink
                            text: root.countsHead()
                        }
                        Meta {
                            text: " · "
                        }
                        // The only masthead color: unknown activity, and
                        // only when there is some (§2 — a screen with no
                        // status to report contains no color).
                        Meta {
                            color: Agents.unknownCount > 0 ? Theme.statusBad : Theme.ink3
                            text: Agents.unknownCount + " unknown"
                        }
                    }
                    Meta {
                        id: mastDate
                        anchors.right: parent.right
                        anchors.top: countRow.bottom
                        anchors.topMargin: 3
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
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                height: 2
                color: Theme.ink
            }

            // ---- body: agent rail | detail pane (mockup .scbody) ----

            ListView {
                id: rail

                anchors.left: parent.left
                anchors.top: mastRule.bottom
                anchors.bottom: footRule.top
                anchors.leftMargin: 20
                anchors.topMargin: 10
                anchors.bottomMargin: 8
                width: 216
                clip: true
                focus: true
                interactive: contentHeight > height
                keyNavigationWraps: false
                model: root.rows
                highlightMoveDuration: Theme.durMicro
                highlightMoveVelocity: -1
                highlightResizeDuration: 0
                currentIndex: -1

                onCurrentIndexChanged: {
                    if (rail.currentIndex >= 0 && rail.currentIndex < root.rows.length)
                        root.selectedId = root.rows[rail.currentIndex].id;
                }

                // Keyboard-first (spec §12): arrows walk the rail, Esc
                // closes. No mouse is required anywhere on this surface.
                Keys.onPressed: function (event) {
                    switch (event.key) {
                    case Qt.Key_Escape:
                        root.dismiss();
                        event.accepted = true;
                        break;
                    case Qt.Key_Down:
                    case Qt.Key_J:
                        win.moveSel(1);
                        event.accepted = true;
                        break;
                    case Qt.Key_Up:
                    case Qt.Key_K:
                        win.moveSel(-1);
                        event.accepted = true;
                        break;
                    case Qt.Key_Home:
                        win.moveSel(-root.rows.length);
                        event.accepted = true;
                        break;
                    case Qt.Key_End:
                        win.moveSel(root.rows.length);
                        event.accepted = true;
                        break;
                    }
                }

                // Rail section headers (mockup .rsec): SESSIONS, UNKNOWN.
                section.property: "group"
                section.delegate: Item {
                    id: railSection

                    required property string section

                    width: rail.width
                    height: 22

                    Meta {
                        anchors.left: parent.left
                        anchors.bottom: parent.bottom
                        anchors.bottomMargin: 5
                        font.pixelSize: 9
                        font.letterSpacing: Theme.tracking(9, 0.16)
                        color: railSection.section === "Unknown" ? Theme.statusBad : Theme.ink3
                        text: railSection.section
                    }
                }

                // Selection = raise fill + 2 px ink left rule (the
                // command-center grammar; no color spent on selection).
                highlight: Rectangle {
                    color: Theme.muted
                    radius: 0

                    Rectangle {
                        anchors.left: parent.left
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom
                        width: 2
                        color: Theme.ink
                    }
                }

                delegate: Item {
                    id: railRow

                    required property int index
                    required property var modelData

                    width: rail.width - 14
                    height: railRow.modelData.sub2 === "" ? 46 : 58

                    Column {
                        anchors.left: parent.left
                        anchors.leftMargin: 10
                        anchors.right: parent.right
                        anchors.rightMargin: 8
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 4

                        Row {
                            spacing: 8

                            // Presence dot: the classification's voice.
                            Rectangle {
                                anchors.verticalCenter: parent.verticalCenter
                                width: 6
                                height: 6
                                radius: 3
                                color: root.toneColor(railRow.modelData.tone)
                            }
                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                width: railRow.width - 44
                                text: railRow.modelData.name
                                font.family: Theme.fontSans
                                font.pixelSize: 14 // mockup 13.5px
                                font.weight: 500
                                color: railRow.modelData.loud ? Theme.statusBad : Theme.ink
                                elide: Text.ElideRight
                            }
                        }

                        Meta {
                            width: parent.width
                            font.pixelSize: 8
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(8, 0.11)
                            color: railRow.modelData.loud ? Theme.statusBad : Theme.ink3
                            text: railRow.modelData.sub
                            elide: Text.ElideRight
                        }
                        Meta {
                            width: parent.width
                            visible: railRow.modelData.sub2 !== ""
                            font.pixelSize: 8
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(8, 0.11)
                            color: railRow.modelData.loud ? Theme.statusBad : Theme.ink3
                            text: railRow.modelData.sub2
                            elide: Text.ElideRight
                        }
                    }

                    MouseArea {
                        anchors.fill: parent
                        onClicked: rail.currentIndex = railRow.index
                    }
                }
            }

            // Calm empty rail (fail-closed: agentd absent, nothing
            // registered, or an unparsable file all land here).
            Meta {
                anchors.left: parent.left
                anchors.top: mastRule.bottom
                anchors.leftMargin: 30
                anchors.topMargin: 16
                visible: root.rows.length === 0
                font.weight: 500
                text: "No agent sessions"
            }

            // The rule between rail and detail (mockup .rail border-right).
            Rectangle {
                id: railRule
                anchors.left: rail.right
                anchors.leftMargin: 14
                anchors.top: mastRule.bottom
                anchors.bottom: footRule.top
                width: Theme.hairline
                color: Theme.border
            }

            // ---- detail pane (mockup .pane) ----
            Flickable {
                id: pane

                anchors.left: railRule.right
                anchors.leftMargin: 22
                anchors.right: parent.right
                anchors.rightMargin: 20
                anchors.top: mastRule.bottom
                anchors.topMargin: 16
                anchors.bottom: footRule.top
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

                    // --- empty state: honest about what is and is not known ---
                    Item {
                        width: parent.width
                        height: 120
                        visible: win.current === null

                        Column {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            spacing: 10

                            Meta {
                                font.weight: 500
                                text: "No agent sessions"
                            }
                            Text {
                                width: parent.width
                                text: "Nothing has been registered on this device."
                                font.family: Theme.fontSans
                                font.pixelSize: 15
                                font.weight: 400
                                color: Theme.ink2
                                wrapMode: Text.WordWrap
                            }
                            Meta {
                                width: parent.width
                                font.pixelSize: 8
                                font.weight: 500
                                font.letterSpacing: Theme.tracking(8, 0.1)
                                color: Theme.inputBorder
                                text: "Managed sessions start with punar-env agent · unknown activity appears after a scan"
                                wrapMode: Text.WordWrap
                            }
                        }
                    }

                    // --- detail masthead (mockup .ptitle + .psub) ---
                    Item {
                        width: parent.width
                        height: 30
                        visible: win.current !== null

                        Text {
                            anchors.left: parent.left
                            anchors.right: titlePill.left
                            anchors.rightMargin: 12
                            anchors.verticalCenter: parent.verticalCenter
                            text: win.isDetection ? "Unknown AI activity"
                                                  : (win.current !== null ? win.current.name : "")
                            font.family: Theme.fontSans
                            font.pixelSize: 19
                            font.weight: 500
                            color: win.isDetection ? Theme.statusBad : Theme.ink
                            elide: Text.ElideRight
                        }

                        Pill {
                            id: titlePill
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            loud: win.isDetection
                            text: {
                                if (win.current === null)
                                    return "";
                                if (win.isDetection)
                                    return "Unmanaged · Suspected";
                                var word = root.classWord(root.str(win.entry, "classification"));
                                return root.str(win.entry, "status") === "ended"
                                    ? word + " · Ended" : word;
                            }
                        }
                    }

                    Meta {
                        width: parent.width
                        visible: win.current !== null
                        topPadding: 4
                        font.pixelSize: 9
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.13)
                        color: win.isDetection ? Theme.statusBad : Theme.ink3
                        text: win.current === null ? ""
                            : (win.isDetection ? root.detectionSub(win.entry)
                                               : root.sessionSub(win.entry))
                        wrapMode: Text.WordWrap
                    }

                    // ================= managed / observed session =================

                    // AUTHORITY — "what it may access" (spec §20).
                    Sect {
                        width: parent.width
                        visible: win.current !== null && !win.isDetection
                        title: "Authority"
                        tagline: "what it may access · policy · "
                                 + root.policyCitation(win.entry)
                    }

                    Repeater {
                        model: (win.current !== null && !win.isDetection)
                            ? root.authorityRows(win.entry) : []

                        AuthorityRow {
                            required property var modelData

                            width: paneColumn.width
                            label: modelData.label
                            zone: modelData.zone
                            decision: modelData.decision
                            enforcement: modelData.enforcement
                            topRule: modelData.topRule
                        }
                    }

                    // No authority block recorded: say so rather than
                    // implying an agent with no constraints.
                    Item {
                        width: parent.width
                        height: 34
                        visible: win.current !== null && !win.isDetection
                                 && root.authorityRows(win.entry).length === 0

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            height: Theme.hairline
                            color: Theme.border
                        }
                        Meta {
                            anchors.left: parent.left
                            anchors.verticalCenter: parent.verticalCenter
                            font.weight: 500
                            text: "No authority summary recorded for this session"
                        }
                    }

                    // LEDGER — "what it accessed" (spec §21). The May/Did
                    // split is structural: two ruled sections, each with
                    // its question in the header. M7 has no ledger, so the
                    // card is drawn DASHED and labelled — the honesty
                    // grammar (dashed = not real yet).
                    Sect {
                        width: parent.width
                        visible: win.current !== null && !win.isDetection
                        title: "Ledger"
                        tagline: "what it accessed · local only"
                    }

                    Item {
                        width: parent.width
                        height: 78
                        visible: win.current !== null && !win.isDetection

                        Canvas {
                            id: ledgerOutline
                            anchors.fill: parent
                            anchors.topMargin: 6
                            onPaint: {
                                var ctx = getContext("2d");
                                ctx.clearRect(0, 0, width, height);
                                ctx.strokeStyle = String(Theme.inputBorder);
                                ctx.lineWidth = 1;
                                ctx.setLineDash([4, 4]);
                                ctx.beginPath();
                                ctx.roundedRect(0.5, 0.5, width - 1, height - 1,
                                                Theme.radius, Theme.radius);
                                ctx.stroke();
                            }
                            onVisibleChanged: if (visible)
                                requestPaint()
                            onWidthChanged: requestPaint()
                            onHeightChanged: requestPaint()

                            Column {
                                anchors.centerIn: parent
                                width: parent.width - 32
                                spacing: 8

                                Meta {
                                    width: parent.width
                                    font.letterSpacing: Theme.tracking(9, 0.16)
                                    color: Theme.ink2
                                    text: "Not yet recorded · Milestone 8"
                                }
                                Meta {
                                    width: parent.width
                                    font.pixelSize: 8
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(8, 0.1)
                                    color: Theme.inputBorder
                                    text: "The access ledger stays on this device when it lands · nothing is recorded yet"
                                    wrapMode: Text.WordWrap
                                }
                            }
                        }
                    }

                    // ===================== unknown activity =====================

                    // IDENTITY — observed, best effort (spec §23).
                    Sect {
                        width: parent.width
                        visible: win.isDetection
                        title: "Identity"
                        tagline: "observed · best effort · spec 23"
                    }

                    FactRow {
                        width: parent.width
                        visible: win.isDetection
                        topRule: true
                        label: "Process"
                        value: win.current !== null ? win.current.name : ""
                    }
                    FactRow {
                        width: parent.width
                        visible: win.isDetection && root.str(win.entry, "executable") !== ""
                        label: "Executable"
                        value: root.str(win.entry, "executable")
                        verbatim: true
                    }
                    FactRow {
                        width: parent.width
                        visible: win.isDetection
                        label: "Classification"
                        value: "Unknown · Suspected AI"
                        valueColor: Theme.statusBad
                    }
                    FactRow {
                        width: parent.width
                        visible: win.isDetection && root.str(win.entry, "user") !== ""
                        label: "Launched by"
                        value: root.str(win.entry, "user")
                    }
                    FactRow {
                        width: parent.width
                        visible: win.isDetection && root.str(win.entry, "signature_id") !== ""
                        label: "Matched signature"
                        value: root.str(win.entry, "signature_id")
                    }
                    FactRow {
                        width: parent.width
                        visible: win.isDetection
                        label: "Session id"
                        value: root.str(win.entry, "session_id")
                    }

                    // The §23 honesty card (mockup .privacy): the panel
                    // states the limits of its own detection, and names
                    // what it deliberately does NOT do yet.
                    Item {
                        width: parent.width
                        height: honestyCard.implicitHeight + 18
                        visible: win.isDetection

                        Rectangle {
                            id: honestyCard
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            implicitHeight: honestyText.implicitHeight + 26
                            height: implicitHeight
                            radius: Theme.radius
                            color: Theme.muted
                            border.width: Theme.hairline
                            border.color: Theme.border

                            Column {
                                id: honestyText
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.verticalCenter: parent.verticalCenter
                                anchors.leftMargin: 15
                                anchors.rightMargin: 15
                                spacing: 7

                                Meta {
                                    width: parent.width
                                    font.pixelSize: 9
                                    font.weight: 600
                                    font.letterSpacing: Theme.tracking(9, 0.1)
                                    color: Theme.ink
                                    text: "Detection is heuristic — suspected, not certain"
                                    wrapMode: Text.WordWrap
                                }
                                Meta {
                                    width: parent.width
                                    font.pixelSize: 9
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(9, 0.1)
                                    text: "Visibility first · inspect, block network and register as managed arrive with enforcement (M9 / M10)"
                                    wrapMode: Text.WordWrap
                                }
                            }
                        }
                    }

                    // Trailing breathing room inside the flickable.
                    Item {
                        width: parent.width
                        height: 14
                    }
                }
            }

            // ---- footer meta row (mockup .scfoot) ----
            Rectangle {
                id: footRule
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: foot.top
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                height: Theme.hairline
                color: Theme.border
            }

            Item {
                id: foot

                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: 20
                anchors.rightMargin: 20
                height: 30

                Meta {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    font.pixelSize: 8
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(8, 0.14)
                    text: "↑↓ Agent · Esc Close"
                }
                Meta {
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    font.pixelSize: 8
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(8, 0.14)
                    text: "Last scan · " + (Agents.scannedAt === ""
                        ? "never" : root.shortTime(Agents.scannedAt))
                }
            }
        }

        // Month · year for the masthead, ticking only while the panel is
        // open — the clock is the one time source, never a data poll.
        SystemClock {
            id: clock
            enabled: root.open
            precision: SystemClock.Minutes
        }
    }
}
