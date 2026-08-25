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
// ACCESS with §20 decision words as tracked mono, then — since
// Milestone 8 — LEDGER · WHAT IT ACCESSED, the real §21 register);
// footer meta row.
//
// HONESTY (spec §1.22, §23):
//   - every authority row carries its `declared · M9/M12` enforcement
//     label exactly as the launcher recorded it — nothing here is
//     enforced in M7 and the surface says so on every row;
//   - the ledger renders only what an owned mediation point actually
//     observed. A category with no producer yet keeps the DASHED
//     honesty grammar M7 established — NOT YET OBSERVED · MILESTONE 12
//     for network destinations, MILESTONE 9+ for MCP servers,
//     MILESTONE 9 for credential classes — so the M8/M12 boundary stays
//     visible exactly where the placeholder used to draw it. An empty
//     row is never allowed to read as "accessed nothing";
//   - process counts are distinct pids seen ALIVE AT A SAMPLING POINT,
//     never a spawn total, and the section tagline says so;
//   - detections are rendered as SUSPECTED, never certain, and the
//     Block network / Register actions of the mockup are NOT drawn:
//     those capabilities arrive with M12 (punar-netd plus a policy verb)
//     and this release ships no dead buttons. `Inspect` is no longer in
//     that list — since M10 it is the alert card's [I] key, which opens
//     THIS panel on the detection it names (milestone-10.md §5.1); this
//     surface is the inspect target, so it still draws no such button of
//     its own.
//
// UNMANAGED-FIRST (DESIGN_LANGUAGE.md §8): the org name appears in the
// masthead only while `Status.enrolled`; a personal device cites
// PERSONAL DEFAULTS as the authority source and shows no org chrome.
//
// DATA (milestone-7.md §8.2, milestone-8.md §8.2, docs/api/ipc.md §11
// and §13.2): the Agents singleton follows `/run/punar/agents.json` and
// the Ledger singleton follows `/run/punar-agentd/ledger.json`, both
// with an inotify FileView — no socket client in the shell, no polling,
// no timers. Opening the panel fires ONE detached
// `punarctl agents list --json`, and one `punarctl agents access <id>
// --json` for a session whose ledger is not on hand yet (fixed argv,
// never a shell string) — the daemon drains and samples on that read
// and rewrites both files; the FileViews deliver the rewrite. A missing
// or unparsable file renders the calm empty panel — fail closed, never
// an error surface.
//
// SUPER+A shows the data; SHIFT+DEL deletes it (spec §24.2 + §1.17:
// deleting your own data cannot be terminal-only). The keystroke runs
// `punarctl privacy purge --session <id> --yes` through the same
// detached fixed-argv path, behind a two-step inline confirm.
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

    // SHIFT+DEL is two-step: the first press ARMS the focused session and
    // the privacy card asks for confirmation in the ghost-red destructive
    // voice; the second press runs the purge. Disarmed by any other key,
    // by moving the selection, and by closing the panel — a destructive
    // action never stays armed behind the reader's back.
    property string purgeArmedId: ""
    // The session whose purge has been handed to punarctl but whose
    // ledger.json rewrite has not arrived yet. Cleared when the record
    // comes back purged (or disappears).
    property string purgeRequestedId: ""

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

    // A dashed hairline. M7 drew the whole ledger card this way to mean
    // "not real yet"; M8 keeps that vocabulary and narrows it to the rows
    // that are genuinely unobserved, so the reader who learned the
    // grammar on the placeholder reads the boundary the same way.
    component DashedRule: Canvas {
        height: 2

        onPaint: {
            var ctx = getContext("2d");
            ctx.clearRect(0, 0, width, height);
            ctx.strokeStyle = String(Theme.inputBorder);
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.moveTo(0, 0.5);
            ctx.lineTo(width, 0.5);
            ctx.stroke();
        }
        onVisibleChanged: if (visible)
            requestPaint()
        onWidthChanged: requestPaint()
    }

    // One ledger row (mockup .kv): the category on the left, what was
    // actually observed on the right in the CALM muted value voice —
    // D-005 renders ledger values muted, never green. The ledger reports;
    // it does not approve. A `dashed` row is one nothing observes yet: it
    // wears the dashed rule and the border ink, and its note names the
    // milestone that will produce it.
    component LedgerRow: Item {
        id: lrow

        property string label: ""
        property string value: ""
        property string note: ""
        property bool dashed: false

        height: lrow.note === "" ? 32 : 42

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            visible: !lrow.dashed
            color: Theme.border
        }
        DashedRule {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            visible: lrow.dashed
        }

        Text {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, parent.width * 0.34)
            text: lrow.label
            font.family: Theme.fontSans
            font.pixelSize: 13
            font.weight: 500
            color: lrow.dashed ? Theme.ink3 : Theme.ink
            elide: Text.ElideRight
        }

        Column {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, parent.width * 0.64)
            spacing: 2

            Meta {
                width: parent.width
                font.pixelSize: 10
                font.letterSpacing: Theme.tracking(10, 0.11)
                horizontalAlignment: Text.AlignRight
                color: lrow.dashed ? Theme.inputBorder : Theme.ink2
                text: lrow.value
                elide: Text.ElideRight
            }
            Meta {
                width: parent.width
                visible: lrow.note !== ""
                font.pixelSize: 8
                font.weight: 500
                font.letterSpacing: Theme.tracking(8, 0.1)
                horizontalAlignment: Text.AlignRight
                color: Theme.inputBorder
                text: lrow.note
                elide: Text.ElideRight
            }
        }
    }

    // One Level-4 security event (mockup .evrow) — the only red on this
    // pane. The row carries the category, the time and the `evt_` id; the
    // payload stays in the audit log, which is the single source of truth
    // (spec §53) and the one place to redact.
    component EventRow: Item {
        id: erow

        property string category: ""
        property string detail: ""

        height: 28

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            height: Theme.hairline
            color: Theme.border
        }

        Rectangle {
            id: eventDot

            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            width: 6
            height: 6
            radius: 3
            color: Theme.statusBad
        }
        Meta {
            anchors.left: eventDot.right
            anchors.leftMargin: 10
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            font.pixelSize: 9
            font.weight: 500
            font.letterSpacing: Theme.tracking(9, 0.1)
            color: Theme.statusBad
            text: erow.category + " · " + erow.detail
            elide: Text.ElideRight
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

    // ---- ledger helpers (pure JS over the ipc.md §12.2 / §13.2 objects) ----

    // The six resource categories, in Plate D-005's reading order, with
    // the label every surface prints. The list is CLOSED: it is exactly
    // the six keys of `schemas/ai-agent/ledger-summary.json`, so a
    // seventh category cannot appear here by accident, and none of the
    // six can go missing without being noticed.
    readonly property var ledgerCategories: [
        {
            "key": "repositories",
            "label": "Repositories"
        },
        {
            "key": "directory_zones",
            "label": "Directory zones"
        },
        {
            "key": "process_classes",
            "label": "Processes"
        },
        {
            "key": "network_destinations",
            "label": "Network destinations"
        },
        {
            "key": "mcp_servers",
            "label": "MCP servers"
        },
        {
            "key": "credential_classes",
            "label": "Credential classes"
        }
    ]

    // `M12` → `Milestone 12`. An unrecognised token prints verbatim: the
    // panel never invents a milestone it was not told about.
    function milestoneWords(milestone: string): string {
        if (milestone === "")
            return "Not scheduled yet";
        if (/^M[0-9]/.test(milestone))
            return "Milestone " + milestone.substring(1);
        return milestone;
    }

    // The seven §21.2 Level-4 categories, spelled for a person.
    function eventWords(eventType: string): string {
        switch (eventType) {
        case "denied_access":
            return "Denied access";
        case "privilege_request":
            return "Privilege request";
        case "credential_request":
            return "Credential request";
        case "policy_bypass_attempt":
            return "Policy bypass attempt";
        case "production_access":
            return "Production access";
        case "sensitive_resource_access":
            return "Sensitive resource access";
        case "unknown_ai_execution":
            return "Unknown AI execution";
        case "":
            return "Security event";
        default:
            return eventType.replace(/_/g, " ");
        }
    }

    // The `summary` document inside a ledger view, tolerating a daemon
    // that hands the bare document instead of the full result object.
    function ledgerSummary(view: var): var {
        if (view === null || view === undefined || typeof view !== "object")
            return null;
        var s = view.summary;
        if (s !== null && s !== undefined && typeof s === "object")
            return s;
        return (view.resources !== undefined) ? view : null;
    }

    // The count recorded for one (category, class) pair, or -1 when the
    // daemon sent no aggregate. -1 renders as a bare class name: a count
    // is never guessed at.
    function ledgerCount(view: var, category: string, resourceClass: string): int {
        if (view === null || typeof view !== "object")
            return -1;
        var detail = view.detail;
        if (detail === null || detail === undefined || typeof detail !== "object")
            return -1;
        var entries = detail.entries;
        if (!Array.isArray(entries))
            return -1;
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            if (e !== null && typeof e === "object" && e.category === category
                    && e.resource_class === resourceClass
                    && typeof e.count === "number")
                return e.count;
        }
        return -1;
    }

    // The `not_yet_observed` row for a Level-3 category, or null.
    function ledgerPending(view: var, category: string): var {
        if (view === null || typeof view !== "object")
            return null;
        var rows = view.not_yet_observed;
        if (!Array.isArray(rows))
            return null;
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            if (r !== null && typeof r === "object" && r.category === category && r.level !== 4)
                return r;
        }
        return null;
    }

    // The six rows the LEDGER section renders. Every category appears —
    // observed with its classes and counts, unobserved with its milestone
    // in the dashed voice, or "None recorded" when a producer exists and
    // simply saw nothing. The three states are never allowed to look
    // alike (spec §1.22).
    function ledgerRows(view: var): var {
        var out = [];
        var summary = root.ledgerSummary(view);
        if (summary === null)
            return out;
        var resources = summary.resources;
        if (resources === null || resources === undefined || typeof resources !== "object")
            resources = ({});
        var peak = (view !== null && typeof view === "object"
                    && view.detail !== null && view.detail !== undefined
                    && typeof view.detail === "object"
                    && typeof view.detail.process_peak === "number")
            ? view.detail.process_peak : -1;

        for (var i = 0; i < root.ledgerCategories.length; i++) {
            var cat = root.ledgerCategories[i];
            var values = Array.isArray(resources[cat.key]) ? resources[cat.key] : [];
            if (values.length > 0) {
                var cells = [];
                for (var j = 0; j < values.length; j++) {
                    var name = String(values[j]);
                    var n = root.ledgerCount(view, cat.key, name);
                    // Process classes always carry the count (the D-005
                    // signature `git × 12 · cargo × 4`); elsewhere a `× 1`
                    // would be noise.
                    cells.push((n > 1 || (n >= 0 && cat.key === "process_classes"))
                        ? name + " × " + n : name);
                }
                var note = "";
                if (cat.key === "process_classes" && peak >= 0)
                    note = "peak " + peak + " concurrent";
                out.push({
                    "label": cat.label,
                    "value": cells.join(" · "),
                    "note": note,
                    "dashed": false
                });
                continue;
            }
            var pending = root.ledgerPending(view, cat.key);
            if (pending !== null) {
                out.push({
                    "label": cat.label,
                    "value": "Not yet observed",
                    "note": root.milestoneWords(root.str(pending, "milestone")),
                    "dashed": true
                });
            } else {
                out.push({
                    "label": cat.label,
                    "value": "None recorded",
                    "note": "",
                    "dashed": false
                });
            }
        }
        return out;
    }

    function ledgerEvents(view: var): var {
        var out = [];
        var summary = root.ledgerSummary(view);
        if (summary === null)
            return out;
        var events = summary.security_events;
        if (!Array.isArray(events))
            return out;
        for (var i = 0; i < events.length; i++) {
            var e = events[i];
            if (e === null || e === undefined || typeof e !== "object")
                continue;
            var parts = [];
            var when = root.str(e, "timestamp");
            if (when !== "")
                parts.push(root.shortTime(when));
            var id = root.str(e, "event_id");
            if (id !== "")
                parts.push(id);
            out.push({
                "category": root.eventWords(root.str(e, "event_type")),
                "detail": parts.join(" · ")
            });
        }
        return out;
    }

    // The Level-4 categories nothing produces yet, named with their
    // milestones — the footnote under an empty security-events register,
    // so "None recorded" can never be mistaken for "nothing could happen".
    function ledgerPendingEvents(view: var): string {
        if (view === null || typeof view !== "object")
            return "";
        var rows = view.not_yet_observed;
        if (!Array.isArray(rows))
            return "";
        var out = [];
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            if (r === null || typeof r !== "object" || r.level !== 4)
                continue;
            var m = root.str(r, "milestone");
            out.push(root.eventWords(root.str(r, "category")) + (m === "" ? "" : " · " + m));
        }
        return out.length === 0 ? "" : "Not yet observed · " + out.join(" · ");
    }

    // The retention sentence: an active session states the window, an
    // ended one states the date its ledger disappears on.
    function ledgerRetention(view: var): string {
        if (view === null || typeof view !== "object")
            return "";
        var r = view.retention;
        if (r === null || r === undefined || typeof r !== "object")
            return "";
        var days = typeof r.days === "number" ? r.days : -1;
        var expires = root.str(r, "expires_at");
        if (expires !== "") {
            var d = new Date(expires);
            var t = d.getTime();
            var when = (t === t) ? Qt.formatDateTime(d, "d MMM yyyy") : expires;
            return "Kept until " + when;
        }
        if (days >= 0)
            return "Kept " + days + " days after the session ends";
        return "Retention not reported";
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
        Ledger.refresh();
        try {
            Quickshell.execDetached(["punarctl", "agents", "list", "--json"]);
        } catch (e) {
            // No punarctl on a dev machine: the panel still renders
            // whatever agents.json holds (or the calm empty state).
            console.warn("punar-shell: agents refresh unavailable:", e);
        }
        root.refreshLedger(root.selectedId);
    }

    // The M10 alert card's [I] Inspect action (milestone-10.md §5.1):
    // open this surface with the rail already sitting on the detection the
    // card is about. `detection_id` (§4.1) is the same `agt_`-shaped
    // identity the rail keys its detection rows by, so the panel opens ON
    // the row and not merely near it.
    //
    // `restoreSelection()` is called explicitly because `show()` only
    // re-runs it through `onOpenChanged` / `onVisibleChanged` — neither
    // fires when the panel is ALREADY open, which is exactly the case
    // where a second alert must move the reader to a different detection.
    // A detection that has since cleared out of `agents.json` falls back
    // to the first row rather than to an empty pane: the rail is the
    // record, and an id it no longer holds is not invented here.
    function showDetection(detectionId: string): void {
        if (detectionId !== "")
            root.selectedId = detectionId;
        root.show();
        win.restoreSelection();
        rail.forceActiveFocus();
    }

    // Ask agentd for one session's ledger, once, on user action — the
    // read itself is what makes agentd drain the audit tail and sample the
    // scope cgroup (milestone-8.md §5.1), and the rewrite reaches the
    // shell through the Ledger FileView. Skipped when the record is
    // already on hand, so walking the rail with the arrow keys does not
    // spawn a process per row. Fixed argv, never a shell string.
    function refreshLedger(sessionId: string): void {
        if (sessionId === "" || Ledger.has(sessionId))
            return;
        try {
            Quickshell.execDetached(["punarctl", "agents", "access", sessionId, "--json"]);
        } catch (e) {
            console.warn("punar-shell: ledger refresh unavailable:", e);
        }
    }

    // SHIFT+DEL on the focused session (spec §24.2 + §1.17: deleting your
    // own data cannot be terminal-only). Two-step by design — the first
    // press arms and the privacy card asks, the second press acts — and
    // the ghost-red destructive voice keeps it from being an accident.
    // The purge itself is punarctl's job, run detached with fixed argv;
    // the daemon is the authorization point, exactly as everywhere else.
    function purgeKey(sessionId: string): void {
        if (sessionId === "")
            return;
        if (root.purgeArmedId !== sessionId) {
            root.purgeArmedId = sessionId;
            return;
        }
        root.purgeArmedId = "";
        root.purgeRequestedId = sessionId;
        try {
            Quickshell.execDetached(["punarctl", "privacy", "purge", "--session", sessionId, "--yes"]);
        } catch (e) {
            console.warn("punar-shell: purge unavailable:", e);
            root.purgeRequestedId = "";
        }
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        // A destructive action never survives the panel closing.
        root.purgeArmedId = "";
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

        // The M8 ledger view for the focused session (ipc.md §13.2).
        // A detection has no ledger and will not have one in M8 — an
        // unregistered process has no persisted session to aggregate
        // against — so the lookup is not even attempted for one.
        readonly property string currentId: win.current !== null ? String(win.current.id) : ""
        readonly property var ledgerView: (win.current !== null && !win.isDetection)
            ? Ledger.view(win.currentId) : null
        readonly property bool hasLedger: win.ledgerView !== null
        readonly property var ledgerRows: root.ledgerRows(win.ledgerView)
        readonly property var ledgerEvents: root.ledgerEvents(win.ledgerView)
        readonly property string ledgerPurgedAt: root.str(win.ledgerView, "purged_at")

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
                    // Moving the cursor disarms a pending purge and asks
                    // for the newly focused session's ledger if the shell
                    // has not seen it yet.
                    root.purgeArmedId = "";
                    if (root.open)
                        root.refreshLedger(root.selectedId);
                }

                // Keyboard-first (spec §12): arrows walk the rail, Esc
                // closes. No mouse is required anywhere on this surface.
                Keys.onPressed: function (event) {
                    // SHIFT+DEL deletes the focused session's local
                    // ledger. Any other key disarms a pending confirm.
                    if (event.key === Qt.Key_Delete
                            && (event.modifiers & Qt.ShiftModifier) !== 0) {
                        if (win.hasLedger && win.ledgerPurgedAt === "")
                            root.purgeKey(root.selectedId);
                        event.accepted = true;
                        return;
                    }
                    root.purgeArmedId = "";
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
                    // its question in the header, so the promise and the
                    // record can never be read as one. Everything below
                    // is DERIVED from a mediation point Punar already
                    // owns — the session's scope cgroup, the audit stream,
                    // the punar-env workspace grant, the adapter record.
                    // Nothing here comes from tracing (spec §1.14).
                    Sect {
                        width: parent.width
                        visible: win.current !== null && !win.isDetection
                        title: "Ledger"
                        tagline: "what it accessed · local only · level 3 · sampled at scan points"
                    }

                    // A purged ledger is NOT an empty one, and the surface
                    // never lets the two look alike (ipc.md §12.2).
                    Item {
                        width: parent.width
                        height: 44
                        visible: win.current !== null && !win.isDetection
                                 && win.ledgerPurgedAt !== ""

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            height: Theme.hairline
                            color: Theme.border
                        }
                        Column {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 3

                            Meta {
                                width: parent.width
                                font.weight: 600
                                color: Theme.ink
                                text: "Purged by you · " + root.shortTime(win.ledgerPurgedAt)
                            }
                            Meta {
                                width: parent.width
                                font.pixelSize: 8
                                font.weight: 500
                                font.letterSpacing: Theme.tracking(8, 0.1)
                                color: Theme.inputBorder
                                text: "The audit trail is separate and was not deleted"
                                wrapMode: Text.WordWrap
                            }
                        }
                    }

                    // The six categories. Observed rows carry their
                    // classes and counts in the calm muted value voice;
                    // the ones no mediation point observes yet keep the
                    // DASHED honesty grammar with their milestone.
                    Repeater {
                        model: (win.current !== null && !win.isDetection
                                && win.ledgerPurgedAt === "") ? win.ledgerRows : []

                        LedgerRow {
                            required property var modelData

                            width: paneColumn.width
                            label: modelData.label
                            value: modelData.value
                            note: modelData.note
                            dashed: modelData.dashed
                        }
                    }

                    // Fail closed: no record for this session yet (agentd
                    // not running, not in group punar, or nothing sampled
                    // so far). Never an error surface.
                    Item {
                        width: parent.width
                        height: 34
                        visible: win.current !== null && !win.isDetection && !win.hasLedger

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            height: Theme.hairline
                            color: Theme.border
                        }
                        Meta {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            font.weight: 500
                            text: "No ledger recorded for this session yet"
                            elide: Text.ElideRight
                        }
                    }

                    // SECURITY EVENTS — the only red on this pane. The
                    // rows are REFERENCES: the payload lives in the audit
                    // log, which is the single source of truth (spec §53).
                    Sect {
                        width: parent.width
                        visible: win.hasLedger && win.ledgerPurgedAt === ""
                        title: "Security events"
                        tagline: "level 4 · punarctl audit tail"
                    }

                    Repeater {
                        model: (win.hasLedger && win.ledgerPurgedAt === "")
                            ? win.ledgerEvents : []

                        EventRow {
                            required property var modelData

                            width: paneColumn.width
                            category: modelData.category
                            detail: modelData.detail
                        }
                    }

                    Item {
                        width: parent.width
                        height: 40
                        visible: win.hasLedger && win.ledgerPurgedAt === ""
                                 && win.ledgerEvents.length === 0

                        Rectangle {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            height: Theme.hairline
                            color: Theme.border
                        }
                        Column {
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            spacing: 3

                            Meta {
                                width: parent.width
                                font.weight: 500
                                text: "None recorded"
                            }
                            // "None recorded" must never read as "nothing
                            // could happen": the categories with no
                            // producer yet are named, with their milestone.
                            Meta {
                                width: parent.width
                                font.pixelSize: 8
                                font.weight: 500
                                font.letterSpacing: Theme.tracking(8, 0.1)
                                color: Theme.inputBorder
                                text: root.ledgerPendingEvents(win.ledgerView)
                                visible: text !== ""
                                elide: Text.ElideRight
                            }
                        }
                    }

                    // The §24.2 privacy card (mockup .privacy), made real:
                    // where the ledger lives, how long it is kept, and the
                    // keystroke that deletes it. Unmanaged-first — the
                    // admin line appears only while enrolled, and even
                    // then it states the honest M8 truth: there is no
                    // remote query path to have used.
                    Item {
                        width: parent.width
                        height: privacyCard.implicitHeight + 20
                        visible: win.current !== null && !win.isDetection

                        Rectangle {
                            id: privacyCard

                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.bottom: parent.bottom
                            implicitHeight: privacyText.implicitHeight + 26
                            height: implicitHeight
                            radius: Theme.radius
                            color: Theme.muted
                            border.width: Theme.hairline
                            border.color: root.purgeArmedId === win.currentId
                                ? Theme.statusBad : Theme.border

                            Column {
                                id: privacyText

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
                                    text: Status.enrolled
                                        ? "This ledger stays on this device · Admin queries are scoped, audited and visible here"
                                        : "This ledger stays on this device · No organization is enrolled"
                                    wrapMode: Text.WordWrap
                                }

                                // The armed confirm replaces the retention
                                // line so the reader cannot miss it.
                                Meta {
                                    width: parent.width
                                    visible: root.purgeArmedId === win.currentId
                                    font.pixelSize: 9
                                    font.weight: 600
                                    font.letterSpacing: Theme.tracking(9, 0.1)
                                    color: Theme.statusBad
                                    text: "Press Shift+Del again to confirm · this deletes the local ledger for "
                                          + win.currentId + " · the audit trail is not deleted"
                                    wrapMode: Text.WordWrap
                                }
                                Meta {
                                    width: parent.width
                                    visible: root.purgeArmedId !== win.currentId
                                             && root.purgeRequestedId === win.currentId
                                             && win.ledgerPurgedAt === ""
                                    font.pixelSize: 9
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(9, 0.1)
                                    text: "Purge requested · punarctl privacy purge --session "
                                          + win.currentId
                                    wrapMode: Text.WordWrap
                                }
                                Meta {
                                    width: parent.width
                                    visible: root.purgeArmedId !== win.currentId
                                             && !(root.purgeRequestedId === win.currentId
                                                  && win.ledgerPurgedAt === "")
                                    font.pixelSize: 9
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(9, 0.1)
                                    text: {
                                        if (win.ledgerPurgedAt !== "")
                                            return "Purged · the audit trail is separate and was not deleted · punarctl audit tail";
                                        if (!win.hasLedger)
                                            return "Nothing is recorded for this session yet · nothing leaves this machine";
                                        var kept = root.ledgerRetention(win.ledgerView);
                                        return (kept === "" ? "" : kept + " · ")
                                            + "Delete it now: Shift+Del · punarctl privacy purge --session "
                                            + win.currentId;
                                    }
                                    wrapMode: Text.WordWrap
                                }

                                // Enrolled only, and still honest: "none"
                                // here is a statement about a path that
                                // does not exist yet, not about a path
                                // nobody used (milestone-8.md §10.5).
                                Meta {
                                    width: parent.width
                                    visible: Status.enrolled
                                    font.pixelSize: 8
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(8, 0.1)
                                    color: Theme.inputBorder
                                    text: "Last admin query · None — no remote query path exists until Milestone 10"
                                    wrapMode: Text.WordWrap
                                }
                                // The never-record rules, on the surface
                                // that shows the record (spec §21.2).
                                Meta {
                                    width: parent.width
                                    font.pixelSize: 8
                                    font.weight: 500
                                    font.letterSpacing: Theme.tracking(8, 0.1)
                                    color: Theme.inputBorder
                                    text: "Never recorded · file paths inside your workspace · prompts · source code · secret values · individual file reads"
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
                                    // M10 FULFILLED THE `INSPECT` HALF OF
                                    // THIS SENTENCE: the alert card's [I]
                                    // opens THIS view on THIS detection
                                    // (milestone-10.md §5.1), so naming
                                    // inspect as pending would now be
                                    // false. Blocking and registering a
                                    // detection still do not exist — they
                                    // need punar-netd and a policy verb —
                                    // and the milestone they wait on is
                                    // named rather than left vague.
                                    text: "Visibility first · block network and register as managed arrive with enforcement (M12)"
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
                    // The purge key is advertised only where it does
                    // something: a detection has no ledger to delete, and
                    // a purged one has nothing left. No dead keys, the
                    // same rule as no dead buttons.
                    text: "↑↓ Agent · "
                          + ((win.hasLedger && win.ledgerPurgedAt === "")
                             ? "Shift+Del Delete ledger · " : "")
                          + "Esc Close"
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
