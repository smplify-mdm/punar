// ControlData — everything System Control KNOWS, with no opinion about
// how it looks. SystemControl.qml renders exactly what this object hands
// it; the split keeps the honesty rules (spec §1.22) in one auditable
// place, and keeps every "we cannot know this yet" answer next to the
// reason it is true.
//
// Three kinds of input, and the view model always says which one a value
// came from:
//
//   1. FILE WATCHES (inotify, zero polling — the Services/ pattern):
//      Status  → /run/punar/status.json   enrollment and the §52 word
//      Agents  → /run/punar/agents.json   AI sessions and detections
//      Live compositor state arrives through Quickshell.Hyprland
//      (socket2 events) and the session audio graph through
//      Quickshell.Services.Pipewire. All event-driven; none polled.
//
//   2. punarctl READS, on open only — an event, never a clock. Four
//      fixed-argv processes whose stdout is collected and parsed:
//        punarctl status --json           device identity, capability
//                                         count, the §52 compliance block
//        punarctl capabilities --json     the §41 registry descriptors
//        punarctl policy effective --json the §40 information set for
//                                         every governed path
//        punarctl privilege status --json the §48 grants held right now
//      A daemon that is not running answers nothing, and the surface then
//      says AWAITING PUNARD instead of inventing a value.
//
//   3. THE KERNEL, for the handful of facts knowable without a network
//      manager, a power daemon or a Bluetooth stack — fixed paths in
//      /proc and /sys, one read per open. Everything the kernel does not
//      report is drawn dashed with its milestone. This surface never
//      starts a service in order to have something to draw.
//
// MUTATION — the shell is never a second control plane. Every write leaves
// as `punarctl` with FIXED ARGV (never a shell string), and the panel
// re-reads afterwards rather than assuming it worked. Three writes exist,
// and each is the real spec path rather than a settings shortcut:
//
//   [E] REQUEST EXCEPTION →  punarctl privilege request --capability <p>
//                            --reason <typed> --duration 15
//       The §48 reason-required flow. It creates an APPROVAL: punard
//       writes approvals.json and the M9 gate (Plate D-003) opens itself.
//       This is the plate's amber "Request exception · Approval required"
//       tag wearing the approval_required colour, exactly as drawn.
//   [S] SET STATE        →  punarctl capabilities set <path> <state>
//       Offered ONLY while a live grant covers that capability, because
//       that is the one circumstance in which a non-root session may
//       write it (punard's ladder: agent test, then a live §48 grant,
//       then uid 0). With no grant the surface offers [E] instead of a
//       switch that would be refused.
//   [R] REVOKE           →  punarctl privilege revoke <grant_id>
//       Privilege is never permanent and never invisible.
//
// The exact argv is printed under the action row and the daemon's
// §73-voice refusal is rendered verbatim, because spec §10 says the panel
// and the CLI are one capability layer — so they may as well share a mouth.

import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io
import Quickshell.Services.Pipewire
import "../Services"

Scope {
    id: data

    // The rail item under the cursor, by id. Kept across a refresh so a
    // probe landing never moves the reader.
    property string selectedId: "firewall"

    // Live filter text from the `/` search field.
    property string query: ""

    // Local-only filter and catalog for the Date & Time chooser. The list
    // comes from the installed tzdata package; opening Settings performs no
    // network lookup.
    property string timezoneQuery: ""
    property var timezoneNames: ["UTC"]

    // The capability awaiting a typed reason ([E] · §48 requires one).
    // "" = nothing armed. Cleared by Esc, by moving the selection and by
    // closing the panel — a request never stays armed behind the reader.
    property string reasonForCapability: ""

    // Millisecond clock for the §48 grant countdown, advanced only by the
    // surface's Timer, which runs only while that surface is open.
    property double nowMs: Date.now()

    // The last mutation handed to punarctl, printed verbatim.
    property string lastActionArgv: ""
    property int lastActionExit: -1
    property string lastActionError: ""
    property bool lastActionPending: false

    // Raised when the reader asks for the full AI surface.
    signal aiPanelRequested

    // Raised by the Applications pane. An installed entry is a typed
    // DesktopEntry launch; a catalog id opens the exact inspect/install
    // card; two empty arguments mean browse everything. shell.qml is the
    // only place allowed to connect those sibling surfaces.
    signal applicationRequested(var entry, string catalogId)

    // ---------------------------------------------------------------
    // Small helpers. Tones are STRINGS here ("ok"/"warn"/"bad"/"") —
    // this object holds no colour, because colour is a rendering
    // decision and DESIGN_LANGUAGE §9.1 keeps those in one place.
    // ---------------------------------------------------------------

    function obj(v: var): var {
        return (v !== null && v !== undefined && typeof v === "object") ? v : null;
    }

    function str(o: var, key: string, fallback: string): string {
        var m = data.obj(o);
        if (m === null)
            return fallback;
        var v = m[key];
        return (typeof v === "string" && v !== "") ? v : fallback;
    }

    // The spec §52 wire states → the §2 status voice, 1:1 and forever.
    function complianceTone(state: string): string {
        switch (state) {
        case "compliant":
            return "ok";
        case "non_compliant":
        case "unknown":
            return "bad";
        case "remediating":
        case "exception":
            return "warn";
        default:
            return "";
        }
    }

    function titleCase(word: string): string {
        if (word === "")
            return "";
        var s = String(word).replace(/_/g, " ");
        return s.charAt(0).toUpperCase() + s.slice(1);
    }

    // DESIGN_LANGUAGE §8.1: the wire never changes, only the word drawn.
    // Status owns the one table shared across shell surfaces.
    function stateLabel(state: string): string {
        return Status.stateLabel(state);
    }

    function stateKey(): string {
        return Status.stateKey;
    }

    // A capability state value is JSON by contract (the schema's
    // `state_value` convention) — never assume string.
    function stateWord(value: var): string {
        if (value === null || value === undefined)
            return "—";
        if (typeof value === "string")
            return value === "" ? "—" : value;
        if (typeof value === "boolean")
            return value ? "true" : "false";
        return JSON.stringify(value);
    }

    // RFC 3339 → the field-note short form. "" for anything unparsable,
    // rather than printing a wrong time.
    function shortTime(ts: string): string {
        if (ts === null || ts === undefined || ts === "")
            return "";
        var d = new Date(ts);
        if (isNaN(d.getTime()))
            return "";
        return Qt.formatDateTime(d, "yyyy-MM-dd hh:mm");
    }

    function minutesLeft(expiresAt: string): int {
        var d = new Date(expiresAt);
        if (isNaN(d.getTime()))
            return -1;
        return Math.max(0, Math.round((d.getTime() - data.nowMs) / 60000));
    }

    function capabilityLabel(path: string): string {
        switch (path) {
        case "security.firewall":
            return "Firewall";
        case "system.hostname":
            return "Hostname";
        case "time.timezone":
            return "Timezone";
        default:
            return path;
        }
    }

    // ---------------------------------------------------------------
    // punarctl probes — fixed argv, asynchronous, output parsed.
    // ---------------------------------------------------------------

    component Probe: Process {
        id: probe

        // Parsed `result` object on success; null while unanswered.
        property var payload: null
        // The daemon's §73-voice refusal, verbatim, when one came back.
        property string errorText: ""
        property bool answered: false

        stdout: StdioCollector {
            id: probeOut
            waitForEnd: true
        }
        stderr: StdioCollector {
            id: probeErr
            waitForEnd: true
        }

        // Connected rather than declared as an `onExited` handler:
        // Process.exited carries a QProcess::ExitStatus that Quickshell
        // does not register as a QML type, so a declarative handler
        // cannot be compiled and qmllint says so. Only the exit code is
        // wanted here, and a runtime connect takes exactly that.
        Component.onCompleted: probe.exited.connect(function (exitCode) {
            probe.answered = true;
            probe.errorText = String(probeErr.text).trim();
            var parsed = null;
            if (exitCode === 0) {
                try {
                    parsed = JSON.parse(probeOut.text);
                } catch (e) {
                    parsed = null;
                }
            }
            probe.payload = parsed;
        })

        function ask(argv: list<string>): void {
            if (probe.running)
                return;
            probe.command = argv;
            try {
                probe.running = true;
            } catch (e) {
                // No punarctl on this machine (a dev checkout): the
                // surface keeps saying AWAITING PUNARD, which is true.
                console.warn("punar-shell: punarctl unavailable:", e);
            }
        }
    }

    Probe {
        id: statusProbe
    }
    Probe {
        id: capsProbe
    }
    Probe {
        id: policyProbe
    }
    Probe {
        id: grantsProbe
    }

    // The mutation channel — separate from the probes so a write never
    // races a read, and so its exit code and stderr can be shown.
    Process {
        id: mutation

        stdout: StdioCollector {
            id: mutationOut
            waitForEnd: true
        }
        stderr: StdioCollector {
            id: mutationErr
            waitForEnd: true
        }

        // Connected, not declared — see the note on Probe above.
        Component.onCompleted: mutation.exited.connect(function (exitCode) {
            data.lastActionPending = false;
            data.lastActionExit = exitCode;
            data.lastActionError = String(mutationErr.text).trim();
            // Never trust the write: re-read the control plane and let
            // the registry say what actually happened.
            data.refreshProbes();
        })
    }

    function runMutation(argv: list<string>): void {
        if (mutation.running)
            return;
        data.lastActionArgv = argv.join(" ");
        data.lastActionExit = -1;
        data.lastActionError = "";
        data.lastActionPending = true;
        mutation.command = argv;
        try {
            mutation.running = true;
        } catch (e) {
            data.lastActionPending = false;
            data.lastActionExit = 127;
            data.lastActionError = "punarctl is not installed on this machine.";
        }
    }

    function refreshProbes(): void {
        statusProbe.ask(["punarctl", "status", "--json"]);
        capsProbe.ask(["punarctl", "capabilities", "--json"]);
        policyProbe.ask(["punarctl", "policy", "effective", "--json"]);
        grantsProbe.ask(["punarctl", "privilege", "status", "--json"]);
    }

    // ---------------------------------------------------------------
    // Accessors over the probe payloads. Each answers null / empty when
    // the control plane has not spoken — callers render AWAITING PUNARD
    // rather than a default.
    // ---------------------------------------------------------------

    readonly property var statusData: data.obj(statusProbe.payload)
    readonly property bool daemonAnswered: data.statusData !== null

    readonly property var capabilityList: {
        var p = data.obj(capsProbe.payload);
        if (p === null || !Array.isArray(p.capabilities))
            return [];
        return p.capabilities;
    }

    readonly property var policyList: {
        var p = data.obj(policyProbe.payload);
        if (p === null || !Array.isArray(p.entries))
            return [];
        return p.entries;
    }

    readonly property var grantList: {
        // The protected approvals projection is event-driven and updates in
        // the same transaction that resolves the approval. Prefer it once
        // loaded so a newly approved grant makes this open pane actionable
        // immediately. The one-shot CLI probe remains the startup fallback.
        if (Approvals.loaded)
            return Array.isArray(Approvals.grants) ? Approvals.grants : [];
        var p = data.obj(grantsProbe.payload);
        if (p === null || !Array.isArray(p.grants))
            return [];
        return p.grants;
    }

    readonly property bool hasLiveGrant: data.grantList.length > 0

    function capFor(path: string): var {
        var list = data.capabilityList;
        for (var i = 0; i < list.length; i++) {
            if (list[i] !== null && list[i].capability === path)
                return list[i];
        }
        return null;
    }

    function explainFor(path: string): var {
        var list = data.policyList;
        for (var i = 0; i < list.length; i++) {
            if (list[i] !== null && list[i].path === path)
                return list[i];
        }
        return null;
    }

    function grantFor(path: string): var {
        var list = data.grantList;
        for (var i = 0; i < list.length; i++) {
            if (list[i] !== null && list[i].capability === path)
                return list[i];
        }
        return null;
    }

    function complianceOverall(): string {
        var s = data.statusData;
        if (s === null)
            return "";
        return data.str(data.obj(s.compliance), "overall", "");
    }

    // ---------------------------------------------------------------
    // Kernel facts — fixed paths, one read per open, no watch, no timer.
    // ---------------------------------------------------------------

    property string netInterface: ""
    property string netGateway: ""
    property string netOperState: ""
    property string netAddress: ""
    property string batteryCapacity: ""
    property string batteryStatus: ""
    property string cryptUuid: ""
    property string secureBootValue: ""

    function hexToIp(h: string): string {
        if (h.length !== 8)
            return "";
        return parseInt(h.substr(6, 2), 16) + "." + parseInt(h.substr(4, 2), 16) + "." + parseInt(h.substr(2, 2), 16) + "." + parseInt(h.substr(0, 2), 16);
    }

    function parseRoute(): void {
        var iface = "";
        var gw = "";
        try {
            var lines = String(routeFile.text()).split("\n");
            for (var i = 1; i < lines.length; i++) {
                var f = lines[i].trim().split(/\s+/);
                if (f.length < 3)
                    continue;
                if (f[1] === "00000000") {
                    iface = f[0];
                    gw = data.hexToIp(f[2]);
                    break;
                }
            }
        } catch (e) {
            iface = "";
            gw = "";
        }
        data.netInterface = iface;
        data.netGateway = gw;
    }

    FileView {
        id: routeFile
        // The kernel's own routing table. procfs delivers no inotify
        // events, so this is re-read on open — an event, not a poll.
        path: "/proc/net/route"
        onLoaded: data.parseRoute()
        onLoadFailed: {
            data.netInterface = "";
            data.netGateway = "";
        }
    }

    // Sysfs facts about whichever interface carries the default route. A
    // device with no default route leaves these unloaded, and the view
    // says so rather than inventing a link state.
    readonly property string netBase: data.netInterface === "" ? "" : "/sys/class/net/" + data.netInterface

    FileView {
        id: operFile
        path: data.netBase === "" ? "" : data.netBase + "/operstate"
        onLoaded: data.netOperState = String(operFile.text()).trim()
        onLoadFailed: data.netOperState = ""
    }
    FileView {
        id: macFile
        path: data.netBase === "" ? "" : data.netBase + "/address"
        onLoaded: data.netAddress = String(macFile.text()).trim()
        onLoadFailed: data.netAddress = ""
    }
    FileView {
        id: batCapFile
        path: "/sys/class/power_supply/BAT0/capacity"
        onLoaded: data.batteryCapacity = String(batCapFile.text()).trim()
        onLoadFailed: data.batteryCapacity = ""
    }
    FileView {
        id: batStatusFile
        path: "/sys/class/power_supply/BAT0/status"
        onLoaded: data.batteryStatus = String(batStatusFile.text()).trim()
        onLoadFailed: data.batteryStatus = ""
    }
    // A device-mapper crypt target names itself in its UUID
    // ("CRYPT-LUKS2-…"). This is the only disk-encryption fact the device
    // reports without a helper; punard registers no encryption
    // capability, so there is nothing else to read.
    FileView {
        id: cryptFile
        path: "/sys/block/dm-0/dm/uuid"
        onLoaded: data.cryptUuid = String(cryptFile.text()).trim()
        onLoadFailed: data.cryptUuid = ""
    }
    // The EFI SecureBoot variable: four attribute bytes, then one value
    // byte. Absent on a machine that did not boot under UEFI Secure Boot
    // — which is every current Punar build, and the plate says so.
    FileView {
        id: secureBootFile
        path: "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
        onLoaded: {
            var t = String(secureBootFile.text());
            data.secureBootValue = t.length >= 5 ? (t.charCodeAt(4) === 1 ? "enabled" : "disabled") : "";
        }
        onLoadFailed: data.secureBootValue = ""
    }

    function parseTimezones(body: string): void {
        var seen = {"UTC": true};
        var zones = ["UTC"];
        var lines = String(body).split("\n");
        for (var i = 0; i < lines.length; ++i) {
            if (lines[i] === "" || lines[i].indexOf("#") === 0)
                continue;
            var fields = lines[i].split("\t");
            if (fields.length < 3)
                continue;
            var zone = fields[2];
            if (!seen[zone] && /^[A-Za-z0-9_+-]+(\/[A-Za-z0-9_+-]+)*$/.test(zone)) {
                seen[zone] = true;
                zones.push(zone);
            }
        }
        zones.sort();
        data.timezoneNames = zones;
    }

    FileView {
        id: timezoneCatalog
        path: "/usr/share/zoneinfo/zone.tab"
        blockLoading: true
        onLoaded: data.parseTimezones(timezoneCatalog.text())
    }

    function refreshKernelFacts(): void {
        routeFile.reload();
        operFile.reload();
        macFile.reload();
        batCapFile.reload();
        batStatusFile.reload();
        cryptFile.reload();
        secureBootFile.reload();
    }

    // Live session audio. The tracker keeps the default nodes bound so
    // their volume and mute stay current while the panel is up.
    PwObjectTracker {
        objects: [Pipewire.defaultAudioSink, Pipewire.defaultAudioSource]
    }

    // ---------------------------------------------------------------
    // The §63 taxonomy, in the spec's order when enrolled. On a personal
    // device ORGANIZATION is absent: it is neither an empty prerequisite nor
    // an enrollment advertisement. The useful local primitives that used to
    // sit beneath it remain fully reachable under SECURITY — drift, effective
    // policy and JIT privilege protect a personal machine too. Enrollment is
    // deliberately discoverable from `punarctl enroll status`, the one place
    // reached by somebody who explicitly asked about enrollment.
    // ---------------------------------------------------------------

    readonly property var taxonomy: {
        var securityItems = [
            {id: "device", name: "Device"},
            {id: "encryption", name: "Encryption"},
            {id: "secureboot", name: "Secure Boot"},
            {id: "firewall", name: "Firewall"}
        ];
        if (!Status.enrolled) {
            securityItems.push({id: "compliance", name: "Drift"});
            securityItems.push({id: "policies", name: "Policy"});
            securityItems.push({id: "privilege", name: "Privilege"});
        }

        var sections = [
            {
                section: "System",
                items: [
                    {id: "network", name: "Network"},
                    {id: "datetime", name: "Date & Time"},
                    {id: "bluetooth", name: "Bluetooth"},
                    {id: "displays", name: "Displays"},
                    {id: "audio", name: "Audio"},
                    {id: "power", name: "Power"},
                    {id: "applications", name: "Applications"}
                ]
            },
            {section: "Security", items: securityItems},
            {
                section: "AI",
                items: [
                    {id: "agents", name: "Agents"},
                    {id: "aipermissions", name: "Permissions"},
                    {id: "models", name: "Models"},
                    {id: "mcp", name: "MCP"}
                ]
            },
            {
                section: "Developer",
                items: [
                    {id: "projects", name: "Projects"},
                    {id: "containers", name: "Containers"},
                    {id: "toolchains", name: "Toolchains"}
                ]
            },
            {
                section: "Privacy",
                items: [
                    {id: "connections", name: "Connections"},
                    {id: "relay", name: "Relay"}
                ]
            }
        ];

        if (Status.enrolled) {
            sections.push({
                section: "Organization",
                items: [
                    {id: "enrollment", name: "Enrollment"},
                    {id: "compliance", name: "Compliance"},
                    {id: "policies", name: "Policies"},
                    {id: "privilege", name: "Privilege"}
                ]
            });
        }
        return sections;
    }

    readonly property var railItems: {
        var out = [];
        var q = data.query.trim().toLowerCase();
        for (var s = 0; s < data.taxonomy.length; s++) {
            var sec = data.taxonomy[s];
            for (var i = 0; i < sec.items.length; i++) {
                var it = sec.items[i];
                if (q !== "" && String(it.name).toLowerCase().indexOf(q) < 0 && String(sec.section).toLowerCase().indexOf(q) < 0)
                    continue;
                out.push({
                    id: it.id,
                    name: it.name,
                    section: sec.section
                });
            }
        }
        return out;
    }

    // Status dots appear ONLY where there is status (mockup register 02;
    // DESIGN_LANGUAGE §2 — a screen with no status to report contains no
    // colour). Three items can carry one, and only when they have data.
    function dotFor(itemId: string): string {
        if (itemId === "firewall") {
            var e = data.explainFor("security.firewall");
            return e === null ? "" : data.complianceTone(data.str(e, "compliance_state", ""));
        }
        if (itemId === "agents") {
            if (Agents.unknownCount > 0)
                return "bad";
            return Agents.managedCount > 0 ? "ok" : "";
        }
        if (itemId === "compliance") {
            var overall = data.complianceOverall();
            if (overall === "")
                return "";
            var tone = data.complianceTone(overall);
            // §8: personal DRIFT is calm when the document matches. Colour
            // appears only for an actual deviation/restoration, never as
            // ambient reassurance.
            if (!Status.enrolled && tone === "ok")
                return "";
            return tone;
        }
        return "";
    }

    // ---------------------------------------------------------------
    // Actions
    // ---------------------------------------------------------------

    function runAction(a: var): void {
        if (a === null || a === undefined)
            return;
        var kind = String(a.kind);
        if (kind === "goto") {
            data.select(String(a.target));
        } else if (kind === "aipanel") {
            // ASK, DO NOT REACH — the AlertStack.onInspectRequested
            // precedent. The shell root answers this signal with
            // `aiPanel.show()`; this object does not know the panel
            // exists. It previously ALSO spawned `qs ipc call aipanel
            // open`, which — now that shell.qml wires the signal — forked
            // a process so this shell could send a message to itself and
            // open the same panel twice. One request, one opening.
            data.aiPanelRequested();
        } else if (kind === "applicationBrowser") {
            data.applicationRequested(null, "");
        } else if (kind === "application") {
            data.applicationRequested(a.entry, "");
        } else if (kind === "catalogApplication") {
            data.applicationRequested(null, String(a.appId));
        } else if (kind === "privilege") {
            // §48 requires a reason, so the reason is asked for before
            // anything is sent. Esc cancels; Enter submits.
            data.reasonForCapability = String(a.path);
        } else if (kind === "capset") {
            data.runMutation(["punarctl", "capabilities", "set", String(a.path), String(a.value)]);
        } else if (kind === "revoke") {
            data.runMutation(["punarctl", "privilege", "revoke", String(a.grantId)]);
        }
    }

    function submitReason(reason: string): void {
        var path = data.reasonForCapability;
        data.reasonForCapability = "";
        if (path === "" || reason.trim() === "")
            return;
        data.runMutation(["punarctl", "privilege", "request", "--capability", path, "--reason", reason.trim(), "--duration", "15"]);
    }

    function actionByHotkey(key: string): var {
        var v = data.view;
        if (v === null || v === undefined || !Array.isArray(v.actions))
            return null;
        for (var i = 0; i < v.actions.length; i++) {
            if (v.actions[i].hotkey === key)
                return v.actions[i];
        }
        return null;
    }

    // What the state toggle does when it is pressed. It is never a dead
    // affordance: on a control this session may write (a live §48 grant
    // covers it) that is [S] SET, and on a control policy owns it is [E]
    // REQUEST EXCEPTION — which is exactly what pressing a managed switch
    // ought to get you. A view with neither returns null and the toggle
    // stays a pure state indicator, which is what the plate draws.
    function toggleAction(): var {
        var setAction = data.actionByHotkey("S");
        return setAction !== null ? setAction : data.actionByHotkey("E");
    }

    function select(itemId: string): void {
        data.selectedId = itemId;
        data.reasonForCapability = "";
        if (itemId !== "datetime")
            data.timezoneQuery = "";
    }

    function refreshAll(): void {
        data.refreshProbes();
        data.refreshKernelFacts();
    }

    // ---------------------------------------------------------------
    // The view model. Every detail view is DATA, rendered by ONE pane —
    // so the grammar cannot drift between sections, which is the plate's
    // register-01 claim ("one rail, one grammar").
    //
    // Shape:
    //   title, sub, simTag
    //   pill{label, dotTone}
    //   toggle{show, on}
    //   kv[]      {k, v, mono, tone}
    //   rows[]    {name, meta, tone, tag}   emptyRows: the honest empty
    //   explains[]{capability, effective, source, policyId, override,
    //              compliance, tone}        — the §40 card
    //   grant     the live §48 grant object, when one covers this view
    //   dashed{what, why, when_}            — the §1.22 honesty panel
    //   note                                — the §73 plain paragraph
    //   actions[] {hotkey, label, tone, kind, …}
    // ---------------------------------------------------------------

    readonly property var view: data.buildView(data.selectedId)

    function awaiting(): var {
        return {
            what: "Awaiting punard",
            why: "The local control plane has not answered on this machine, so there is nothing measured to show. Punar renders no value it did not read.",
            when_: "Start punard, or run punarctl status in a terminal"
        };
    }

    function explainCardFor(path: string): var {
        var exp = data.explainFor(path);
        if (exp === null)
            return null;
        var src = data.obj(exp.source);
        var rawState = data.str(exp, "compliance_state", "unknown");
        return {
            capability: path,
            effective: data.stateWord(exp.effective_value),
            source: data.str(src, "name", "Unknown source"),
            policyId: data.str(src, "policy_id", ""),
            override: exp.user_override_permitted === true ? "Permitted" : "Not permitted",
            stateKey: data.stateKey(),
            compliance: data.stateLabel(rawState),
            tone: data.complianceTone(rawState)
        };
    }

    // The §48/§40 action row shared by every governed capability.
    function capabilityActions(path: string): var {
        var acts = [];
        var exp = data.explainFor(path);
        var cap = data.capFor(path);
        if (exp === null || cap === null)
            return acts;
        var grant = data.grantFor(path);
        if (grant !== null && cap.mutable === true) {
            // A live §48 grant is the ONLY circumstance in which this
            // session may write the capability, so the set action appears
            // only now — and it names the state it would write.
            var current = data.stateWord(exp.effective_value);
            var next = current === "enabled" ? "disabled" : "enabled";
            acts.push({
                hotkey: "S",
                label: "Set " + next,
                tone: "ghost",
                kind: "capset",
                path: path,
                value: next
            });
            acts.push({
                hotkey: "R",
                label: "Revoke grant",
                tone: "danger",
                kind: "revoke",
                grantId: data.str(grant, "grant_id", "")
            });
        } else {
            acts.push({
                hotkey: "E",
                label: exp.user_override_permitted === true ? "Request privilege · Approval required" : "Request exception · Approval required",
                tone: "amber",
                kind: "privilege",
                path: path
            });
        }
        acts.push({
            hotkey: "P",
            label: "View policy",
            tone: "ghost",
            kind: "goto",
            target: "policies"
        });
        return acts;
    }

    function buildView(id: string): var {
        var v = data.systemView(id);
        if (v !== null)
            return v;
        v = data.securityView(id);
        if (v !== null)
            return v;
        v = data.aiView(id);
        if (v !== null)
            return v;
        v = data.developerView(id);
        if (v !== null)
            return v;
        v = data.privacyView(id);
        if (v !== null)
            return v;
        v = data.orgView(id);
        if (v !== null)
            return v;
        return {
            title: "System Control",
            sub: "Punar",
            note: "Choose a section on the left."
        };
    }

    // ---- SYSTEM ----------------------------------------------------

    function systemView(id: string): var {
        if (id === "network")
            return data.viewNetwork();
        if (id === "datetime")
            return data.viewDateTime();
        if (id === "bluetooth") {
            return {
                title: "Bluetooth",
                sub: "System · not present on this device",
                dashed: {
                    what: "Not available on this device",
                    why: "No Bluetooth stack ships in the Punar desktop image, and punard registers no bluetooth capability. There is nothing here to switch on, so no switch is drawn.",
                    when_: "Unscheduled · no milestone claims it"
                },
                note: "Silence is not support. A surface that cannot act says so."
            };
        }
        if (id === "displays")
            return data.viewDisplays();
        if (id === "audio")
            return data.viewAudio();
        if (id === "power")
            return data.viewPower();
        if (id === "applications")
            return data.viewApplications();
        return null;
    }

    function timezoneRows(current: string, writable: bool): var {
        var rows = [];
        var queryText = data.timezoneQuery.trim().toLowerCase();
        var common = [
            "UTC", "America/Los_Angeles", "America/New_York",
            "Europe/London", "Asia/Kolkata"
        ];
        var source = queryText === "" ? common : data.timezoneNames;
        var added = {};
        if (current !== "" && current !== "unknown" && queryText === "")
            source = [current].concat(source);
        for (var i = 0; i < source.length && rows.length < 24; ++i) {
            var zone = String(source[i]);
            if (added[zone] || (queryText !== "" && zone.toLowerCase().indexOf(queryText) < 0))
                continue;
            added[zone] = true;
            var row = {
                name: zone,
                meta: zone === current ? "Current timezone" : (writable ? "Select to use this timezone" : "Request access below to change"),
                tone: zone === current ? "ok" : "",
                tag: zone === current ? "Current" : ""
            };
            if (writable && zone !== current) {
                row.action = {
                    kind: "capset",
                    path: "time.timezone",
                    value: zone
                };
            }
            rows.push(row);
        }
        return rows;
    }

    function viewDateTime(): var {
        var exp = data.explainFor("time.timezone");
        var cap = data.capFor("time.timezone");
        if (exp === null || cap === null) {
            return {
                title: "Date & Time",
                sub: "System · timezone",
                dashed: data.awaiting()
            };
        }
        var current = data.stateWord(exp.effective_value);
        var source = data.obj(exp.source);
        var sourceKind = data.str(source, "kind", "");
        var grant = data.grantFor("time.timezone");
        var writable = grant !== null && cap.mutable === true;
        var mode = sourceKind === "local_user_preference"
            ? "Manual"
            : (sourceKind.indexOf("organization_") === 0
                ? "Managed"
                : (sourceKind === "os_secure_default" ? "Automatic · UTC fallback" : "Automatic from network"));
        var actions = [];
        if (writable) {
            actions.push({
                hotkey: "R",
                label: "Revoke access",
                tone: "danger",
                kind: "revoke",
                grantId: data.str(grant, "grant_id", "")
            });
        } else {
            actions.push({
                hotkey: "E",
                label: exp.user_override_permitted === true ? "Change timezone · Approval required" : "Request exception · Approval required",
                tone: "amber",
                kind: "privilege",
                path: "time.timezone"
            });
        }
        actions.push({
            hotkey: "P",
            label: "View policy",
            tone: "ghost",
            kind: "goto",
            target: "policies"
        });
        return {
            title: "Date & Time",
            sub: "System · local tzdata · no location service",
            zonePicker: true,
            kv: [
                {k: "Timezone", v: current},
                {k: "Mode", v: mode, mono: false},
                {k: "Source", v: data.str(source, "name", "Unknown source")}
            ],
            rows: data.timezoneRows(current, writable),
            emptyRows: "No timezone matches that search",
            grant: grant,
            actions: actions,
            note: writable
                ? "Search the IANA timezone catalog and choose a row. The change is applied through punard, audited, and protected from later network overrides."
                : "Punar selects a timezone from RFC 4833 network information when available and otherwise uses UTC. To choose manually, request short-lived access below; no IP address or location is sent to a third party."
        };
    }

    function viewApplications(): var {
        // Installed applications are the compositor session's live desktop
        // entry index. Available applications are the finite catalog shipped
        // in the signed root slot. Neither path performs network I/O merely
        // because the reader opened System Control.
        var rows = [];
        var installed = Apps.search("", 0);
        var knownIds = ({});
        for (var i = 0; i < installed.length; i++) {
            var installedId = Apps.bareId(installed[i]);
            knownIds[installedId] = true;
            rows.push({
                name: String(installed[i].name),
                meta: "Installed · select to open",
                tone: "",
                tag: "Installed",
                action: {
                    kind: "application",
                    entry: installed[i]
                }
            });
        }

        var available = Catalog.search("", 0);
        var availableCount = 0;
        for (var k = 0; k < available.length; k++) {
            var app = available[k];
            if (knownIds[String(app.id).toLowerCase()] === true)
                continue;
            availableCount++;
            rows.push({
                name: String(app.name),
                meta: data.titleCase(String(app.category)) + " · " + data.titleCase(String(app.trustTier)) + " · select to inspect",
                tone: "",
                tag: "Available",
                action: {
                    kind: "catalogApplication",
                    appId: String(app.id)
                }
            });
        }

        var version = Catalog.document && typeof Catalog.document.catalogVersion === "string"
            ? Catalog.document.catalogVersion : "unavailable";
        return {
            title: "Applications",
            sub: "System · " + installed.length + " installed · " + availableCount + " available · catalog " + version,
            pill: {
                label: Status.enrolled ? "Policy applies" : "User installs allowed"
            },
            rows: rows,
            emptyRows: "No installed or catalog applications are visible",
            note: Status.enrolled
                ? "Installed entries come from this live session; available entries come from the signed image catalog. Organization policy is evaluated by punard before any install."
                : "Installed entries come from this live session; available entries come from the signed image catalog. Opening the browser below fetches nothing until you choose an application.",
            actions: [
                {
                    hotkey: "O",
                    label: "Browse and install",
                    tone: "ghost",
                    kind: "applicationBrowser"
                }
            ]
        };
    }

    function viewNetwork(): var {
        var kv = [];
        if (data.netInterface === "") {
            kv.push({
                k: "Default route",
                v: "NONE — the kernel routing table has no default entry",
                mono: false
            });
        } else {
            kv.push({
                k: "Default route",
                v: data.netInterface + (data.netGateway === "" ? "" : "  via  " + data.netGateway)
            });
            kv.push({
                k: "Link state",
                v: data.netOperState === "" ? "not reported" : data.netOperState.toUpperCase(),
                tone: data.netOperState === "up" ? "ok" : ""
            });
            kv.push({
                k: "Hardware address",
                v: data.netAddress === "" ? "not reported" : data.netAddress
            });
        }
        kv.push({
            k: "Source",
            v: "/proc/net/route · /sys/class/net — read once per open"
        });
        return {
            title: "Network",
            sub: "System · kernel routing table · read-only",
            kv: kv,
            dashed: {
                what: "Networks, connect and disconnect · Milestone 12",
                why: "Punar ships no NetworkManager and registers no network capability, so there is no list of networks to show and no ConnectWifi to call. The plate draws that row against punar-netd, which arrives with the network privacy prototype.",
                when_: "Milestone 12 · punar-netd"
            },
            note: "System Control shows what the kernel already reports. It does not start a network service in order to have something to draw, and it will not render a toggle that no capability backs."
        };
    }

    function viewDisplays(): var {
        var rows = [];
        var mons = Hyprland.monitors.values;
        for (var i = 0; i < mons.length; i++) {
            var m = mons[i];
            var ipc = data.obj(m.lastIpcObject);
            var hz = (ipc !== null && typeof ipc.refreshRate === "number") ? (" @ " + ipc.refreshRate.toFixed(2) + " Hz") : "";
            rows.push({
                name: m.name,
                meta: m.width + "×" + m.height + hz + " · scale " + m.scale.toFixed(2) + " · " + m.x + "," + m.y + (m.focused ? " · FOCUSED" : ""),
                tone: ""
            });
        }
        return {
            title: "Displays",
            sub: "System · Hyprland monitor state · live",
            pill: {
                label: rows.length + (rows.length === 1 ? " display" : " displays")
            },
            rows: rows,
            emptyRows: "No monitor is reported by the compositor",
            note: "Read-only, and here is the reason: display configuration is not a registered capability. punard's registry carries three backends — security.firewall, system.hostname, time.timezone — and this panel does not write a setting the control plane does not own."
        };
    }

    function viewAudio(): var {
        if (!Pipewire.ready) {
            return {
                title: "Audio",
                sub: "System · PipeWire session graph",
                dashed: {
                    what: "PipeWire is not running in this session",
                    why: "The audio graph has not come up, so this device reports no sink and no source. Nothing is inferred from its absence.",
                    when_: "Starts with the session · systemctl --user status pipewire"
                }
            };
        }
        var kv = [];
        var sink = Pipewire.defaultAudioSink;
        var source = Pipewire.defaultAudioSource;
        if (sink !== null && sink.audio !== null) {
            kv.push({
                k: "Output",
                v: sink.description === "" ? sink.name : sink.description,
                mono: false
            });
            kv.push({
                k: "Output volume",
                v: Math.round(sink.audio.volume * 100) + " %"
            });
            kv.push({
                k: "Output muted",
                v: sink.audio.muted ? "MUTED" : "NO",
                tone: sink.audio.muted ? "warn" : ""
            });
        } else {
            kv.push({
                k: "Output",
                v: "no default sink"
            });
        }
        if (source !== null && source.audio !== null) {
            kv.push({
                k: "Input",
                v: source.description === "" ? source.name : source.description,
                mono: false
            });
            kv.push({
                k: "Input volume",
                v: Math.round(source.audio.volume * 100) + " %"
            });
            kv.push({
                k: "Input muted",
                v: source.audio.muted ? "MUTED" : "NO",
                tone: source.audio.muted ? "warn" : ""
            });
        }
        return {
            title: "Audio",
            sub: "System · PipeWire session graph · live",
            kv: kv,
            note: "Read-only here, and here is the reason: volume is a property of your session's audio graph, not a typed capability — punard governs no audio path and never will. Adjustment belongs to the volume keys and their on-screen display, which own one source of truth between them."
        };
    }

    function viewPower(): var {
        if (data.batteryCapacity === "") {
            return {
                title: "Power",
                sub: "System · power supply class",
                dashed: {
                    what: "No battery reported",
                    why: "This device exposes no BAT0 entry under /sys/class/power_supply — which is what a virtual machine reports, truthfully. No power capability is registered either, so there is nothing to govern.",
                    when_: "Unscheduled · no milestone claims power management"
                }
            };
        }
        return {
            title: "Power",
            sub: "System · power supply class · read-only",
            kv: [
                {
                    k: "Charge",
                    v: data.batteryCapacity + " %"
                },
                {
                    k: "State",
                    v: data.batteryStatus === "" ? "not reported" : data.batteryStatus.toUpperCase()
                },
                {
                    k: "Source",
                    v: "/sys/class/power_supply/BAT0 — read once per open"
                }
            ],
            note: "Punar registers no power capability, so this view reports and does not set."
        };
    }

    // ---- SECURITY --------------------------------------------------

    function securityView(id: string): var {
        if (id === "device")
            return data.viewDevice();
        if (id === "encryption")
            return data.viewEncryption();
        if (id === "secureboot")
            return data.viewSecureBoot();
        if (id === "firewall")
            return data.viewFirewall();
        return null;
    }

    function viewDevice(): var {
        var s = data.statusData;
        if (s === null) {
            return {
                title: "Device",
                sub: "Security · identity",
                dashed: data.awaiting()
            };
        }
        var reconciled = data.shortTime(data.str(s, "last_reconcile", ""));
        var kv = [
            {
                k: "Hostname",
                v: data.str(s, "hostname", "—")
            },
            {
                k: "Device id",
                v: data.str(s, "device_id", "—")
            },
            {
                k: "Mode",
                v: data.titleCase(data.str(s, "mode", "—")),
                mono: false
            },
            {
                k: "Capabilities",
                v: (typeof s.capabilities_total === "number" ? s.capabilities_total : 0) + " registered"
            },
            {
                k: "Daemon",
                v: "punard " + data.str(s, "daemon_version", "?")
            },
            {
                k: "Last reconcile",
                v: reconciled === "" ? "not yet" : reconciled
            }
        ];
        var explains = [];
        var h = data.explainCardFor("system.hostname");
        if (h !== null)
            explains.push(h);
        var tz = data.explainCardFor("time.timezone");
        if (tz !== null)
            explains.push(tz);
        var hostExp = data.explainFor("system.hostname");
        return {
            title: "Device",
            sub: "Security · identity · two typed capabilities",
            pill: (hostExp !== null && hostExp.user_override_permitted === false) ? {
                label: "Managed"
            } : null,
            kv: kv,
            explains: explains,
            grant: data.grantFor("system.hostname"),
            actions: data.capabilityActions("system.hostname"),
            note: "The hostname and the timezone are real typed capabilities: punard observes them, policy decides them, and every change is audited. Everything else on this card is identity that punard reports and nobody sets by hand."
        };
    }

    function viewEncryption(): var {
        var luks = data.cryptUuid !== "" && data.cryptUuid.indexOf("CRYPT-LUKS") === 0;
        if (!luks) {
            return {
                title: "Encryption",
                sub: "Security · disk encryption",
                kv: [
                    {
                        k: "Crypt target",
                        v: data.cryptUuid === "" ? "none — no device-mapper crypt device on this machine" : data.cryptUuid,
                        mono: data.cryptUuid !== ""
                    }
                ],
                dashed: {
                    what: "Not measured as a capability",
                    why: "punard registers no encryption capability, so there is no effective value, no source policy and no compliance state to explain. The only fact this device reports is the device-mapper UUID above — and on this build there is not one, because the development image boots unencrypted.",
                    when_: "The installer design makes LUKS2 the default for an installed device"
                }
            };
        }
        return {
            title: "Encryption",
            sub: "Security · disk encryption · dm-crypt",
            kv: [
                {
                    k: "Crypt target",
                    v: data.cryptUuid
                },
                {
                    k: "Format",
                    v: "LUKS2",
                    tone: "ok"
                },
                {
                    k: "Source",
                    v: "/sys/block/dm-0/dm/uuid — read once per open"
                }
            ],
            note: "This is an observation, not a compliance judgement: no capability governs disk encryption yet, so nothing here is remediated or audited."
        };
    }

    function viewSecureBoot(): var {
        var attestation = data.str(data.statusData, "attestation", "");
        var kv = [
            {
                k: "EFI variable",
                v: data.secureBootValue === "" ? "absent — this device did not boot under UEFI Secure Boot" : data.secureBootValue.toUpperCase(),
                mono: data.secureBootValue !== "",
                tone: data.secureBootValue === "enabled" ? "ok" : ""
            }
        ];
        if (attestation !== "") {
            kv.push({
                k: "Attestation",
                v: attestation.toUpperCase(),
                tone: attestation === "simulated" ? "warn" : ""
            });
        }
        return {
            title: "Secure Boot",
            sub: "Security · boot integrity",
            simTag: "Simulated · VM",
            kv: kv,
            dashed: {
                what: "Boot integrity is simulated in this build",
                why: "Nothing on this device measures the boot chain, and the control plane says so itself: the attestation it reports is the word \"simulated\", not a measurement. The plate carries the same dashed tag on this row for the same reason.",
                when_: "Measured boot and attestation are unscheduled"
            },
            note: "A simulated mechanism is labelled, never quietly counted as compliant."
        };
    }

    function viewFirewall(): var {
        var cap = data.capFor("security.firewall");
        var exp = data.explainFor("security.firewall");
        if (cap === null || exp === null) {
            return {
                title: "Firewall",
                sub: "Security · nftables",
                dashed: data.awaiting()
            };
        }
        var effective = data.stateWord(exp.effective_value);
        var observed = data.stateWord(cap.current_state);
        var card = data.explainCardFor("security.firewall");
        return {
            title: "Firewall",
            sub: "Security · " + data.str(cap, "managed_by", "punard") + " · " + data.str(cap, "verification", "unverified"),
            toggle: {
                show: true,
                on: effective === "enabled"
            },
            pill: exp.user_override_permitted === false ? {
                label: "Managed"
            } : null,
            grant: data.grantFor("security.firewall"),
            kv: [
                {
                    k: "Observed state",
                    v: observed.toUpperCase(),
                    tone: observed === "enabled" ? "ok" : "bad"
                },
                {
                    k: "Desired state",
                    v: data.stateWord(cap.desired_state).toUpperCase()
                },
                {
                    k: "Verification",
                    v: data.str(cap, "verification", "—").toUpperCase()
                },
                {
                    k: "Risk",
                    v: data.str(cap, "risk", "—").toUpperCase()
                },
                {
                    k: "Mutable",
                    v: cap.mutable === true ? "YES" : "NO"
                },
                {
                    k: "Requires reboot",
                    v: cap.requires_reboot === true ? "YES" : "NO"
                }
            ],
            explains: card === null ? [] : [card],
            actions: data.capabilityActions("security.firewall"),
            note: "If the firewall changes outside Punar, punard's reconcile pass observes the drift, remediates it where the effective policy says to, and writes an audit event either way. That is the promise this view makes before anything goes wrong, not after."
        };
    }

    // ---- AI --------------------------------------------------------

    function aiView(id: string): var {
        if (id === "agents")
            return data.viewAgents();
        if (id === "aipermissions")
            return data.viewAiPermissions();
        if (id === "models") {
            return {
                title: "Models",
                sub: "AI · no local model registry",
                dashed: {
                    what: "Not yet drawn",
                    why: "This device holds no model catalogue and registers no model capability, so there is no effective value to explain and nothing to choose between.",
                    when_: "Unscheduled · the design system applies its own production-claim rule to itself"
                }
            };
        }
        if (id === "mcp") {
            return {
                title: "MCP",
                sub: "AI · servers not observed yet",
                dashed: {
                    // NOT "Milestone 9+": M9 has shipped and did not
                    // bring MCP mediation, so pointing at it would read
                    // as a promise already kept. No milestone claims this
                    // one, and saying so is the honest answer (§1.22).
                    what: "Not yet observed · unscheduled",
                    why: "Nothing on this device mediates MCP traffic, so no server can be listed and none can be governed. The AI access ledger reserves this row and draws it dashed for exactly the same reason.",
                    when_: "Unscheduled · mediation before enumeration"
                },
                note: "An empty list would read as \"no servers\". That is a different claim from \"nothing is watching\", and only one of them is true."
            };
        }
        return null;
    }

    function viewAgents(): var {
        var rows = [];
        var sessions = Agents.sessions;
        for (var i = 0; i < sessions.length; i++) {
            var s = sessions[i];
            if (s === null || typeof s !== "object")
                continue;
            var live = s.status === "active" && s.classification === "managed";
            rows.push({
                name: data.str(s, "agent", data.str(s, "session_id", "session")),
                meta: data.str(s, "project", "—") + " · " + data.str(s, "session_id", "—") + " · " + data.titleCase(data.str(s, "classification", "—")) + " · " + data.titleCase(data.str(s, "status", "—")),
                tone: live ? "ok" : ""
            });
        }
        var detections = Agents.detections;
        for (var d = 0; d < detections.length; d++) {
            var det = detections[d];
            if (det === null || typeof det !== "object")
                continue;
            rows.push({
                name: data.str(det, "agent", "unknown"),
                meta: data.str(det, "detection_id", "—") + " · Unknown · Suspected AI",
                tone: "bad"
            });
        }
        return {
            title: "AI Agents",
            sub: "AI · registry · " + Agents.managedCount + " managed · " + Agents.observedCount + " observed · " + Agents.unknownCount + " unknown",
            pill: {
                label: "Punar + A · Full panel"
            },
            rows: rows,
            emptyRows: "No agent sessions · no suspected AI activity observed",
            actions: [
                {
                    hotkey: "O",
                    label: "Open AI panel",
                    tone: "ghost",
                    kind: "aipanel"
                }
            ],
            note: "Authority, network zones and the access ledger live in the full AI panel. This view is the registry at a glance — it reads the same /run/punar/agents.json the panel does, and duplicates none of its judgement."
        };
    }

    function viewAiPermissions(): var {
        var citation = Agents.policyCitation === "" ? (Status.enrolled ? "organization policy" : "personal defaults") : Agents.policyCitation;
        var scanned = data.shortTime(Agents.scannedAt);
        return {
            title: "Permissions",
            sub: "AI · authority model",
            pill: {
                label: "Punar + A · Full panel"
            },
            kv: [
                {
                    k: "Policy source",
                    v: citation
                },
                {
                    k: "Sessions",
                    v: Agents.managedCount + " managed · " + Agents.observedCount + " observed"
                },
                {
                    k: "Last detection pass",
                    v: scanned === "" ? "no pass recorded" : scanned
                }
            ],
            actions: [
                {
                    hotkey: "O",
                    label: "Open AI panel",
                    tone: "ghost",
                    kind: "aipanel"
                }
            ],
            note: "What each agent may access is rendered per session in the AI panel, next to what it actually accessed. Splitting that pair across two surfaces would weaken both, so this section links rather than copies. Authority always has a named source — above is this device's."
        };
    }

    // ---- DEVELOPER -------------------------------------------------

    function developerView(id: string): var {
        if (id === "projects")
            return data.viewProjects();
        if (id === "containers") {
            return {
                title: "Containers",
                sub: "Developer · owned by punar-env",
                dashed: {
                    what: "Not drawn here · punar-env owns it",
                    why: "Development environments are punar-env's job. System Control will not shell out to a container runtime to enumerate one: reading a socket nothing mediates would make this panel a second control plane, which is the one thing it must never become.",
                    when_: "Use punar-env up in a terminal"
                }
            };
        }
        if (id === "toolchains") {
            return {
                title: "Toolchains",
                sub: "Developer · not yet drawn",
                dashed: {
                    what: "Not yet drawn",
                    why: "No toolchain inventory exists on this device and no capability describes one.",
                    when_: "Unscheduled"
                }
            };
        }
        return null;
    }

    function viewProjects(): var {
        var rows = [];
        var wss = Hyprland.workspaces.values;
        for (var i = 0; i < wss.length; i++) {
            var w = wss[i];
            if (w.id < 0)
                continue; // special workspaces are scratchpads, not projects
            rows.push({
                name: w.name === "" ? String(w.id) : w.name,
                meta: "Workspace " + w.id + " · " + w.toplevels.values.length + " windows" + (w.focused ? " · FOCUSED" : ""),
                tone: ""
            });
        }
        return {
            title: "Projects",
            sub: "Developer · workspaces · live",
            pill: {
                label: "Punar + Tab · Overview"
            },
            rows: rows,
            emptyRows: "No workspaces open",
            note: "A workspace is a project. Renaming, layout and restoration belong to the overview; environments — toolchains, containers, credentials — belong to punar-env. System Control lists, and points at the surface that owns each."
        };
    }

    // ---- PRIVACY ---------------------------------------------------

    function privacyView(id: string): var {
        if (id === "connections") {
            return {
                title: "Connections",
                sub: "Privacy · who is talking to the network",
                dashed: {
                    what: "Local network observability is not available yet",
                    why: "Nothing on this device observes network destinations — punar-netd arrives in Milestone 12, and Punar does not guess at data it does not mediate. punarctl privacy connections answers with this same sentence, because it is the same answer.",
                    when_: "Milestone 12 · network privacy prototype"
                },
                kv: [
                    {
                        k: "What does exist",
                        v: "punarctl privacy ledger — what AI sessions accessed"
                    },
                    {
                        k: "And",
                        v: "punarctl privacy queries — every question an admin asked"
                    }
                ],
                note: "Those two commands are the real privacy surfaces on this device today, and they are the user's to read without privilege. This panel links to them rather than reprinting them, so there is one record and not two."
            };
        }
        if (id === "relay") {
            return {
                title: "Relay",
                sub: "Privacy · private relay",
                dashed: {
                    what: "Not implemented until Milestone 12",
                    why: "punarctl relay status answers with exactly this sentence. The relay is drawn dashed everywhere it appears in the design language because the complete path is not operating — implementation alone does not earn a solid line.",
                    when_: "Milestone 12 · network privacy prototype"
                }
            };
        }
        return null;
    }

    // ---- ORGANIZATION ----------------------------------------------

    function orgView(id: string): var {
        if (id === "enrollment" && !Status.enrolled)
            return null;
        if (id === "enrollment")
            return data.viewEnrollment();
        if (id === "compliance")
            return data.viewCompliance();
        if (id === "policies")
            return data.viewPolicies();
        if (id === "privilege")
            return data.viewPrivilege();
        return null;
    }

    function viewEnrollment(): var {
        if (!Status.enrolled)
            return null;
        var org = data.obj(data.statusData === null ? null : data.statusData.org);
        return {
            title: "Enrollment",
            sub: "Organization · enrolled",
            pill: {
                label: Status.orgName,
                dotTone: Status.state
            },
            kv: [
                {
                    k: "Organization",
                    v: data.str(org, "display_name", Status.orgName),
                    mono: false
                },
                {
                    k: "Domain",
                    v: data.str(org, "domain", "—")
                },
                {
                    k: "Compliance",
                    v: Status.label.toUpperCase(),
                    tone: Status.state
                }
            ],
            note: "Enrollment adds chrome; it never redraws the machine. Every section of this panel looked the same before it and looks the same after, with the organization's answers annotated on top."
        };
    }

    function viewCompliance(): var {
        var s = data.statusData;
        var c = data.obj(s === null ? null : s.compliance);
        var key = data.stateKey();
        if (c === null) {
            return {
                title: key,
                sub: Status.enrolled ? "Organization · spec §52 states" : "Security · this device's effective document",
                dashed: data.awaiting()
            };
        }
        var overall = data.str(c, "overall", "unknown");
        var rows = [];
        var caps = Array.isArray(c.capabilities) ? c.capabilities : [];
        for (var i = 0; i < caps.length; i++) {
            var e = caps[i];
            if (e === null || typeof e !== "object")
                continue;
            rows.push({
                name: data.capabilityLabel(data.str(e, "capability", "—")),
                meta: data.str(e, "capability", "—") + " · " + data.stateLabel(data.str(e, "state", "unknown")),
                tone: data.complianceTone(data.str(e, "state", ""))
            });
        }
        var remediated = typeof c.drift_remediated_total === "number" ? c.drift_remediated_total : 0;
        var lastRemediation = data.shortTime(data.str(c, "last_remediation_at", ""));
        return {
            title: key,
            sub: Status.enrolled ? "Organization · " + Status.orgName : "Security · measured against this device's own effective document",
            pill: {
                label: "Overall · " + data.stateLabel(overall),
                dotTone: data.complianceTone(overall)
            },
            rows: rows,
            emptyRows: "No capability is measured on this device",
            kv: [
                {
                    k: "Drift remediated",
                    v: remediated === 0 ? "none since daemon start" : String(remediated) + (lastRemediation === "" ? "" : " · last " + lastRemediation)
                }
            ],
            note: "These are the capabilities this device actually measures. The plate also sketches Boot Integrity, Disk Encryption, Private Relay, OS Update and Enterprise Identity rows — none of them is measured here, so none of them is listed here. A state table that reports a reading it did not observe is worse than a short one."
        };
    }

    function viewPolicies(): var {
        var entries = data.policyList;
        var personal = !Status.enrolled;
        if (entries.length === 0) {
            return {
                title: personal ? "Policy" : "Policies",
                sub: personal ? "Security · your effective document" : "Organization · effective document",
                dashed: data.awaiting()
            };
        }
        var rows = [];
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            if (e === null || typeof e !== "object")
                continue;
            var src = data.obj(e.source);
            rows.push({
                name: data.capabilityLabel(data.str(e, "path", "—")),
                meta: data.stateWord(e.effective_value) + " · " + data.str(src, "name", "?") + " · " + data.str(src, "policy_id", "?") + " · override " + (e.user_override_permitted === true ? "permitted" : "not permitted"),
                tone: data.complianceTone(data.str(e, "compliance_state", ""))
            });
        }
        return {
            title: personal ? "Policy" : "Policies",
            sub: (personal ? "Security · your effective merged document · " : "Organization · effective merged document · ") + rows.length + " governed paths",
            rows: rows,
            note: "Each row is one winning source after the layered merge. Opening the capability's own section shows the same information as a §40 explain card — same data, same order, and the same order punarctl policy explain prints it in."
        };
    }

    function viewPrivilege(): var {
        var grants = data.grantList;
        var scope = Status.enrolled ? "Organization" : "Security";
        if (grants.length === 0) {
            return {
                title: "Privilege",
                sub: scope + " · time-boxed elevation",
                kv: [
                    {
                        k: "Grants held",
                        v: "none"
                    }
                ],
                note: "You hold no privilege right now, and that is this device's resting state. There is no permanent local administrator on a Punar machine: privilege is a reason, a grant and a clock. Ask for one from the capability you actually need — the Firewall and Device views both carry the request — and a person answers the gate."
            };
        }
        var rows = [];
        var acts = [];
        for (var i = 0; i < grants.length; i++) {
            var g = grants[i];
            if (g === null || typeof g !== "object")
                continue;
            var mins = data.minutesLeft(data.str(g, "expires_at", ""));
            rows.push({
                name: data.capabilityLabel(data.str(g, "capability", "—")),
                meta: data.str(g, "grant_id", "—") + " · " + (mins < 0 ? "expiry unknown" : mins + " min left") + " · " + data.str(g, "reason", ""),
                tone: (mins >= 0 && mins <= 2) ? "warn" : "ok"
            });
            if (acts.length === 0) {
                acts.push({
                    hotkey: "R",
                    label: "Revoke grant",
                    tone: "danger",
                    kind: "revoke",
                    grantId: data.str(g, "grant_id", "")
                });
            }
        }
        return {
            title: "Privilege",
            sub: scope + " · " + grants.length + (grants.length === 1 ? " grant held" : " grants held"),
            rows: rows,
            actions: acts,
            note: "Privilege is never invisible and never permanent. The clock above is the grant's own, counted only while this window is open."
        };
    }
}
