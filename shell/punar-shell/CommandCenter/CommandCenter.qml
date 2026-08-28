pragma ComponentBehavior: Bound
// CommandCenter — the PUNAR+Space overlay, implementing the command-center
// card of docs/design/mockups/command-approval.html (Sect I, Plate D-003):
// centered 560px paper card on a warm ink-wash scrim, masthead row, sans
// input, glyph-tag result rows, selection = raise fill + 2px ink left rule,
// footer meta row carrying the principle line.
//
// ── WHAT CHANGED IN THIS PASS ────────────────────────────────────────────
// The M1 shell shipped this surface with a two-entry static table ("Open
// terminal" and a "System Control · arrives M3" stub) and no project verb,
// which left spec §75 step 3 ("Open Atlas") unperformable and Definition-
// of-Done item 4 unmet (milestone-13.md §6.1 gap 1). The action table is
// now REAL and it is DATA — see CommandCenter/Actions.qml for the taxonomy:
//
//   app       installed .desktop entries, ranked (Services/Apps.qml). The
//             browser the image ships (chromium) is reachable by name, by
//             its WebBrowser role, and from the empty overlay.
//   project   `Open Atlas` switches to — or creates — the named project
//             workspace through Hyprland's own typed dispatchers, and the
//             rename is what persists it through WorkspaceState's M2
//             contract (~/.local/state/punar/workspaces.json).
//   surface   the other first-party surfaces, addressed BY IPC TARGET
//             NAME (systemcontrol · notifications · shortcuts · aipanel ·
//             overview). The wiring is one object literal per surface, not
//             a branch, and a target this shell did not register renders
//             dashed with its milestone instead of pretending.
//   layout    the §13.5 presets, by name, through punar-layout.sh — the
//             consumer punar-binds.conf already names in prose.
//   wallpaper a shipped desktop field, committed as one typed preference;
//             no generic file picker, download or background process.
//   explain   a §40 policy question, answered inline from
//             `punarctl --json policy explain <path>`.
//
// ── THE LAW (spec §10, §12.2; D-003's register) ──────────────────────────
// "The command center never generates a shell string." Every row prints
// the typed capability or the concrete action it will invoke, in its right
// meta column, BEFORE Enter. Plain language resolves to one of the six
// kinds above and to nothing else — there is no free-text execution path
// in this file, deliberately, mirroring ipc.md §8's permanent non-goal.
//
// ── BUDGET (PERFORMANCE_BUDGETS.md §5; spec §6.3) ────────────────────────
// No timers except the 300 ms exit-animation one-shot this surface always
// had. No polling. Three short-lived processes exist and every one is
// user-initiated and at-most-once per session or per keystroke-committed
// action: the IPC target probe (first open), the policy-path index (first
// question typed), and one `punarctl policy explain` per question run.
//
// Toggled from Hyprland via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call commandcenter toggle

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Hyprland
import "." as Local
import "../Theme"
import "../Services"

DeferredSurfaceBase {
    id: root

    // Loader contract used by the isolated cost probe and the eventual
    // production lazy wrapper. Construction timing ends before show().
    property bool openOnReady: false
    property bool windowVisible: false

    // Non-empty while the §40 explain answer replaces the result list.
    property string explainPath: ""

    // Non-empty while a catalog application replaces the result list. The
    // row comes from the signed local catalog; the card comes from punard's
    // live pinned-metadata inspection.
    property string appId: ""
    property string appPhase: ""
    property var appRecord: null
    property string appFailure: ""
    // Browse mode expands this same lazy surface into the application library;
    // no second resident launcher/store process is introduced.
    property bool appBrowse: false

    // One honest line under the results — why a row did nothing, or why a
    // question has no answer on this device. Cleared by the next keystroke;
    // never on a timer.
    property string note: ""

    // Meta-row / label grammar (DESIGN_LANGUAGE.md §1): mono, tracked,
    // uppercase. Sizes follow the mockup CSS, rounded to whole px
    // (font.pixelSize is integral: 8.5 → 9, 8 → 8).
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.15)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    // The action taxonomy. A plain object — no window, no timer, no file
    // of its own. (The application index is the `Apps` singleton from
    // ../Services; it needs no instance.)
    Local.Actions {
        id: actions
    }

    function show(): void {
        if (!root.open)
            SurfaceTiming.begin("commandcenter");
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
        root.probeTargets();
    }

    Component.onCompleted: {
        SurfaceTiming.constructed("commandcenter");
        if (root.openOnReady)
            root.show();
    }

    function dismiss(): void {
        if (!root.open)
            return;
        root.open = false;
        root.explainPath = "";
        root.appId = "";
        root.appPhase = "";
        root.appRecord = null;
        root.appFailure = "";
        root.appBrowse = false;
        root.note = "";
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function toggle(): void {
        if (root.open)
            root.dismiss();
        else
            root.show();
    }

    // Public methods used by shell.qml's always-resident IPC proxy and by
    // surface-probe.qml. Keeping the target outside this object means asking
    // for `state` does not instantiate the surface it is measuring.
    function ipcState(): string {
        if (!root.open)
            return "closed";
        if (root.explainPath !== "")
            return "explain";
        if (root.appBrowse && root.appId === "")
            return "applications";
        return root.appId !== "" ? "application" : "open";
    }

    function ipcExplain(): string {
        if (root.explainPath === "")
            return "none";
        return explainCard.phase + " · " + root.explainPath;
    }

    function ipcQuery(text: string): string {
        root.show();
        win.setQuery(text);
        var top = win.results.length > 0 ? win.results[0] : null;
        return top === null ? "no-match" : (top.kind + " · " + top.meta);
    }

    function ipcApplication(id: string): string {
        root.show();
        root.appBrowse = true;
        root.askApp(id);
        return "catalog-app · " + id;
    }

    function ipcBrowseApplications(): string {
        root.show();
        root.appBrowse = true;
        win.setApplicationQuery("");
        return "applications";
    }

    function ipcRun(): string {
        if (!root.open)
            return "closed";
        if (root.appId !== "") {
            root.appAction();
            return "catalog-app · " + root.appId;
        }
        if (root.appBrowse) {
            applicationBrowser.activateCurrent();
            return "application-library";
        }
        var item = list.currentIndex >= 0 && list.currentIndex < win.results.length ? win.results[list.currentIndex] : null;
        if (item === null)
            return "no-match";
        var label = item.kind + " · " + item.meta;
        root.activate(item);
        return label;
    }

    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: {
            root.windowVisible = false;
            root.unloadRequested();
        }
    }

    // ---- IPC target probe -------------------------------------------------
    //
    // Which sibling surfaces exist in THIS shell is a fact, not an
    // assumption: `qs ipc show` lists the registered IpcHandler targets.
    // Run once, on the first open. If the listing cannot be produced — or
    // does not contain this very surface's own target, which would mean the
    // output was not understood — nothing is claimed and every surface row
    // stays solid with `targetState() === "unknown"`. Refusing to guess in
    // both directions is the §1.22 rule: a dashed row is a claim too.
    Process {
        id: probeProc
        stdout: StdioCollector {
            id: probeOut
            waitForEnd: true
            onStreamFinished: root.finishProbe()
        }
        // Completion is read from `running` rather than `exited`, because
        // the `exited` signal carries a QProcess::ExitStatus parameter whose
        // C++ type has no QML registration — a handler for it does not
        // compile cleanly (qmllint [signal-handler-parameters]). `running`
        // going false is the same moment, and both finishers below are
        // idempotent, so whichever of the two signals lands first wins.
        onRunningChanged: if (!probeProc.running)
            root.finishProbe()
    }

    function probeTargets(): void {
        if (actions.probed || probeProc.running)
            return;
        try {
            probeProc.command = ["qs", "-p", actions.shellPath, "ipc", "show"];
            probeProc.running = true;
        } catch (e) {
            console.warn("punar-shell: ipc target probe unavailable:", e);
        }
    }

    function parseTargets(text: string): var {
        var out = [];
        var lines = String(text).split("\n");
        for (var i = 0; i < lines.length; i++) {
            var raw = lines[i];
            if (raw.trim() === "")
                continue;
            var labelled = raw.match(/^\s*target\s+([A-Za-z0-9_.-]+)/);
            if (labelled) {
                out.push(labelled[1]);
                continue;
            }
            // A bare, unindented identifier line is the other shape a
            // listing can take; indented lines are that target's functions.
            if (!/^\s/.test(raw)) {
                var bare = raw.match(/^([A-Za-z0-9_.-]+)\s*$/);
                if (bare)
                    out.push(bare[1]);
            }
        }
        return out;
    }

    function finishProbe(): void {
        if (actions.probed)
            return;
        var found = root.parseTargets(probeOut.text);
        // Anchor: this surface is definitely registered. If it is not in
        // the parse, the parse is wrong and its absences mean nothing.
        if (found.indexOf("commandcenter") === -1)
            return;
        actions.availableTargets = found;
        actions.probed = true;
    }

    // ---- policy path index (spec §40) -------------------------------------
    //
    // The set of paths punard can explain comes from punard, once, the
    // first time a question is typed. Until then the seeds in Actions.qml
    // (the capability ids the daemon's backends register today) answer.
    property bool policyPathsTried: false

    Process {
        id: pathsProc
        stdout: StdioCollector {
            id: pathsOut
            waitForEnd: true
            onStreamFinished: root.finishPaths()
        }
        onRunningChanged: if (!pathsProc.running)
            root.finishPaths()
    }

    function refreshPolicyPaths(): void {
        if (root.policyPathsTried || pathsProc.running)
            return;
        root.policyPathsTried = true;
        try {
            pathsProc.command = ["punarctl", "--json", "policy", "effective"];
            pathsProc.running = true;
        } catch (e) {
            // No punarctl on a dev machine: the seeded paths still answer.
            console.warn("punar-shell: policy path index unavailable:", e);
        }
    }

    function finishPaths(): void {
        var parsed = root.parseLastLine(pathsOut.text);
        if (parsed === null || typeof parsed !== "object" || !Array.isArray(parsed.entries))
            return;
        var paths = [];
        for (var i = 0; i < parsed.entries.length; i++) {
            var entry = parsed.entries[i];
            if (entry && typeof entry.path === "string")
                paths.push(entry.path);
        }
        if (paths.length > 0)
            actions.livePaths = paths;
    }

    // ---- policy explain (spec §40) ----------------------------------------

    Process {
        id: explainProc
        stdout: StdioCollector {
            id: explainOut
            waitForEnd: true
            onStreamFinished: root.finishExplain()
        }
        stderr: StdioCollector {
            id: explainErr
            waitForEnd: true
            onStreamFinished: root.finishExplain()
        }
        onRunningChanged: if (!explainProc.running)
            root.finishExplain()
    }

    // punarctl's `--json` contract is ONE JSON line on stdout (the IPC
    // result verbatim). Parsing the last non-empty line — rather than the
    // whole buffer — keeps a second question from tripping over the first
    // answer if a collector is ever reused across runs.
    function parseLastLine(text: string): var {
        var lines = String(text).split("\n");
        for (var i = lines.length - 1; i >= 0; i--) {
            var line = lines[i].trim();
            if (line === "")
                continue;
            try {
                return JSON.parse(line);
            } catch (e) {
                return null;
            }
        }
        return null;
    }

    // Mirrors punarctl's `state_str` (crates/punarctl/src/model.rs): a JSON
    // string renders bare, anything else renders as JSON. The two clients
    // must not disagree about what a value looks like.
    function valueString(value: var): string {
        if (typeof value === "string")
            return value;
        try {
            return JSON.stringify(value);
        } catch (e) {
            return "unknown";
        }
    }

    function askExplain(path: string): void {
        // One question at a time: a second Enter abandons the first answer
        // rather than racing it.
        if (explainProc.running)
            explainProc.running = false;
        root.explainPath = path;
        explainCard.path = path;
        explainCard.phase = "asking";
        explainCard.failure = "";
        explainCard.effective = "";
        explainCard.sourceName = "";
        explainCard.policyId = "";
        explainCard.compliance = "";
        explainCard.overridePermitted = false;
        try {
            explainProc.command = ["punarctl", "--json", "policy", "explain", path];
            explainProc.running = true;
        } catch (e) {
            explainCard.failure = "punarctl is not available on this machine.";
            explainCard.phase = "failed";
        }
    }

    // Idempotent, and safe to call from any of the three completion
    // signals. An answer never regresses to a failure; a failure recorded
    // because the process ended before its stream did is upgraded the
    // moment the parseable line arrives.
    function finishExplain(): void {
        if (root.explainPath === "" || explainCard.phase === "answered")
            return;
        var parsed = root.parseLastLine(explainOut.text);
        if (parsed !== null && typeof parsed === "object" && parsed.source) {
            explainCard.effective = root.valueString(parsed.effective_value);
            explainCard.sourceName = typeof parsed.source.name === "string" ? parsed.source.name : "an unnamed source";
            explainCard.policyId = typeof parsed.source.policy_id === "string" ? parsed.source.policy_id : "unknown";
            explainCard.overridePermitted = parsed.user_override_permitted === true;
            explainCard.compliance = typeof parsed.compliance_state === "string" ? parsed.compliance_state : "";
            explainCard.phase = "answered";
            return;
        }
        if (explainProc.running)
            return; // the answer may still be on its way
        var why = String(explainErr.text).split("\n")[0].trim();
        explainCard.failure = why !== "" ? why : "punarctl returned no answer — punard may not be running on this machine.";
        explainCard.phase = "failed";
    }

    // ---- catalog application inspection + action ------------------------

    Process {
        id: appInspectProc
        stdout: StdioCollector {
            id: appInspectOut
            waitForEnd: true
            onStreamFinished: root.finishAppInspect()
        }
        stderr: StdioCollector {
            id: appInspectErr
            waitForEnd: true
            onStreamFinished: root.finishAppInspect()
        }
        onRunningChanged: if (!appInspectProc.running)
            root.finishAppInspect()
    }

    Process {
        id: appInstallProc
        stdout: StdioCollector {
            id: appInstallOut
            waitForEnd: true
            onStreamFinished: root.finishAppInstall()
        }
        stderr: StdioCollector {
            id: appInstallErr
            waitForEnd: true
            onStreamFinished: root.finishAppInstall()
        }
        onRunningChanged: if (!appInstallProc.running)
            root.finishAppInstall()
    }

    Process {
        id: appOpenProc
        stderr: StdioCollector {
            id: appOpenErr
            waitForEnd: true
        }
        Component.onCompleted: appOpenProc.exited.connect(function(exitCode) {
            root.finishAppOpen(exitCode);
        })
    }

    function firstError(text: string, fallback: string): string {
        var lines = String(text).split("\n");
        for (var i = 0; i < lines.length; i++) {
            var line = lines[i].trim();
            if (line !== "")
                return line;
        }
        return fallback;
    }

    function askApp(id: string): void {
        if (appInspectProc.running)
            appInspectProc.running = false;
        root.explainPath = "";
        root.appId = id;
        root.appPhase = "loading";
        root.appRecord = null;
        root.appFailure = "";
        try {
            appInspectProc.command = ["punarctl", "--json", "app", "show", id];
            appInspectProc.running = true;
        } catch (e) {
            root.appFailure = "punarctl is not available on this machine.";
            root.appPhase = "failed";
        }
    }

    function finishAppInspect(): void {
        if (root.appId === "" || (root.appPhase !== "loading" && root.appPhase !== "failed"))
            return;
        var parsed = root.parseLastLine(appInspectOut.text);
        if (parsed !== null && typeof parsed === "object" && parsed.app) {
            root.appRecord = parsed.app;
            root.appPhase = "ready";
            return;
        }
        if (appInspectProc.running)
            return;
        root.appFailure = root.firstError(appInspectErr.text, "The package source could not be verified.");
        root.appPhase = "failed";
    }

    function appAction(): void {
        if (root.appId === "")
            return;
        if (root.appPhase === "failed") {
            root.askApp(root.appId);
            return;
        }
        if (root.appPhase !== "ready" || root.appRecord === null)
            return;
        var source = String(root.appRecord.source || "");
        if (source === "web" || root.appRecord.installed === true) {
            root.appPhase = "opening";
            try {
                appOpenProc.command = ["punarctl", "app", "open", root.appId];
                appOpenProc.running = true;
            } catch (e) {
                root.appFailure = "The application launcher is unavailable.";
                root.appPhase = "failed";
            }
            return;
        }
        var inspection = root.appRecord.inspection;
        if (source !== "flatpak" || !inspection || inspection.verified !== true || inspection.containment !== "sandboxed") {
            root.appFailure = "This package needs a security review before Punar can install it.";
            root.appPhase = "failed";
            return;
        }
        var digest = String(inspection.metadata_sha256 || "");
        if (digest.length !== 64) {
            root.appFailure = "The verified metadata digest is missing.";
            root.appPhase = "failed";
            return;
        }
        root.appPhase = "installing";
        try {
            appInstallProc.command = [
                "punarctl", "--json", "app", "install", root.appId, "--yes",
                "--confirm-metadata-sha256", digest
            ];
            appInstallProc.running = true;
        } catch (e) {
            root.appFailure = "The application installer is unavailable.";
            root.appPhase = "failed";
        }
    }

    function finishAppInstall(): void {
        if (root.appId === "" || (root.appPhase !== "installing" && root.appPhase !== "failed"))
            return;
        var parsed = root.parseLastLine(appInstallOut.text);
        if (parsed !== null && typeof parsed === "object" && parsed.installed === true) {
            var updated = ({});
            for (var key in root.appRecord)
                updated[key] = root.appRecord[key];
            updated.installed = true;
            root.appRecord = updated;
            root.appPhase = "ready";
            return;
        }
        if (appInstallProc.running)
            return;
        root.appFailure = root.firstError(appInstallErr.text, "The install did not complete.");
        root.appPhase = "failed";
    }

    function finishAppOpen(exitCode: int): void {
        if (root.appId === "" || root.appPhase !== "opening")
            return;
        if (exitCode === 0) {
            root.dismiss();
            return;
        }
        root.appFailure = root.firstError(appOpenErr.text, "The application could not start.");
        root.appPhase = "failed";
    }

    // ---- row construction -------------------------------------------------

    function titleCase(name: string): string {
        var words = String(name).split(" ");
        for (var i = 0; i < words.length; i++) {
            if (words[i].length > 0)
                words[i] = words[i].charAt(0).toUpperCase() + words[i].slice(1);
        }
        return words.join(" ");
    }

    function projectRow(name: string, group: string, existing: bool): var {
        var id = actions.plannedWorkspaceId(name);
        return {
            "group": group,
            "glyph": "PR",
            "name": "Open " + root.titleCase(name),
            "meta": "OpenProject(" + name + ") · " + (existing ? "Workspace " : "New workspace ") + id,
            "cap": true,
            "kind": "project",
            "state": "shipped",
            "arg": name
        };
    }

    function appRow(entry: var, group: string): var {
        return {
            "group": group,
            "glyph": Apps.glyphFor(entry.name),
            "icon": Apps.iconSource(entry),
            "name": Apps.displayName(entry),
            "meta": "Launch(" + Apps.bareId(entry) + ")",
            "cap": false,
            "kind": "app",
            "state": "shipped",
            "arg": "",
            "entry": entry
        };
    }

    function catalogAppRow(app: var, group: string): var {
        return {
            "group": group,
            "glyph": Apps.glyphFor(String(app.name || app.id)),
            "icon": Catalog.iconSource(app),
            "name": String(app.name),
            "meta": "Application(" + String(app.id) + ") · on demand",
            "cap": true,
            "kind": "catalog-app",
            "state": "shipped",
            "arg": String(app.id)
        };
    }

    // A role row names what the thing IS on this machine ("Open browser"
    // → Chromium), so the browser is one keystroke away even from an empty
    // field. Returns null when the machine has no such application, which
    // is the honest answer and draws no row at all.
    function roleRow(entry: var, glyph: string, label: string, group: string): var {
        if (entry === null || entry === undefined)
            return null;
        return {
            "group": group,
            "glyph": glyph,
            "icon": Apps.iconSource(entry),
            "name": label + " · " + Apps.displayName(entry),
            "meta": "Launch(" + Apps.bareId(entry) + ")",
            "cap": true,
            "kind": "app",
            "state": "shipped",
            "arg": "",
            "entry": entry
        };
    }

    function applicationBrowserRow(group: string): var {
        return {
            "group": group,
            "glyph": "AP",
            "icon": "",
            "name": "Browse applications",
            "meta": "ApplicationLibrary(installed + approved)",
            "cap": true,
            "kind": "app-browser",
            "state": "shipped",
            "arg": ""
        };
    }

    function surfaceRow(surface: var, group: string): var {
        var state = actions.targetState(surface.target);
        // An absent surface's tail is just its milestone: the dashed glyph
        // already says "outside the current production claim"
        // (DESIGN_LANGUAGE §7), and a short tail keeps the typed action —
        // the half the law requires — from being elided away.
        var tail = state === "absent" ? surface.milestone : surface.chord;
        return {
            "group": group,
            "glyph": surface.glyph,
            "name": String(surface.name),
            "meta": "Surface(" + surface.target + ") · " + tail,
            "cap": true,
            "kind": "surface",
            "state": state,
            "arg": String(surface.target),
            "milestone": String(surface.milestone)
        };
    }

    function layoutRow(layout: var, group: string): var {
        return {
            "group": group,
            "glyph": "LY",
            "name": String(layout.name),
            "meta": "SetLayout(" + layout.preset + ") · " + layout.note,
            "cap": true,
            "kind": "layout",
            "state": "shipped",
            "arg": String(layout.preset)
        };
    }

    function policyRow(path: string, group: string): var {
        return {
            "group": group,
            "glyph": "PO",
            "name": "Explain " + path,
            "meta": "PolicyExplain(" + path + ")",
            "cap": true,
            "kind": "explain",
            "state": "shipped",
            "arg": path
        };
    }

    function wallpaperRow(wallpaper: var, group: string): var {
        var current = String(wallpaper.id) === WallpaperState.activeId;
        return {
            "group": group,
            "glyph": "WP",
            "name": String(wallpaper.name),
            "meta": "SetWallpaper(" + wallpaper.id + ")" + (current ? " · current" : ""),
            "cap": true,
            "kind": "wallpaper",
            "state": "shipped",
            "arg": String(wallpaper.id)
        };
    }

    function matches(haystack: string, q: string): bool {
        return q === "" || String(haystack).toLowerCase().indexOf(q) !== -1;
    }

    // Build the result rows for one query.
    //
    // `deps` carries the live models this result set depends on (the
    // application index, the probe answer, the compositor's workspaces and
    // the stored workspace names). It exists so the binding in `win`
    // re-evaluates when any of them changes — the values are read through
    // `apps` and `actions`, not from the array.
    function buildResults(query: string, deps: var): var {
        void deps;
        var q = String(query).trim();
        var lower = q.toLowerCase();
        var out = [];
        var i = 0;

        if (q === "") {
            // Empty state (mockup 01): what this device has, not a menu.
            // Installed and catalog applications are visible without the
            // reader guessing a name first. This is the quick browse path;
            // typing still ranks the full live indexes.
            var known = actions.knownProjects();
            for (i = 0; i < known.length && i < 4; i++)
                out.push(root.projectRow(known[i].name, "Recent", true));
            var shownIds = ({});
            var browserRow = root.roleRow(Apps.browser, "BR", "Open browser", "Suggested");
            if (browserRow !== null) {
                out.push(browserRow);
                shownIds[Apps.bareId(Apps.browser)] = true;
            }
            var termRow = root.roleRow(Apps.terminal, "TE", "Open terminal", "Suggested");
            if (termRow !== null) {
                out.push(termRow);
                shownIds[Apps.bareId(Apps.terminal)] = true;
            }
            out.push(root.applicationBrowserRow("Suggested"));

            var installed = Apps.search("", 0);
            var installedGroup = "Installed · " + installed.length;
            var installedShown = 0;
            for (i = 0; i < installed.length && installedShown < 8; i++) {
                var installedId = Apps.bareId(installed[i]);
                if (shownIds[installedId] === true)
                    continue;
                out.push(root.appRow(installed[i], installedGroup));
                shownIds[installedId] = true;
                installedShown++;
            }

            var available = Catalog.search("", 8);
            var availableGroup = "Get applications · " + Catalog.entries.length;
            for (i = 0; i < available.length; i++)
                out.push(root.catalogAppRow(available[i], availableGroup));

            for (i = 0; i < actions.surfaces.length; i++)
                out.push(root.surfaceRow(actions.surfaces[i], "System"));
            return out;
        }

        // ---- role verbs, surfaces, layouts ----
        //
        // Named verbs rank above projects: "open browser" must reach the
        // browser, not offer to create a workspace called `browser`.
        var browserHit = root.roleRow(Apps.browser, "BR", "Open browser", "Actions");
        if (browserHit !== null && (root.matches("open browser web internet", lower) || root.matches(String(Apps.browser.name), lower)))
            out.push(browserHit);
        var termHit = root.roleRow(Apps.terminal, "TE", "Open terminal", "Actions");
        if (termHit !== null && (root.matches("open terminal shell console", lower) || root.matches(String(Apps.terminal.name), lower)))
            out.push(termHit);
        if (root.matches("applications apps app store install software get", lower))
            out.push(root.applicationBrowserRow("Actions"));

        for (i = 0; i < actions.surfaces.length; i++) {
            var surface = actions.surfaces[i];
            if (root.matches(surface.name, lower) || root.matches(surface.keywords, lower) || root.matches(surface.target, lower))
                out.push(root.surfaceRow(surface, "Actions"));
        }

        for (i = 0; i < actions.layouts.length; i++) {
            var layout = actions.layouts[i];
            if (root.matches(layout.name + " " + layout.note + " layout preset", lower))
                out.push(root.layoutRow(layout, "Actions"));
        }

        // A wallpaper is a finite installed preference, not an arbitrary
        // command or file path. Typing "wallpaper", a title, or its visual
        // intent exposes every matching shipped choice.
        var wallpapers = WallpaperState.catalog;
        for (i = 0; i < wallpapers.length; i++) {
            var wallpaper = wallpapers[i];
            if (root.matches("wallpaper background desktop " + wallpaper.id + " " + wallpaper.name + " " + wallpaper.intent, lower))
                out.push(root.wallpaperRow(wallpaper, "Wallpaper"));
        }

        var namedVerbs = out.length;

        // ---- projects (spec §75 step 3) ----
        var argument = actions.projectArgument(q);
        var normalized = actions.normalizeProject(argument);
        var projects = actions.knownProjects();
        var exact = false;
        for (i = 0; i < projects.length; i++) {
            if (projects[i].name === normalized)
                exact = true;
            if (root.matches(projects[i].name, argument.toLowerCase()))
                out.push(root.projectRow(projects[i].name, "Projects", true));
        }
        // "Open Atlas" on a device that has never had an Atlas workspace is
        // the demo's own case: offer to create it, and say so in the meta.
        // Two conditions, both deliberate: the reader must have used a
        // project verb (a bare "chrom" is a search, not an intent to make a
        // workspace), and no named verb may have answered already (typing
        // "open terminal" means the terminal).
        if (normalized !== "" && !exact && namedVerbs === 0 && actions.projectVerbUsed(q))
            out.push(root.projectRow(normalized, "Projects", false));

        // ---- applications ----
        var matchedApps = Apps.search(lower, 8);
        for (i = 0; i < matchedApps.length; i++)
            out.push(root.appRow(matchedApps[i], "Applications"));
        var catalogApps = Catalog.search(lower, 4);
        for (i = 0; i < catalogApps.length; i++)
            out.push(root.catalogAppRow(catalogApps[i], "Get applications"));

        // ---- policy (spec §40) ----
        var asked = actions.isQuestion(q) ? actions.questionPath(q) : "";
        if (asked !== "")
            out.push(root.policyRow(asked, "Policy"));
        var table = actions.policyPaths;
        for (i = 0; i < table.length; i++) {
            var path = String(table[i].path);
            if (path === asked)
                continue;
            if (root.matches(path + " " + table[i].keywords, lower))
                out.push(root.policyRow(path, "Policy"));
        }

        return out;
    }

    // ---- activation -------------------------------------------------------

    function activate(item: var): void {
        if (item === null || item === undefined)
            return;
        root.note = "";
        switch (item.kind) {
        case "app-browser":
            root.appBrowse = true;
            win.setApplicationQuery("");
            return;
        case "app":
            if (Apps.launch(item.entry))
                root.dismiss();
            else
                root.note = "That application could not be launched";
            return;
        case "catalog-app":
            root.askApp(item.arg);
            return;
        case "project":
            if (actions.openProject(item.arg) >= 0)
                root.dismiss();
            else
                root.note = "Not a valid project name · letters, digits, spaces, - and _";
            return;
        case "surface":
            // A surface this shell did not register is named, not opened —
            // the row already says so, and pressing Enter repeats it rather
            // than silently doing nothing (spec §1.22).
            if (item.state === "absent") {
                root.note = item.name + " is not in this build · " + item.milestone;
                return;
            }
            if (actions.openSurface(item.arg))
                root.dismiss();
            else
                root.note = "Could not reach " + item.arg;
            return;
        case "layout":
            if (actions.applyLayout(item.arg))
                root.dismiss();
            else
                root.note = "Layout preset unavailable on this machine";
            return;
        case "wallpaper":
            if (WallpaperState.setWallpaper(item.arg))
                root.dismiss();
            else
                root.note = "That wallpaper is not installed or the preference cannot be written";
            return;
        case "explain":
            // The answer replaces the list; the overlay stays open because
            // an answer the reader cannot read is not an answer.
            root.askExplain(item.arg);
            return;
        default:
            root.note = "Unknown action kind · " + item.kind;
            return;
        }
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
        WlrLayershell.keyboardFocus: root.open ? WlrKeyboardFocus.Exclusive : WlrKeyboardFocus.None

        function setQuery(text: string): void {
            queryInput.text = text;
            root.appBrowse = false;
            root.explainPath = "";
            root.appId = "";
            root.appPhase = "";
            root.appRecord = null;
            root.note = "";
        }

        function setApplicationQuery(text: string): void {
            root.explainPath = "";
            root.appId = "";
            root.appPhase = "";
            root.appRecord = null;
            root.appFailure = "";
            root.note = "";
            queryInput.text = text;
            queryInput.forceActiveFocus();
        }

        onVisibleChanged: {
            if (win.visible) {
                queryInput.text = "";
                queryInput.forceActiveFocus();
            }
        }

        // Live models this result set is derived from. Listed explicitly so
        // the binding re-evaluates when any of them changes — the probe
        // answering, an application appearing, a workspace being renamed.
        readonly property var resultDeps: [Apps.entries, Catalog.entries, actions.availableTargets, Hyprland.workspaces.values, WorkspaceState.pendingNames, WallpaperState.activeId]

        readonly property var results: root.buildResults(queryInput.text, win.resultDeps)
        onResultsChanged: list.currentIndex = win.results.length > 0 ? 0 : -1

        // Warm ink-wash scrim at 22% (mockup .scrim) — motion is the 300ms
        // token curve, only on show/hide (§4: fluid, not decorative).
        Rectangle {
            id: scrim
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

        // ---- the command card (mockup .cc) ----
        Rectangle {
            id: card

            width: root.appBrowse ? Math.min(900, win.width * 0.90) : Math.min(560, win.width * 0.78)
            anchors.horizontalCenter: parent.horizontalCenter
            y: root.open ? win.height * 0.11 : (win.height * 0.11) - 10
            height: cardColumn.implicitHeight
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder
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
                            color: Theme.shellFg
                        }
                        Meta {
                            text: " · Command"
                        }
                    }

                    // ORG CHROME, AND ONLY WHEN THERE IS AN ORG. This row read
                    // "LOCAL · COMPLIANT" on every personal machine: "Local"
                    // was a hardcoded placeholder and "Compliant" came from an
                    // empty compliance string falling through a shared case
                    // arm. Both halves were furniture implying an authority
                    // that does not exist (DESIGN_LANGUAGE.md section 8.1), on
                    // the surface a person opens most often.
                    //
                    // Enrollment ADDS this row; it does not restructure the
                    // masthead, because the row is anchored right and the
                    // title beside it does not move when it is absent.
                    Row {
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        spacing: 5
                        visible: Status.enrolled && Status.label !== ""

                        Rectangle {
                            anchors.verticalCenter: parent.verticalCenter
                            width: 5
                            height: 5
                            radius: 2.5
                            color: Status.color // live via status.json (M5)
                        }
                        Meta {
                            anchors.verticalCenter: parent.verticalCenter
                            // The organization's own name, not a placeholder:
                            // if this row is drawn at all there IS an org, and
                            // naming it is the honest thing to show.
                            text: Status.orgName + " · " + Status.label
                        }
                    }

                    Rectangle {
                        anchors.left: parent.left
                        anchors.right: parent.right
                        anchors.bottom: parent.bottom
                        height: Theme.hairline
                        color: Theme.shellBorder
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
                        color: Theme.shellFg
                        clip: true

                        onTextChanged: {
                            root.note = "";
                            root.explainPath = "";
                            root.appId = "";
                            root.appPhase = "";
                            root.appRecord = null;
                            // The set of explainable paths is fetched from
                            // punard once, the first time a question is
                            // actually asked — never on open, never on a
                            // timer.
                            if (actions.isQuestion(queryInput.text))
                                root.refreshPolicyPaths();
                        }

                        Keys.onPressed: function (event) {
                            switch (event.key) {
                            case Qt.Key_Escape:
                                // First Escape leaves the answer, second closes.
                                if (root.explainPath !== "")
                                    root.explainPath = "";
                                else if (root.appId !== "") {
                                    root.appId = "";
                                    root.appPhase = "";
                                    root.appRecord = null;
                                    root.appFailure = "";
                                }
                                else if (root.appBrowse) {
                                    root.appBrowse = false;
                                    queryInput.text = "";
                                }
                                else
                                    root.dismiss();
                                event.accepted = true;
                                break;
                            case Qt.Key_Down:
                                if (root.appId === "" && root.appBrowse)
                                    applicationBrowser.move(1);
                                else if (root.appId === "")
                                    list.incrementCurrentIndex();
                                root.note = "";
                                event.accepted = true;
                                break;
                            case Qt.Key_Up:
                                if (root.appId === "" && root.appBrowse)
                                    applicationBrowser.move(-1);
                                else if (root.appId === "")
                                    list.decrementCurrentIndex();
                                root.note = "";
                                event.accepted = true;
                                break;
                            case Qt.Key_Return:
                            case Qt.Key_Enter:
                                if (root.appId !== "")
                                    root.appAction();
                                else if (root.appBrowse)
                                    applicationBrowser.activateCurrent();
                                else
                                    root.activate(list.currentIndex >= 0 && list.currentIndex < win.results.length ? win.results[list.currentIndex] : null);
                                event.accepted = true;
                                break;
                            }
                        }
                    }

                    Text {
                        anchors.fill: queryInput
                        visible: queryInput.text === ""
                        text: root.appBrowse
                            ? "Search installed and approved applications"
                            : "Type — an app, a setting, a project, or plain intent"
                        font.family: Theme.fontSans
                        font.pixelSize: 17
                        font.weight: 400
                        color: Theme.shellInputBorder
                        elide: Text.ElideRight
                    }
                }

                // Results (mockup .cc .body, max-height 300).
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.shellBorder
                }

                // The §40 answer takes the body when a question was run.
                Local.ExplainCard {
                    id: explainCard
                    width: parent.width
                    height: root.explainPath !== "" ? implicitHeight : 0
                    visible: root.explainPath !== ""
                }

                Local.AppInstallCard {
                    id: appCard
                    width: parent.width
                    height: root.appId !== "" ? implicitHeight : 0
                    visible: root.appId !== ""
                    phase: root.appPhase === "" ? "loading" : root.appPhase
                    record: root.appRecord
                    iconSource: Catalog.iconSource(Catalog.byId(root.appId))
                    failure: root.appFailure
                    onActionRequested: root.appAction()
                }

                Local.ApplicationBrowser {
                    id: applicationBrowser
                    width: parent.width
                    // Keep the whole card inside short and side-by-side
                    // displays. The browser itself scrolls; shell chrome does
                    // not fall beyond the output edge.
                    height: root.appBrowse && root.appId === ""
                        ? Math.max(240, Math.min(implicitHeight, win.height * 0.62))
                        : 0
                    visible: root.appBrowse && root.appId === ""
                    query: queryInput.text
                    onLaunchRequested: function(entry) {
                        if (Apps.launch(entry))
                            root.dismiss();
                        else
                            root.note = "That application could not be launched";
                    }
                    onCatalogRequested: function(id) {
                        root.askApp(id);
                    }
                }

                ListView {
                    id: list

                    width: parent.width
                    height: root.explainPath !== "" || root.appId !== "" || root.appBrowse ? 0 : Math.min(contentHeight, 300)
                    visible: root.explainPath === "" && root.appId === "" && !root.appBrowse
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
                        color: Theme.shellMuted

                        Rectangle {
                            anchors.left: parent.left
                            anchors.top: parent.top
                            anchors.bottom: parent.bottom
                            width: 2
                            color: Theme.shellFg
                        }
                    }

                    delegate: Item {
                        id: row

                        required property int index
                        required property var modelData

                        readonly property bool sel: row.ListView.isCurrentItem
                        readonly property bool hovered: rowMouse.containsMouse
                        // DESIGN_LANGUAGE §7: a dashed stroke marks a
                        // mechanism outside the current production claim.
                        readonly property bool unshipped: row.modelData.state === "absent"

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
                            // monochrome (mockup register 02). An unshipped
                            // row's square is dashed instead of solid.
                            Item {
                                anchors.verticalCenter: parent.verticalCenter
                                width: 26
                                height: 26

                                Rectangle {
                                    anchors.fill: parent
                                    visible: !row.unshipped
                                    radius: Theme.radiusTag
                                    color: Theme.shellSurface
                                    border.width: Theme.hairline
                                    border.color: row.sel || row.hovered ? Theme.shellFg : Theme.shellBorder
                                }

                                Canvas {
                                    anchors.fill: parent
                                    visible: row.unshipped
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
                                }

                                Image {
                                    id: rowIcon
                                    anchors.fill: parent
                                    anchors.margins: 5
                                    source: String(row.modelData.icon || "")
                                    fillMode: Image.PreserveAspectFit
                                    smooth: true
                                }

                                Text {
                                    anchors.centerIn: parent
                                    visible: rowIcon.source.toString() === "" || rowIcon.status !== Image.Ready
                                    text: row.modelData.glyph
                                    font.family: Theme.fontMono
                                    font.pixelSize: 8
                                    font.weight: 600
                                    font.letterSpacing: Theme.tracking(8, 0.06)
                                    color: row.unshipped ? Theme.shellInk3 : (row.sel || row.hovered ? Theme.shellFg : Theme.shellInk2)
                                }
                            }

                            Text {
                                anchors.verticalCenter: parent.verticalCenter
                                width: Math.max(0, parent.width - 38)
                                text: row.modelData.name
                                font.family: Theme.fontSans
                                font.pixelSize: 15 // mockup 14.5px
                                font.weight: 500
                                color: row.unshipped ? Theme.shellInk3 : Theme.shellFg
                                elide: Text.ElideRight
                            }
                        }

                        // Right meta: the typed capability or the concrete
                        // action this row will invoke — ALWAYS, for every
                        // row (spec §10, §12.2; D-003 register 03).
                        Meta {
                            id: rowMeta
                            anchors.right: parent.right
                            anchors.rightMargin: 16
                            anchors.verticalCenter: parent.verticalCenter
                            width: Math.min(implicitWidth, row.width * 0.56)
                            font.weight: 500
                            font.letterSpacing: Theme.tracking(9, 0.1)
                            horizontalAlignment: Text.AlignRight
                            // Right-elide: the typed action leads the string
                            // and must survive truncation (§10, §12.2).
                            elide: Text.ElideRight
                            text: row.modelData.meta
                            color: row.modelData.cap && !row.unshipped ? Theme.shellInk2 : Theme.shellInk3
                        }

                        MouseArea {
                            id: rowMouse

                            anchors.fill: parent
                            hoverEnabled: true
                            cursorShape: Qt.PointingHandCursor
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
                    visible: root.explainPath === "" && root.appId === "" && !root.appBrowse && win.results.length === 0

                    Meta {
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.weight: 500
                        text: actions.isQuestion(queryInput.text) ? "No policy on this device answers that" : "No matches"
                    }
                }

                // The honest note line: why the last Enter did what it did.
                Item {
                    width: parent.width
                    height: root.note !== "" ? 28 : 0
                    visible: root.note !== ""

                    Meta {
                        anchors.left: parent.left
                        anchors.leftMargin: 16
                        anchors.right: parent.right
                        anchors.rightMargin: 16
                        anchors.verticalCenter: parent.verticalCenter
                        font.weight: 500
                        font.letterSpacing: Theme.tracking(9, 0.1)
                        elide: Text.ElideRight
                        text: root.note
                    }
                }

                // Footer meta row (mockup .cc .foot) with the principle line.
                Rectangle {
                    width: parent.width
                    height: Theme.hairline
                    color: Theme.shellBorder
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
                        text: root.explainPath !== "" || root.appId !== "" || root.appBrowse
                            ? "Esc Back · ↑↓ Navigate · Click or ↵ Open"
                            : "↑↓ Navigate · Click or ↵ Open · Esc Close"
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
