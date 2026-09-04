pragma Singleton
pragma ComponentBehavior: Bound
// Apps — the installed-application index behind the command center.
//
// Wraps Quickshell's `DesktopEntries` (the freedesktop application index,
// already filtered of Hidden/NoDisplay entries) and adds the three things
// a launcher actually needs and the plate asks for:
//
//   1. RANKED SEARCH. `search(query)` scores name/generic-name/keywords/
//      comment/id and returns entries best-first, so "browser" reaches the
//      one generic Punar entry rather than a vendor implementation helper.
//   2. ROLE RESOLUTION. `browser` and `terminal` resolve the entry that
//      plays that role on THIS machine — by id first (`chromium` is what
//      the punar-desktop image installs), then by heuristic name, then by
//      the freedesktop `Categories` key (`WebBrowser` / `TerminalEmulator`).
//      No hardcoded argv, no assumption that chromium is present: a
//      machine with only Firefox resolves to Firefox, and a machine with
//      no browser at all resolves to null and the command center says so.
//   3. LAUNCH. Quickshell parses the desktop file's `Exec` key into argv.
//      GUI entries use `DesktopEntry.execute()`; `Terminal=true` entries pass
//      that argv to Punar's Foot adapter because freedesktop leaves terminal
//      selection to the desktop environment. THE SHELL NEVER BUILDS A SHELL
//      STRING (spec §10, §12.2; D-003 register).
//
// A SINGLETON, like every other type in Services/: the index has no
// per-instance state and every surface that ever wants to launch something
// should share one wrapper over one DesktopEntries model. Registered in
// `Services/qmldir` — the ONE line this pass adds outside its own files,
// and it is additive: a directory import does NOT expose a .qml file that
// the directory's qmldir omits (verified the hard way — qmllint resolves
// such a type happily and the QML engine then refuses it at load with
// "Apps is not a type").
//
// Budget: zero timers, zero polling. `DesktopEntries` is inotify-backed by
// Quickshell; every property here is a binding over its live model
// (PERFORMANCE_BUDGETS.md §5 — the shell renders on demand).

import QtQuick
import Quickshell
import Quickshell.Wayland

Singleton {
    id: root

    // Live model of installed, visible applications.
    // Distribution packages occasionally expose implementation launchers as
    // ordinary applications. Foot is the important example: `foot.desktop`,
    // `footclient.desktop`, and `foot-server.desktop` are three ways to reach
    // one terminal product. Thunar also publishes a settings helper which is
    // not a working standalone application in Punar. A person should see the
    // products, not their process topology. This is intentionally an exact-id
    // list, never a fuzzy name filter.
    readonly property var rawEntries: DesktopEntries.applications.values
    readonly property var entries: root.productEntries(root.rawEntries)
    readonly property var hiddenProductEntryIds: [
        "footclient",
        "foot-server",
        "chromium",
        "chromium-browser",
        "org.chromium.chromium",
        "thunar-settings",
        "thunar-bulk-rename",
        "xfce4-about",
        "bssh",
        "bvnc",
        "avahi-discover"
    ]

    // DesktopEntries updates asynchronously after an installer writes or
    // removes a desktop file. Keep the result of the just-completed typed
    // transaction as an immediate, session-local truth so returning from an
    // install card can never offer the same app for installation again.
    // A monotonic revision beside the map gives every dependent QML binding
    // a deterministic change notification.
    readonly property var catalogInstallState: ({})
    property int catalogInstallRevision: 0

    function recordCatalogInstallState(id: string, installed: bool): void {
        var normalized = root.normalizedWindowId(id);
        if (normalized === "")
            return;
        root.catalogInstallState[normalized] = installed;
        root.catalogInstallRevision++;
    }

    // Role candidates, most-specific first. `punar-browser` is the generic
    // product entry shipped by Punar; vendor browser entries remain fallbacks
    // for user-installed alternatives, never duplicate rows for the built-in
    // implementation.
    readonly property var browserIds: ["punar-browser", "firefox", "org.mozilla.firefox", "firefox-esr", "chromium", "chromium-browser", "org.chromium.Chromium"]
    readonly property var terminalIds: ["foot", "footclient", "org.codeberg.dnkl.foot"]

    readonly property string browserCategory: "WebBrowser"
    readonly property string terminalCategory: "TerminalEmulator"

    function productEntries(entries: var): var {
        var out = [];
        for (var i = 0; i < entries.length; i++) {
            var id = root.bareId(entries[i]);
            if (root.hiddenProductEntryIds.indexOf(id) !== -1)
                continue;
            out.push(entries[i]);
        }
        return out;
    }

    // Product names may deliberately differ from a package's desktop-file
    // name. Keep aliases here so every launcher/settings surface agrees.
    function genericNameForId(id: string): string {
        var value = String(id).trim().toLowerCase();
        if (value.length > 8 && value.slice(-8) === ".desktop")
            value = value.slice(0, -8);
        if (value === "foot" || value === "footclient" || value === "foot-server"
                || value === "org.codeberg.dnkl.foot")
            return "Terminal";
        if (value === "punar-browser" || value === "chromium" || value === "chromium-browser" || value === "org.chromium.chromium")
            return "Browser";
        if (value === "nvim")
            return "Terminal Editor";
        if (value === "geany")
            return "Text Editor";
        if (value === "thunar")
            return "Files";
        if (value === "htop")
            return "System Monitor";
        if (value === "lstopo")
            return "Hardware Information";
        return "";
    }

    function displayName(entry: var): string {
        var generic = root.genericNameForId(root.bareId(entry));
        if (generic !== "")
            return generic;
        return String(entry && entry.name ? entry.name : "Application");
    }

    // Foreign-toplevel and Hyprland events expose technical app ids, not
    // desktop entries. Keep the same product vocabulary in the bar and in
    // window actions even when the app did not originate in the launcher.
    function displayNameForAppId(appId: string): string {
        var value = String(appId).trim();
        var generic = root.genericNameForId(value);
        if (generic !== "")
            return generic;
        var entry = root.entryById(value);
        if (entry !== null)
            return root.displayName(entry);
        return value === "" ? "Application" : value;
    }

    function windowTitleForAppId(appId: string, title: string): string {
        var value = String(title).trim();
        if (root.genericNameForId(appId) === "Files")
            value = value.replace(/\s*[-–]\s*Thunar\s*$/i, "");
        return value;
    }

    function iconSource(entry: var): string {
        if (entry === null || entry === undefined)
            return "";
        var icon = String(entry.icon || "");
        return icon === "" ? "" : Quickshell.iconPath(icon, true);
    }

    // The resolved role entries (null when the machine has none — the
    // caller must render that honestly rather than offer a dead row).
    readonly property var browser: root.resolveRole(root.browserIds, root.browserCategory)
    readonly property var terminal: root.resolveRole(root.terminalIds, root.terminalCategory)

    // ---- lookup ----------------------------------------------------------

    // Desktop-file id without its `.desktop` suffix, lowercased.
    function bareId(entry: var): string {
        var id = String(entry.id === undefined || entry.id === null ? "" : entry.id);
        if (id.length > 8 && id.slice(-8) === ".desktop")
            id = id.slice(0, -8);
        return id.toLowerCase();
    }

    // Exact id match over the live model. Scanning beats DesktopEntries.byId
    // here because a miss must be silent — this is a probe, not a lookup
    // failure, and it runs once per role.
    function entryById(id: string): var {
        var want = String(id).toLowerCase();
        var list = root.entries;
        for (var i = 0; i < list.length; i++) {
            if (root.bareId(list[i]) === want)
                return list[i];
        }
        return null;
    }

    function entryByCategory(category: string): var {
        var list = root.entries;
        for (var i = 0; i < list.length; i++) {
            var cats = list[i].categories;
            if (!cats)
                continue;
            for (var j = 0; j < cats.length; j++) {
                if (String(cats[j]) === category)
                    return list[i];
            }
        }
        return null;
    }

    // Catalog ids are product ids ("firefox"), while an installed Flatpak's
    // desktop entry is its application id ("org.mozilla.firefox"). Join on
    // the declared source id so every browse surface hides an app immediately
    // after installation instead of offering it twice.
    function catalogAppInstalled(app: var): bool {
        // Establish an explicit binding dependency even though the state map
        // itself is updated in place for this singleton's lifetime.
        void root.catalogInstallRevision;
        var catalogId = root.normalizedWindowId(app && app.id);
        if (catalogId !== "" && root.catalogInstallState[catalogId] !== undefined)
            return root.catalogInstallState[catalogId] === true;
        var sources = app && Array.isArray(app.sources) ? app.sources : [];
        for (var i = 0; i < sources.length; i++) {
            var appId = String(sources[i].appId || "").toLowerCase();
            if (appId !== "" && root.entryById(appId) !== null)
                return true;
            var desktopId = String(sources[i].desktopId || "").toLowerCase();
            if (desktopId !== "" && root.entryById(desktopId) !== null)
                return true;
        }
        return false;
    }

    // True when a desktop entry is one of the launchers declared by a
    // catalog product. The command center uses this to present one result for
    // an installed catalog application instead of a separate "installed"
    // row and "installable" row for the same product.
    function catalogAppMatchesEntry(app: var, entry: var): bool {
        if (entry === null || entry === undefined)
            return false;
        var entryId = root.bareId(entry);
        var sources = app && Array.isArray(app.sources) ? app.sources : [];
        for (var i = 0; i < sources.length; i++) {
            var appId = root.normalizedWindowId(sources[i].appId);
            var desktopId = root.normalizedWindowId(sources[i].desktopId);
            if ((appId !== "" && entryId === appId)
                    || (desktopId !== "" && entryId === desktopId))
                return true;
        }
        return false;
    }

    function resolveRole(ids: var, category: string): var {
        for (var i = 0; i < ids.length; i++) {
            var byId = root.entryById(ids[i]);
            if (byId !== null)
                return byId;
        }
        // Heuristic lookup is Quickshell's own forgiving matcher (handles
        // vendor prefixes and startup classes); it is tried before the
        // category sweep because it is far more specific.
        for (var k = 0; k < ids.length; k++) {
            var guess = DesktopEntries.heuristicLookup(ids[k]);
            if (guess !== null && guess !== undefined)
                return guess;
        }
        return root.entryByCategory(category);
    }

    // ---- search ----------------------------------------------------------

    // Two-letter mono glyph code (D-003 register 02: glyph tags instead of
    // app icons keep the surface monochrome).
    function glyphFor(name: string): string {
        var words = String(name).trim().split(/\s+/);
        if (words.length >= 2 && words[0].length > 0 && words[1].length > 0) {
            return String(words[0]).charAt(0).toUpperCase() + String(words[1]).charAt(0).toUpperCase();
        }
        return String(name).substring(0, 2).toUpperCase();
    }

    // Relevance score for one entry against a lowercased query.
    // -1 means "no match"; higher is better. The ladder is deliberately
    // coarse — an exact product id beats a fuzzy display-name match, while an
    // exact display name remains strongest. This keeps helper entries such as
    // `thunar-settings` from shadowing the actual `thunar` application.
    function score(entry: var, q: string): int {
        if (q === "")
            return 10;
        var name = root.displayName(entry).toLowerCase();
        if (name === q)
            return 100;
        var id = root.bareId(entry);
        if (id === q)
            return 90;
        if (name.indexOf(q) === 0)
            return 80;
        if (name.indexOf(" " + q) !== -1)
            return 60;
        if (id.indexOf(q) === 0)
            return 50;
        if (name.indexOf(q) !== -1)
            return 45;
        if (id.indexOf(q) !== -1)
            return 35;
        // The command the entry runs is part of its identity: `nvim` must
        // reach Neovim even though the string is not inside "neovim".
        var command = entry.command && entry.command.length > 0 ? String(entry.command[0]).toLowerCase() : "";
        if (command !== "" && command.split("/").pop().indexOf(q) === 0)
            return 32;
        var generic = String(entry.genericName || "").toLowerCase();
        if (generic.indexOf(q) !== -1)
            return 30;
        var keywords = entry.keywords ? String(entry.keywords.join(" ")).toLowerCase() : "";
        if (keywords.indexOf(q) !== -1)
            return 20;
        var comment = String(entry.comment || "").toLowerCase();
        if (comment.indexOf(q) !== -1)
            return 10;
        return -1;
    }

    // Ranked matches, best first, ties broken alphabetically.
    function search(query: string, limit: int): var {
        var q = String(query).trim().toLowerCase();
        var list = root.entries;
        var scored = [];
        for (var i = 0; i < list.length; i++) {
            var s = root.score(list[i], q);
            if (s >= 0)
                scored.push({
                    "entry": list[i],
                    "score": s,
                    "name": root.displayName(list[i])
                });
        }
        scored.sort(function (a, b) {
            if (b.score !== a.score)
                return b.score - a.score;
            return a.name.localeCompare(b.name);
        });
        var out = [];
        var cap = limit > 0 ? Math.min(limit, scored.length) : scored.length;
        for (var k = 0; k < cap; k++)
            out.push(scored[k].entry);
        return out;
    }

    // ---- launch ----------------------------------------------------------

    function normalizedWindowId(value: var): string {
        var id = String(value === undefined || value === null ? "" : value).trim().toLowerCase();
        if (id.length > 8 && id.slice(-8) === ".desktop")
            id = id.slice(0, -8);
        return id;
    }

    function executableName(value: var): string {
        var path = String(value === undefined || value === null ? "" : value).trim();
        if (path === "")
            return "";
        var parts = path.split("/");
        return root.normalizedWindowId(parts[parts.length - 1]);
    }

    function addWindowCandidate(candidates: var, value: var): void {
        var id = root.normalizedWindowId(value);
        if (id === "")
            return;
        candidates[id] = true;
        // Punar-owned desktop entries carry a namespace so they cannot clash
        // with package-owned files. Applications correctly expose their own
        // app_id to Wayland, without that packaging namespace.
        if (id.indexOf("punar-") === 0 && id.length > 6)
            candidates[id.slice(6)] = true;
    }

    function entryWindowCandidates(entry: var): var {
        var candidates = ({});
        if (entry === null || entry === undefined)
            return candidates;
        root.addWindowCandidate(candidates, root.bareId(entry));

        // A catalog-generated desktop file launches through the typed
        // `punarctl app open <id>` capability. Include that product id: it is
        // the stable identity exposed by Claude/ChatGPT's native windows.
        var argv = entry.command || [];
        if (argv.length >= 4
                && root.executableName(argv[0]) === "punarctl"
                && String(argv[1]) === "app"
                && String(argv[2]) === "open")
            root.addWindowCandidate(candidates, argv[3]);
        else if (argv.length > 0)
            root.addWindowCandidate(candidates, root.executableName(argv[0]));

        // Runtime app IDs belong to the signed catalog rather than a
        // launcher-specific exception table. This join also covers native
        // apps such as Claude whose Wayland identity intentionally differs
        // from both its executable and its desktop-file id.
        var catalogApps = Catalog.entries;
        for (var k = 0; k < catalogApps.length; k++) {
            if (!root.catalogAppMatchesEntry(catalogApps[k], entry))
                continue;
            var catalogCandidates = root.catalogWindowCandidates(catalogApps[k]);
            for (var candidate in catalogCandidates)
                candidates[candidate] = true;
        }
        return candidates;
    }

    function catalogWindowCandidates(app: var): var {
        var candidates = ({});
        if (app === null || app === undefined)
            return candidates;
        root.addWindowCandidate(candidates, app.id);
        root.addWindowCandidate(candidates, app.app_id);
        root.addWindowCandidate(candidates, app.desktop_id);
        root.addWindowCandidate(candidates, app.package_name);
        root.addWindowCandidate(candidates, root.executableName(app.launch_executable));
        var directWindowIds = Array.isArray(app.windowAppIds) ? app.windowAppIds
            : (Array.isArray(app.window_app_ids) ? app.window_app_ids : []);
        for (var direct = 0; direct < directWindowIds.length; direct++)
            root.addWindowCandidate(candidates, directWindowIds[direct]);

        var sources = Array.isArray(app.sources) ? app.sources : [];
        for (var i = 0; i < sources.length; i++) {
            root.addWindowCandidate(candidates, sources[i].appId);
            root.addWindowCandidate(candidates, sources[i].desktopId);
            root.addWindowCandidate(candidates, sources[i].packageName);
            root.addWindowCandidate(candidates, root.executableName(sources[i].executable));
        }
        return candidates;
    }

    // Foreign-toplevel activation stays protocol-native, with a typed
    // Hyprland focus request to guarantee that an off-workspace match is
    // raised on this compositor. This gives the launcher task-switcher
    // semantics without polling or parsing window titles, and without
    // spawning a duplicate process.
    function focusExisting(candidates: var): bool {
        var list = ToplevelManager.toplevels.values;
        for (var i = 0; i < list.length; i++) {
            var observedAppId = String(list[i].appId || "").trim();
            var appId = root.normalizedWindowId(observedAppId);
            if (appId !== "" && candidates[appId] === true) {
                // Keep the protocol-level activation request for compositor
                // portability, then use Hyprland's typed focus dispatcher to
                // guarantee macOS-like task switching across workspaces.
                list[i].activate();
                var exactClass = observedAppId.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
                HyprlandActions.focusWindow("class:^" + exactClass + "$");
                return true;
            }
        }
        return false;
    }

    function focusCatalogApp(app: var): bool {
        return root.focusExisting(root.catalogWindowCandidates(app));
    }

    // Launch through Quickshell's parsed `Exec` — never a shell string.
    // Returns false when there is nothing to launch, so the caller can say
    // so instead of pretending something happened.
    function launch(entry: var): bool {
        if (entry === null || entry === undefined)
            return false;
        try {
            if (root.focusExisting(root.entryWindowCandidates(entry)))
                return true;
            if (entry.runInTerminal === true) {
                var terminalCommand = ["/usr/lib/punar/punar-terminal-app.sh"];
                var workingDirectory = String(entry.workingDirectory || "");
                if (workingDirectory !== "")
                    terminalCommand.push("--working-directory", workingDirectory);
                terminalCommand.push("--");
                var argv = entry.command || [];
                if (argv.length === 0)
                    return false;
                for (var i = 0; i < argv.length; i++)
                    terminalCommand.push(String(argv[i]));
                Quickshell.execDetached(terminalCommand);
                return true;
            }
            entry.execute();
        } catch (e) {
            console.warn("punar-shell: launch failed for", entry.id, e);
            return false;
        }
        return true;
    }
}
