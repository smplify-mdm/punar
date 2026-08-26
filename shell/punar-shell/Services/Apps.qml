pragma Singleton
pragma ComponentBehavior: Bound
// Apps — the installed-application index behind the command center.
//
// Wraps Quickshell's `DesktopEntries` (the freedesktop application index,
// already filtered of Hidden/NoDisplay entries) and adds the three things
// a launcher actually needs and the plate asks for:
//
//   1. RANKED SEARCH. `search(query)` scores name/generic-name/keywords/
//      comment/id and returns entries best-first, so "chrom" reaches
//      Chromium before "Chromium (Safe Mode)" or anything that merely
//      mentions chromium in a comment.
//   2. ROLE RESOLUTION. `browser` and `terminal` resolve the entry that
//      plays that role on THIS machine — by id first (`chromium` is what
//      the punar-desktop image installs), then by heuristic name, then by
//      the freedesktop `Categories` key (`WebBrowser` / `TerminalEmulator`).
//      No hardcoded argv, no assumption that chromium is present: a
//      machine with only Firefox resolves to Firefox, and a machine with
//      no browser at all resolves to null and the command center says so.
//   3. LAUNCH. `launch(entry)` calls `DesktopEntry.execute()` — Quickshell
//      parses the `Exec` key itself and spawns the argv. THE SHELL NEVER
//      BUILDS A SHELL STRING (spec §10, §12.2; D-003 register: "the
//      command center never generates a shell string").
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

Singleton {
    id: root

    // Live model of installed, visible applications.
    readonly property var entries: DesktopEntries.applications.values

    // Role candidates, most-specific first. Ids are freedesktop desktop-file
    // ids without the `.desktop` suffix. `chromium` is the id Arch's
    // chromium package installs and the one the punar-desktop image ships
    // (os/images/mkosi.profiles/desktop/mkosi.conf), so the browser the
    // image contains is reachable by name, by role, and by one keystroke.
    readonly property var browserIds: ["chromium", "chromium-browser", "org.chromium.Chromium", "firefox", "org.mozilla.firefox", "firefox-esr"]
    readonly property var terminalIds: ["foot", "footclient", "org.codeberg.dnkl.foot"]

    readonly property string browserCategory: "WebBrowser"
    readonly property string terminalCategory: "TerminalEmulator"

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
    // coarse — name matches always beat metadata matches, so the row the
    // reader meant is the row the selection starts on.
    function score(entry: var, q: string): int {
        if (q === "")
            return 10;
        var name = String(entry.name).toLowerCase();
        if (name === q)
            return 100;
        if (name.indexOf(q) === 0)
            return 80;
        if (name.indexOf(" " + q) !== -1)
            return 60;
        if (name.indexOf(q) !== -1)
            return 45;
        if (root.bareId(entry).indexOf(q) !== -1)
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
                    "name": String(list[i].name)
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

    // Launch through Quickshell's parsed `Exec` — never a shell string.
    // Returns false when there is nothing to launch, so the caller can say
    // so instead of pretending something happened.
    function launch(entry: var): bool {
        if (entry === null || entry === undefined)
            return false;
        try {
            entry.execute();
        } catch (e) {
            console.warn("punar-shell: launch failed for", entry.id, e);
            return false;
        }
        return true;
    }
}
