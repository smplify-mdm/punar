pragma Singleton
pragma ComponentBehavior: Bound
// Catalog — read-only projection of the signed image application catalog.
//
// This singleton performs local discovery only. It never renders permissions,
// trust containment, installed state, or an install command: those values are
// obtained from punard after a live pinned-metadata inspection when a person
// selects a row. Keeping those two stages separate makes typing instantaneous
// and prevents publisher text from becoming a security claim.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string installedPath: "/usr/share/punar/catalog/catalog.json"
    readonly property string devPath: Quickshell.shellDir + "/../../catalog/catalog.json"
    readonly property string installedIconDir: "/usr/share/punar/catalog/icons"
    readonly property string devIconDir: Quickshell.shellDir + "/../../catalog/icons"
    property var document: ({ "apps": [] })
    readonly property var entries: root.document && Array.isArray(root.document.apps) ? root.document.apps : []
    readonly property var categoryOrder: ["ai", "developer", "diagnostics", "writing", "files", "security", "browsers", "communication", "media", "graphics", "productivity", "utilities"]

    FileView {
        id: catalogFile
        path: root.installedPath
        blockLoading: true
        watchChanges: false
        onLoaded: {
            try {
                var parsed = JSON.parse(catalogFile.text());
                root.document = parsed && parsed.v === 1 && Array.isArray(parsed.apps) ? parsed : ({ "apps": [] });
            } catch (e) {
                console.warn("punar-shell: application catalog is invalid at", catalogFile.path, e);
                root.document = ({ "apps": [] });
            }
        }
        onLoadFailed: {
            if (catalogFile.path === root.installedPath)
                catalogFile.path = root.devPath;
            else
                root.document = ({ "apps": [] });
        }
    }

    function score(app: var, query: string): int {
        var q = String(query).trim().toLowerCase();
        // An empty query is the browse view. The catalog is intentionally
        // curated and finite, so showing it is not a live-store fetch.
        if (q === "")
            return app.featured === true ? 20 : 10;
        var name = String(app.name || "").toLowerCase();
        var id = String(app.id || "").toLowerCase();
        if (name === q || id === q)
            return 100;
        if (name.indexOf(q) === 0 || id.indexOf(q) === 0)
            return 80;
        if (name.indexOf(q) !== -1 || id.indexOf(q) !== -1)
            return 60;
        var keywords = Array.isArray(app.keywords) ? app.keywords.join(" ") : "";
        var context = (id + " " + name + " " + String(app.category || "") + " "
            + String(app.summary || "") + " " + keywords).toLowerCase();
        var terms = q.split(/\s+/);
        for (var i = 0; i < terms.length; i++) {
            if (context.indexOf(terms[i]) === -1)
                return -1;
        }
        return 30;
    }

    function search(query: string, limit: int): var {
        var scored = [];
        var list = root.entries;
        for (var i = 0; i < list.length; i++) {
            var rank = root.score(list[i], query);
            if (rank >= 0)
                scored.push({ "app": list[i], "rank": rank });
        }
        scored.sort(function(a, b) {
            if (a.rank !== b.rank)
                return b.rank - a.rank;
            return String(a.app.name).localeCompare(String(b.app.name));
        });
        var out = [];
        var cap = limit > 0 ? Math.min(limit, scored.length) : scored.length;
        for (var k = 0; k < cap; k++)
            out.push(scored[k].app);
        return out;
    }

    function byId(id: string): var {
        var want = String(id).toLowerCase();
        for (var i = 0; i < root.entries.length; i++) {
            if (String(root.entries[i].id).toLowerCase() === want)
                return root.entries[i];
        }
        return null;
    }

    function categoryLabel(category: string): string {
        var labels = {
            "ai": "AI",
            "developer": "Developer",
            "diagnostics": "Diagnostics",
            "writing": "Writing",
            "files": "Files",
            "security": "Security",
            "browsers": "Browsers",
            "communication": "Communication",
            "media": "Media",
            "graphics": "Graphics",
            "productivity": "Productivity",
            "utilities": "Utilities"
        };
        return labels[String(category)] || String(category || "Applications");
    }

    function categories(): var {
        var present = ({});
        for (var i = 0; i < root.entries.length; i++)
            present[String(root.entries[i].category || "")] = true;
        var out = [];
        for (var k = 0; k < root.categoryOrder.length; k++) {
            var id = root.categoryOrder[k];
            if (present[id] === true)
                out.push({ "id": id, "label": root.categoryLabel(id) });
        }
        return out;
    }

    function webOnly(app: var): bool {
        if (app === null || app === undefined || !Array.isArray(app.sources) || app.sources.length === 0)
            return false;
        for (var i = 0; i < app.sources.length; i++) {
            if (String(app.sources[i].kind) !== "web")
                return false;
        }
        return true;
    }

    // Icons are signed-image content and must resolve locally. The schema and
    // daemon enforce the same basename-only shape; this guard keeps the shell
    // safe even when it is run directly against an unvalidated dev catalog.
    function iconSource(app: var): string {
        if (app === null || app === undefined)
            return "";
        var name = String(app.icon || "");
        if (!/^[A-Za-z0-9._-]+\.(svg|png)$/.test(name))
            return "";
        var base = catalogFile.path === root.installedPath ? root.installedIconDir : root.devIconDir;
        return "file://" + base + "/" + name;
    }
}
