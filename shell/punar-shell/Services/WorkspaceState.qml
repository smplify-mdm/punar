pragma Singleton
// WorkspaceState — named-workspace persistence (Milestone 2; spec §14.3
// first slice: layout memory ships first — names + preset, never windows).
//
// Contract: docs/development/milestone-2.md §6. punar-shell is the ONLY
// writer of ~/.local/state/punar/workspaces.json in M2, via FileView with
// atomicWrites (QSaveFile tmp+rename; parent directories are created).
// Writes happen only when a `renameworkspace` socket2 event arrives or the
// layout-preset cache changes, debounced 1 s by a one-shot timer — never
// on a periodic timer (PERFORMANCE_BUDGETS.md: no polling loops; the
// preset cache is watched via inotify, which is event-driven).
//
// State file shape (schema version 1, milestone-2.md §6):
//   { "version": 1, "updated": "<UTC ISO-8601>", "layoutPreset": "balanced",
//     "workspaces": [ { "id": 1, "name": "atlas" } ] }
// workspaces sorted by id, entries only for non-empty real names, id >= 1
// (specials never persisted), names match ^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Hyprland

Singleton {
    id: root

    // Called by shell.qml at startup purely to force instantiation
    // (QML singletons are created lazily on first reference).
    function init(): void {
    }

    readonly property string statePath: {
        var home = Quickshell.env("HOME");
        return home ? home + "/.local/state/punar/workspaces.json" : "";
    }

    // Active layout preset cache, written by punar-layout.sh
    // (milestone-2.md §4). Watched so preset switches reach the state file.
    readonly property string presetCachePath: {
        var rt = Quickshell.env("XDG_RUNTIME_DIR");
        return rt ? rt + "/punar/layout-preset" : "";
    }

    readonly property var presetNames: ["balanced", "columns", "rows", "focus", "stack"]

    // milestone-2.md §6: 1–32 chars, no commas (the socket2 rename event
    // frames as `ID,NAME`), no leading "special" (lowercase, matching the
    // case-sensitive rule in crates/punar-workspace and the schema's
    // `"not": {"pattern": "^special"}` — "Specialist" stays valid).
    readonly property var nameRe: /^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$/

    property string layoutPreset: "balanced"
    property bool presetFromCache: false

    // Version guard: if the on-disk file says version > 1, neither restore
    // from it nor overwrite it — a newer writer owns that file.
    property bool writable: true

    // id -> name read from disk; applied when that workspace exists
    // (re-checked on createworkspacev2, milestone-2.md §6).
    property var pendingNames: ({})

    function validName(name: string): bool {
        return root.nameRe.test(name) && name.indexOf("special") !== 0;
    }

    // True when the workspace carries a real (persistable) name — Hyprland
    // reports unnamed numeric workspaces with the id as the name.
    function isNamed(ws: var): bool {
        return ws.name !== "" && ws.name !== String(ws.id);
    }

    function loadState() {
        var st = null;
        try {
            st = JSON.parse(stateFile.text());
        } catch (e) {
            st = null;
        }
        if (st === null || typeof st !== "object" || typeof st.version !== "number") {
            console.warn("punar-shell: workspaces.json missing or corrupt — fresh default");
            root.freshDefault();
            return;
        }
        if (st.version > 1) {
            console.warn("punar-shell: workspaces.json version", st.version,
                         "> 1 — leaving the file untouched");
            root.writable = false;
            return;
        }
        if (!root.presetFromCache && root.presetNames.indexOf(st.layoutPreset) !== -1)
            root.layoutPreset = st.layoutPreset;
        var pending = {};
        var list = Array.isArray(st.workspaces) ? st.workspaces : [];
        for (var i = 0; i < list.length; i++) {
            var w = list[i];
            if (w && typeof w.id === "number" && w.id >= 1
                    && typeof w.name === "string" && root.validName(w.name)) {
                pending[w.id] = w.name;
            }
        }
        root.pendingNames = pending;
        root.applyPending();
    }

    // Missing/corrupt state file: fresh default — workspace 1 is "Punar".
    function freshDefault() {
        root.pendingNames = {
            1: "Punar"
        };
        root.applyPending();
    }

    // Apply stored names to workspaces that exist and are currently
    // unnamed (a live name always wins over a stored one). Re-run from
    // valuesChanged / createworkspacev2 so late-created workspaces pick
    // their stored names up.
    function applyPending() {
        var wss = Hyprland.workspaces.values;
        var pending = root.pendingNames;
        var changed = false;
        for (var i = 0; i < wss.length; i++) {
            var ws = wss[i];
            var name = pending[ws.id];
            if (name === undefined)
                continue;
            if (!root.isNamed(ws))
                Hyprland.dispatch("renameworkspace " + ws.id + " " + name);
            delete pending[ws.id];
            changed = true;
        }
        if (changed)
            root.pendingNames = pending;
    }

    function scheduleWrite() {
        writeTimer.restart();
    }

    function writeNow() {
        if (!root.writable || root.statePath === "")
            return;
        var wss = Hyprland.workspaces.values;
        var entries = [];
        var seen = {};
        for (var i = 0; i < wss.length; i++) {
            var ws = wss[i];
            if (ws.id < 1)
                continue; // specials are never persisted
            seen[ws.id] = true;
            if (root.isNamed(ws) && root.validName(ws.name))
                entries.push({
                    id: ws.id,
                    name: ws.name
                });
        }
        // Retain stored names for workspaces that have not been recreated
        // yet this session — a rewrite must not lose them (they are still
        // pending restoration, applied on createworkspacev2).
        for (var id in root.pendingNames) {
            if (!seen[id])
                entries.push({
                    id: Number(id),
                    name: root.pendingNames[id]
                });
        }
        entries.sort(function (a, b) {
            return a.id - b.id;
        });
        var st = {
            version: 1,
            updated: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            layoutPreset: root.layoutPreset,
            workspaces: entries
        };
        stateFile.setText(JSON.stringify(st, null, 2) + "\n");
    }

    FileView {
        id: stateFile
        path: root.statePath
        // Atomic tmp+rename via QSaveFile; parent dirs are created on write.
        atomicWrites: true
        watchChanges: false // the shell is the only writer in M2
        onLoaded: root.loadState()
        onLoadFailed: root.freshDefault()
    }

    FileView {
        id: presetFile
        path: root.presetCachePath
        watchChanges: true // inotify — event-driven, not polling
        onLoaded: {
            var p = presetFile.text().trim();
            if (root.presetNames.indexOf(p) !== -1) {
                root.presetFromCache = true;
                if (p !== root.layoutPreset) {
                    root.layoutPreset = p;
                    root.scheduleWrite();
                }
            }
        }
        onFileChanged: presetFile.reload()
        onLoadFailed: {
            // Cache absent until the first preset switch of the session —
            // punar-layout.sh restore creates it; nothing to do here.
        }
    }

    Timer {
        id: writeTimer
        interval: 1000 // debounce (milestone-2.md §6) — one-shot, never periodic
        repeat: false
        onTriggered: root.writeNow()
    }

    Connections {
        target: Hyprland

        function onRawEvent(event: HyprlandEvent): void {
            if (event.name === "renameworkspace")
                root.scheduleWrite();
            else if (event.name === "createworkspacev2")
                root.applyPending();
        }
    }

    Connections {
        target: Hyprland.workspaces

        function onValuesChanged(): void {
            root.applyPending();
        }
    }
}
