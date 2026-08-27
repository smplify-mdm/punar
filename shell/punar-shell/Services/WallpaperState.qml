pragma Singleton
// WallpaperState — one tiny, event-driven preference for the desktop field.
//
// The catalog is compiled into the shell and the selected id is the only
// value persisted.  No directory scan, daemon, timer, network request or
// background decoder is involved: Wallpaper.qml asks for activeFile and Qt
// decodes exactly that one asset for each output.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string defaultId: "signal-horizon"
    readonly property var catalog: [{
        "id": "signal-horizon",
        "name": "Signal Horizon",
        "intent": "Luminous path · toward possibility",
        "file": "signal-horizon.jpg",
        "vector": false
    }, {
        "id": "daybreak",
        "name": "Daybreak",
        "intent": "Alpine twilight · open and quiet",
        "file": "daybreak.jpg",
        "vector": false
    }, {
        "id": "winterline",
        "name": "Winterline",
        "intent": "Winter lake · precise and bright",
        "file": "winterline.jpg",
        "vector": false
    }, {
        "id": "earthrise",
        "name": "Earthrise",
        "intent": "Lunar horizon · deep focus",
        "file": "earthrise.jpg",
        "vector": false
    }, {
        "id": "field",
        "name": "Field",
        "intent": "Theme-derived vector · ultra lean",
        "file": "",
        "vector": true
    }]

    readonly property string homeDir: {
        var home = Quickshell.env("HOME");
        return home ? home : "";
    }
    readonly property string statePath: root.homeDir === "" ? "" : root.homeDir + "/.config/punar/wallpaper.json"

    property string selectedId: root.defaultId
    property bool writable: true
    property bool hasPreference: false

    readonly property string activeId: root.validId(root.selectedId) ? root.selectedId : root.defaultId
    readonly property var active: root.descriptor(root.activeId)
    readonly property string activeName: root.active === null ? "Signal Horizon" : String(root.active.name)
    readonly property string activeIntent: root.active === null ? "Luminous path · toward possibility" : String(root.active.intent)
    readonly property string activeFile: root.active === null ? "signal-horizon.jpg" : String(root.active.file)
    readonly property bool activeIsVector: root.active !== null && root.active.vector === true

    function init(): void {
    }

    function descriptor(id: string): var {
        for (var i = 0; i < root.catalog.length; i++) {
            if (root.catalog[i].id === id)
                return root.catalog[i];
        }
        return null;
    }

    function validId(id: string): bool {
        return root.descriptor(String(id)) !== null;
    }

    function loadState(): void {
        var doc = null;
        try {
            doc = JSON.parse(stateFile.text());
        } catch (e) {
            doc = null;
        }
        if (doc === null || typeof doc !== "object" || typeof doc.version !== "number") {
            root.selectedId = root.defaultId;
            root.writable = true;
            root.hasPreference = false;
            return;
        }
        if (doc.version > 1) {
            console.warn("punar-shell: wallpaper.json version", doc.version, "> 1 — leaving the file untouched");
            root.selectedId = root.defaultId;
            root.writable = false;
            root.hasPreference = false;
            return;
        }
        root.writable = true;
        root.selectedId = root.validId(String(doc.active)) ? String(doc.active) : root.defaultId;
        root.hasPreference = root.validId(String(doc.active));
    }

    function writeSelection(id: string): bool {
        if (!root.writable || root.statePath === "" || !root.validId(id))
            return false;
        var doc = {
            "version": 1,
            "active": id,
            "updated": new Date().toISOString().replace(/\.\d{3}Z$/, "Z")
        };
        // Update the live binding immediately; QSaveFile commits the same id
        // atomically so a crash cannot leave half a preference behind.
        root.selectedId = id;
        root.hasPreference = true;
        stateFile.setText(JSON.stringify(doc, null, 2) + "\n");
        return true;
    }

    function setWallpaper(id: string): bool {
        return root.writeSelection(String(id));
    }

    function resetWallpaper(): bool {
        if (!root.writable || root.statePath === "" || preferenceRemover.running)
            return false;
        // Reset means "fall through to the shipped default", not "record the
        // shipped id as my preference". The fixed argv never enters a shell;
        // the short-lived process exists only for this explicit action.
        preferenceRemover.command = ["rm", "-f", root.statePath];
        preferenceRemover.running = true;
        root.selectedId = root.defaultId;
        root.hasPreference = false;
        return true;
    }

    Process {
        id: preferenceRemover

        Component.onCompleted: preferenceRemover.exited.connect(function(exitCode) {
            if (exitCode !== 0) {
                console.warn("punar-shell: could not reset wallpaper preference; restoring its on-disk state");
                stateFile.reload();
            }
        })
    }

    FileView {
        id: stateFile
        path: root.statePath
        blockLoading: true
        atomicWrites: true
        watchChanges: true
        printErrors: false
        onFileChanged: stateFile.reload()
        onLoaded: root.loadState()
        onLoadFailed: {
            // Absence means the shipped default; creating the file is deferred
            // until the person actually chooses something.
            root.selectedId = root.defaultId;
            root.writable = true;
            root.hasPreference = false;
        }
    }

    IpcHandler {
        target: "wallpaper"

        function state(): string {
            return JSON.stringify({
                "active": root.activeId,
                "name": root.activeName,
                "intent": root.activeIntent,
                "source": root.hasPreference ? "user preference" : "shipped default",
                "path": root.statePath,
                "writable": root.writable
            });
        }

        function list(): string {
            return JSON.stringify({
                "default": root.defaultId,
                "active": root.activeId,
                "wallpapers": root.catalog
            });
        }

        function set(id: string): string {
            var applied = root.setWallpaper(id);
            return JSON.stringify({
                "applied": applied,
                "active": root.activeId,
                "reason": applied ? "active wallpaper is now " + root.activeId : "wallpaper id is not installed or the preference is not writable"
            });
        }

        function reset(): string {
            var applied = root.resetWallpaper();
            return JSON.stringify({
                "applied": applied,
                "active": root.activeId,
                "source": root.hasPreference ? "user preference" : "shipped default"
            });
        }

        function reload(): string {
            stateFile.reload();
            return root.activeId;
        }
    }
}
