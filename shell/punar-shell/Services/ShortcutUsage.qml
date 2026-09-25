pragma Singleton
// ShortcutUsage — which parts of the key grammar this person has tried, so the
// shortcut help can suggest the ones they have not (SMP-1405 WP-02; Omarchy
// discussion #9447 asked for the same hint).
//
// COMPUTED HERE, KEPT HERE. Nothing is sent anywhere, and nothing records a
// keystroke. A family counts as tried when the compositor reports the thing
// it does (Hyprland's own socket2 events, which the shell already receives)
// or when the shell opens the surface it opens. Clicking the bar into the
// overview therefore counts as having found the overview: the hint teaches
// features, and a person who already reached one does not need its chord
// pushed at them. Families with no clear signal (focus moves, which a click
// also does) are never listed as untried, so the hint cannot nag about
// something the person does all day.
//
// ONE SMALL FILE, WRITTEN RARELY. ~/.local/state/punar/shortcuts-tried.json
// holds the names of the families and which of them were tried. It is
// written when the shell first finds it missing or naming a different list
// of families (a new account, an update that changed the list), and when a
// family is tried for the FIRST time: a handful of writes in the life of an
// account, never one per keypress. `punarctl keys list --untried` reads the
// same file, so the terminal gives the same hint from the first session on
// (a fresh account used to get three suggestions here and none there).
//
// NOT THE SESSION'S OWN START. Events in the first seconds after the shell
// starts come from the session setting itself up (restoring layouts, a
// web-app sync, the first workspace), not from a person, so they count for
// nothing.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Hyprland

Singleton {
    id: root

    // Instantiated at startup by shell.qml so events are counted from the
    // first one; singletons are otherwise created on first use.
    function init(): void {
    }

    // The families the hint can speak about, in teaching order: the ones a
    // new person gains most from come first. Each is a description PREFIX as
    // punar-binds.lua writes it, so the hint finds its chord in the live
    // table and a renamed bind drops out of the hint rather than lying.
    readonly property var families: [
        "Project overview",
        "Open command center",
        "Switch windows",
        "Workspace ",
        "Move window to workspace ",
        "Toggle scratchpad terminal",
        "Enter resize mode",
        "Toggle window group",
        "Toggle floating",
        "Toggle fullscreen",
        "Pop window out",
        "Move workspace to ",
        "Toggle notes scratchpad",
        "System control",
        "Notification centre",
        "Privacy and network activity",
        "AI on this device",
        "Window actions",
        "Session menu"
    ]

    // family -> true once tried. Replaced (never mutated in place) so
    // bindings that read it see the change.
    property var tried: ({})
    property bool loaded: false
    // Raw compositor events count only after the session has settled.
    property bool listening: false

    readonly property string statePath: {
        var home = Quickshell.env("HOME");
        return home ? home + "/.local/state/punar/shortcuts-tried.json" : "";
    }

    function isTried(family: string): bool {
        return root.tried[family] === true;
    }

    // Families not tried yet, in teaching order.
    function untried(): var {
        var out = [];
        for (var i = 0; i < root.families.length; i++) {
            if (!root.isTried(root.families[i]))
                out.push(root.families[i]);
        }
        return out;
    }

    function mark(family: string): void {
        if (!root.loaded || root.isTried(family) || root.families.indexOf(family) < 0)
            return;
        var next = {};
        for (var key in root.tried)
            next[key] = true;
        next[family] = true;
        root.tried = next;
        root.save();
    }

    function save(): void {
        if (root.statePath === "")
            return;
        var list = [];
        for (var i = 0; i < root.families.length; i++) {
            if (root.isTried(root.families[i]))
                list.push(root.families[i]);
        }
        store.setText(JSON.stringify({
            "version": 1,
            "families": root.families,
            "tried": list
        }, null, 2) + "\n");
    }

    function load(text: string): void {
        var doc = null;
        try {
            doc = JSON.parse(text);
        } catch (e) {
            doc = null;
        }
        var next = {};
        var current = doc !== null && typeof doc === "object" && doc.version === 1 && Array.isArray(doc.tried);
        if (current) {
            for (var i = 0; i < doc.tried.length; i++) {
                if (typeof doc.tried[i] === "string" && root.families.indexOf(doc.tried[i]) >= 0)
                    next[doc.tried[i]] = true;
            }
        }
        root.tried = next;
        root.loaded = true;
        // The terminal reads the family list from this file, so a missing
        // file, or one naming another list, is written once now.
        if (!current || !Array.isArray(doc.families) || doc.families.join("\n") !== root.families.join("\n"))
            root.save();
    }

    // A shell surface opened, by its IPC target name (shell.qml calls this).
    function surfaceOpened(surface: string): void {
        var map = {
            "overview": "Project overview",
            "commandcenter": "Open command center",
            "windowswitcher": "Switch windows",
            "systemcontrol": "System control",
            "notifications": "Notification centre",
            "privacypanel": "Privacy and network activity",
            "aipanel": "AI on this device",
            "windowactions": "Window actions",
            "session": "Session menu"
        };
        var family = map[surface];
        if (typeof family === "string")
            root.mark(family);
    }

    FileView {
        id: store
        path: root.statePath
        atomicWrites: true
        watchChanges: false // the shell is the only writer
        printErrors: false
        onLoaded: root.load(store.text())
        onLoadFailed: root.load("")
    }

    Timer {
        interval: 10000
        running: root.loaded
        repeat: false
        onTriggered: root.listening = true
    }

    Connections {
        target: Hyprland

        function onRawEvent(event: HyprlandEvent): void {
            if (!root.listening)
                return;
            var data = String(event.data);
            switch (event.name) {
            case "workspacev2":
                root.mark("Workspace ");
                break;
            case "movewindowv2":
                root.mark("Move window to workspace ");
                break;
            case "fullscreen":
                if (data === "1")
                    root.mark("Toggle fullscreen");
                break;
            case "changefloatingmode":
                root.mark("Toggle floating");
                break;
            case "submap":
                if (data === "resize")
                    root.mark("Enter resize mode");
                break;
            case "togglegroup":
                if (data.indexOf("1,") === 0)
                    root.mark("Toggle window group");
                break;
            case "moveworkspacev2":
                root.mark("Move workspace to ");
                break;
            case "activespecial":
                if (data.indexOf("special:term,") === 0)
                    root.mark("Toggle scratchpad terminal");
                else if (data.indexOf("special:notes,") === 0)
                    root.mark("Toggle notes scratchpad");
                break;
            case "pin":
                if (data.indexOf(",1") > 0)
                    root.mark("Pop window out");
                break;
            default:
                break;
            }
        }
    }
}
