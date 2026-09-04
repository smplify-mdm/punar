pragma Singleton
// BrowserContext — the user-owned active browser-storage preference.
//
// The browser daemon owns which contexts exist and which web apps use them;
// this singleton owns only the small session preference documented by
// schemas/browser/browser-context-state.json. The file is watched because
// both the graphical picker and `punarctl web-apps context use` are supported
// writers. There is no polling: a CLI write arrives through inotify, and a
// workspace binding is applied only when Hyprland emits a workspace event.

import QtQuick
import Quickshell
import Quickshell.Hyprland
import Quickshell.Io

Singleton {
    id: root

    readonly property string statePath: {
        var home = Quickshell.env("HOME");
        return home ? home + "/.local/state/punar/browser-context.json" : "";
    }

    property var document: ({
        version: 1,
        updated: "",
        active: "personal",
        active_cause: "default",
        bindings: []
    })

    readonly property string active: root.validId(root.document.active)
        ? String(root.document.active) : "personal"
    readonly property string activeCause: typeof root.document.active_cause === "string"
        ? String(root.document.active_cause) : "default"

    readonly property var idPattern: /^[a-z0-9][a-z0-9-]{0,31}$/

    function init(): void {
    }

    function validId(value: var): bool {
        return typeof value === "string" && root.idPattern.test(value);
    }

    function validBinding(value: var): bool {
        return value !== null && typeof value === "object"
            && typeof value.workspace === "string"
            && /^[A-Za-z0-9][A-Za-z0-9 _-]{0,31}$/.test(value.workspace)
            && root.validId(value.context);
    }

    function normalizedBindings(value: var): var {
        var source = Array.isArray(value) ? value : [];
        var out = [];
        var seen = ({});
        for (var i = 0; i < source.length && out.length < 64; ++i) {
            var binding = source[i];
            if (!root.validBinding(binding) || seen[binding.workspace] === true)
                continue;
            seen[binding.workspace] = true;
            out.push({workspace: String(binding.workspace), context: String(binding.context)});
        }
        return out;
    }

    function load(): void {
        try {
            var parsed = JSON.parse(stateFile.text());
            if (parsed !== null && typeof parsed === "object"
                    && parsed.version === 1 && root.validId(parsed.active)) {
                root.document = {
                    version: 1,
                    updated: typeof parsed.updated === "string" ? parsed.updated : "",
                    active: String(parsed.active),
                    active_cause: typeof parsed.active_cause === "string"
                        ? parsed.active_cause : "default",
                    bindings: root.normalizedBindings(parsed.bindings)
                };
                return;
            }
        } catch (e) {
            console.warn("punar-shell: browser context state is not valid JSON", e);
        }
        root.reset();
    }

    function reset(): void {
        root.document = {
            version: 1,
            updated: "",
            active: "personal",
            active_cause: "default",
            bindings: []
        };
    }

    function write(activeId: string, cause: string, bindings: var): bool {
        if (!root.validId(activeId) || root.statePath === "")
            return false;
        var next = {
            version: 1,
            updated: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            active: activeId,
            active_cause: cause,
            bindings: root.normalizedBindings(bindings)
        };
        root.document = next;
        try {
            stateFile.setText(JSON.stringify(next, null, 2) + "\n");
            return true;
        } catch (e) {
            console.warn("punar-shell: browser context preference could not be written", e);
            return false;
        }
    }

    function use(activeId: string): bool {
        return root.write(activeId, "manual", root.document.bindings);
    }

    function bindToFocusedWorkspace(activeId: string): bool {
        var workspace = Hyprland.focusedWorkspace;
        if (workspace === null || !WorkspaceState.isNamed(workspace))
            return root.use(activeId);
        var name = String(workspace.name);
        var next = [];
        var bindings = root.normalizedBindings(root.document.bindings);
        for (var i = 0; i < bindings.length; ++i) {
            if (bindings[i].workspace !== name)
                next.push(bindings[i]);
        }
        next.push({workspace: name, context: activeId});
        return root.write(activeId, "workspace:" + name, next);
    }

    function applyFocusedWorkspaceBinding(): void {
        var workspace = Hyprland.focusedWorkspace;
        if (workspace === null)
            return;
        var bindings = root.normalizedBindings(root.document.bindings);
        if (WorkspaceState.isNamed(workspace)) {
            var name = String(workspace.name);
            for (var i = 0; i < bindings.length; ++i) {
                if (bindings[i].workspace === name) {
                    var cause = "workspace:" + name;
                    if (bindings[i].context !== root.active || root.activeCause !== cause)
                        root.write(bindings[i].context, cause, bindings);
                    return;
                }
            }
        }
        // Leaving a bound workspace returns to the documented personal
        // fallback. A manual selection remains global until a bound
        // workspace overrides it; there is no hidden per-workspace history.
        if (root.activeCause.indexOf("workspace:") === 0)
            root.write("personal", "default", bindings);
    }

    FileView {
        id: stateFile
        path: root.statePath
        atomicWrites: true
        watchChanges: true
        onFileChanged: stateFile.reload()
        onLoaded: root.load()
        onLoadFailed: root.reset()
    }

    Connections {
        target: Hyprland

        function onRawEvent(event: HyprlandEvent): void {
            if (event.name === "workspace" || event.name === "workspacev2")
                Qt.callLater(root.applyFocusedWorkspaceBinding);
        }
    }
}
