pragma Singleton
// HyprlandActions — the shell's typed bridge to Hyprland 0.56's Lua
// dispatcher API.
//
// Hyprland.dispatch() now accepts a Lua dispatcher expression, not the
// pre-0.56 `workspace 1` / `renameworkspace 1 Atlas` command grammar. Keep
// expression construction here so user-authored workspace names are escaped
// once and every surface speaks the same compositor contract.

import QtQuick
import Quickshell.Hyprland

QtObject {
    id: root

    function luaString(value: var): string {
        var text = String(value);
        return "'" + text
            .replace(/\\/g, "\\\\")
            .replace(/'/g, "\\'")
            .replace(/\r/g, "\\r")
            .replace(/\n/g, "\\n") + "'";
    }

    function focusWorkspace(selector: var): void {
        Hyprland.dispatch("hl.dsp.focus({ workspace = " + root.luaString(selector) + " })");
    }

    function renameWorkspace(selector: var, name: string): void {
        var expression = "hl.dsp.workspace.rename({ workspace = " + root.luaString(selector);
        if (name !== "")
            expression += ", name = " + root.luaString(name);
        Hyprland.dispatch(expression + " })");
    }
}
