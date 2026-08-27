// Typed contract shared by the measured on-demand surfaces.
//
// Loader.item is QObject to the QML type system. Without this small base,
// shell.qml would have to make unchecked dynamic calls and qmllint could not
// verify the lifecycle API. Concrete surfaces override all four methods;
// these inert defaults make a type mismatch fail closed rather than opening a
// different object accidentally.

import Quickshell

Scope {
    property bool open: false
    signal unloadRequested

    function show(): void {
    }

    function dismiss(): void {
    }

    function toggle(): void {
    }

    function ipcState(): string {
        return "closed";
    }

    function ipcExplain(): string {
        return "none";
    }

    function ipcQuery(text: string): string {
        return text === "" ? "no-match" : "unavailable";
    }

    function ipcRun(): string {
        return "closed";
    }

    function ipcRail(): string {
        return "[]";
    }

    function ipcModel(viewId: string): string {
        return viewId === "" ? "{}" : "{}";
    }

    function ipcReload(): string {
        return "unavailable";
    }

    function ipcRows(): string {
        return "0";
    }

    function ipcUndescribed(): string {
        return "0";
    }

    function ipcCount(): string {
        return "0";
    }

    function ipcFocused(): string {
        return "";
    }

    function ipcOwner(): string {
        return "unverified";
    }

    function ipcDismiss(): string {
        return "";
    }

    function ipcClear(): string {
        return "0";
    }

    function ipcDnd(mode: string): string {
        return mode === "on" ? "on" : "off";
    }

    function showDetection(detectionId: string): void {
    }
}
