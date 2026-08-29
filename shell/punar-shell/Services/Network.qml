pragma Singleton
// Network — event-driven privacy-panel display state.
//
// The root-owned side file is the rendered local view. Opening or refreshing
// the panel starts exactly one fixed-argv `punarctl privacy connections
// --json` pass; netd rewrites the file only when its semantic set changes and
// this FileView follows that replacement. There is no timer and no socket
// client in the shell.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string connectionsPath: "/run/punar-netd/connections.json"
    property var view: null
    property bool refreshing: false
    property string errorText: ""

    function resetUnavailable(reason: string): void {
        root.view = null;
        root.errorText = reason;
    }

    function loadView(): void {
        var parsed = null;
        try {
            parsed = JSON.parse(connectionFile.text());
        } catch (e) {
            parsed = null;
        }
        if (parsed === null || typeof parsed !== "object") {
            root.resetUnavailable("The local connection view could not be read.");
            return;
        }
        root.view = parsed;
        root.errorText = "";
    }

    function refresh(): void {
        connectionFile.reload();
        if (refreshProbe.running)
            return;
        root.refreshing = true;
        root.errorText = "";
        refreshProbe.command = ["/usr/bin/punarctl", "privacy", "connections", "--json"];
        try {
            refreshProbe.running = true;
        } catch (e) {
            root.refreshing = false;
            root.errorText = "The network service is unavailable. Check punar-netd.";
        }
    }

    FileView {
        id: connectionFile
        path: root.connectionsPath
        watchChanges: true
        onLoaded: root.loadView()
        onFileChanged: connectionFile.reload()
        onLoadFailed: root.resetUnavailable("No connection view is available yet. Refresh to run a local pass.")
    }

    Process {
        id: refreshProbe

        stdout: StdioCollector {
            id: refreshOut
            waitForEnd: true
        }
        stderr: StdioCollector {
            id: refreshErr
            waitForEnd: true
        }

        Component.onCompleted: refreshProbe.exited.connect(function (exitCode) {
            root.refreshing = false;
            if (exitCode !== 0) {
                var message = String(refreshErr.text).trim();
                root.errorText = message !== "" ? message
                    : "The local network pass did not complete. Check punar-netd.";
                return;
            }
            // The command may intentionally perform no write when the set is
            // unchanged, so parse its stdout as an immediate answer and still
            // reload the watched file for the canonical side contract.
            try {
                var parsed = JSON.parse(refreshOut.text);
                if (parsed !== null && typeof parsed === "object") {
                    root.view = parsed;
                    root.errorText = "";
                }
            } catch (e) {
                root.errorText = "The connection response was not valid JSON.";
            }
            connectionFile.reload();
        })
    }
}
