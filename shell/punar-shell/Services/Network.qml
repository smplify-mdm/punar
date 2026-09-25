pragma Singleton
// Network — event-driven privacy-panel display state, for THIS person.
//
// Opening or refreshing the panel starts exactly one fixed-argv `punarctl
// privacy connections --json` pass, and its answer is the view. netd scopes
// that answer to the caller (docs/api/ipc.md section 21.3): this person's own
// programs and managed sessions, and the device's, with `withheld` counting
// the rows of other people it left out. There is no timer and no socket
// client in the shell.
//
// WHY NOT THE SIDE FILE ANY MORE. This used to follow
// `/run/punar-netd/connections.json` with a FileView. That file holds every
// person's rows and was `0640 root:punar` — readable by every account — so on
// a shared device each person could see which destinations another person's
// programs reached. It is now root-only, and the panel asks instead.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    property var view: null
    property bool refreshing: false
    property string errorText: ""

    function refresh(): void {
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
            // The answer is the view: netd scoped it to this person.
            try {
                var parsed = JSON.parse(refreshOut.text);
                if (parsed !== null && typeof parsed === "object") {
                    root.view = parsed;
                    root.errorText = "";
                } else {
                    root.errorText = "The connection response was not a view.";
                }
            } catch (e) {
                root.errorText = "The connection response was not valid JSON.";
            }
        })
    }
}
