// Punar surface-cost probe.
//
// This is a SECOND Quickshell configuration used only by the in-VM
// performance exercise.  The shipping shell keeps its current eager
// behaviour while this process starts empty, loads exactly one of the five
// user-invoked candidate surfaces, opens it once, and reports four timestamps.
// A fresh process per sample keeps type caches and allocator history from one
// surface out of the next surface's number.
//
// The probe deliberately imports the real surface files by URL.  No benchmark
// copy exists, so the measured object tree is the one the product ships.

import QtQuick
import Quickshell
import Quickshell.Io
// Qualify the two directory imports in this nested configuration.  The
// production entrypoint sits beside Services/ and can use its singleton names
// directly; this probe is one directory deeper and Quickshell otherwise
// resolves those names as JavaScript globals at runtime.  That made the probe
// answer IPC while every SurfaceTiming access raised ReferenceError.
import "../Services" as Services
import "../Theme" as ThemeModule

ShellRoot {
    id: root

    property string selectedSurface: ""
    property double startedAtMs: 0
    property string problem: ""

    // The production shell has already instantiated these singletons through
    // its always-resident bar, wallpaper, approval and alert surfaces before
    // any candidate panel opens. Charge them to the empty probe baseline, not
    // independently to every candidate's isolated delta.
    readonly property string sharedState: ThemeModule.Theme.activeId + "|" + Services.Status.state
        + "|" + Services.Agents.scannedAt + "|" + String(Services.Alerts.activeCount)
        + "|" + String(Services.Approvals.pendingCount)

    function sourceFor(surface: string): url {
        switch (surface) {
        case "commandcenter":
            return Qt.resolvedUrl("../CommandCenter/CommandCenter.qml");
        case "systemcontrol":
            return Qt.resolvedUrl("../SystemControl/SystemControl.qml");
        case "shortcuts":
            return Qt.resolvedUrl("../Shortcuts/Shortcuts.qml");
        case "aipanel":
            return Qt.resolvedUrl("../AiPanel/AiPanel.qml");
        case "overview":
            return Qt.resolvedUrl("../Overview/Overview.qml");
        default:
            return "";
        }
    }

    function openSurface(surface: string): string {
        if (root.selectedSurface !== "")
            return "busy";

        var source = root.sourceFor(surface);
        if (String(source) === "")
            return "unknown";

        root.selectedSurface = surface;
        root.problem = "";
        // Loading the real surface also registers its own IpcHandler. Do not
        // mutate Quickshell's IPC target registry while this handler is still
        // serializing its reply: that made the first `open` call complete
        // without a payload even though `state` had just answered. Queue the
        // construction for the next event-loop turn instead.
        Qt.callLater(root.loadSelectedSurface);
        return "loading";
    }

    function loadSelectedSurface(): void {
        var surface = root.selectedSurface;
        var source = root.sourceFor(surface);
        if (surface === "" || String(source) === "") {
            root.problem = "queued surface has no source";
            return;
        }

        root.startedAtMs = Date.now();
        Services.SurfaceTiming.beginConstruction(surface, root.startedAtMs);
        surfaceLoader.setSource(source, {"openOnReady": true});
        surfaceLoader.active = true;
    }

    // start, loader-ready, show-begin, compositor-openlayer.  The last two
    // come from the same SurfaceTiming singleton as the production latency
    // gate. "pending" is absence, never a fabricated zero.
    function timing(): string {
        if (root.problem !== "")
            return "error:" + root.problem;
        if (root.selectedSurface === "")
            return "pending";
        return Services.SurfaceTiming.constructionSample(root.selectedSurface);
    }

    Component.onCompleted: {
        Services.SurfaceTiming.init();
        Services.WorkspaceState.init();
    }

    Loader {
        id: surfaceLoader
        active: false
        asynchronous: false

        onLoaded: {
            if (surfaceLoader.item === null)
                root.problem = "loader returned no object";
        }

        onStatusChanged: {
            if (surfaceLoader.status === Loader.Error)
                root.problem = "loader error";
        }
    }

    IpcHandler {
        target: "surfaceprobe"

        function state(): string {
            if (root.problem !== "")
                return "error";
            if (root.selectedSurface === "")
                return "idle";
            if (surfaceLoader.status === Loader.Ready)
                return "loaded";
            return "loading";
        }

        function open(surface: string): string {
            return root.openSurface(surface);
        }

        function timing(): string {
            return root.timing();
        }
    }
}
