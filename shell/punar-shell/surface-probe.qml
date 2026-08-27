// Punar surface-cost probe.
//
// This is a SECOND Quickshell configuration used only by the in-VM
// performance exercise. The shipping shell now uses the measured lazy
// wrappers while this process starts empty, loads exactly one of the five
// user-invoked candidate surfaces, opens it once, and reports four timestamps.
// A fresh process per sample keeps type caches and allocator history from one
// surface out of the next surface's number.
//
// The probe deliberately imports the real surface files by URL.  No benchmark
// copy exists, so the measured object tree is the one the product ships.

import QtQuick
import Quickshell
import Quickshell.Io
import "Services"
import "Theme"

ShellRoot {
    id: root

    property string selectedSurface: ""
    property double startedAtMs: 0
    property string problem: ""
    readonly property DeferredSurfaceBase selected: surfaceLoader.item as DeferredSurfaceBase

    // The production shell has already instantiated these singletons through
    // its always-resident bar, wallpaper, approval and alert surfaces before
    // any candidate panel opens. Charge them to the empty probe baseline, not
    // independently to every candidate's isolated delta.
    readonly property string sharedState: Theme.activeId + "|" + Status.state
        + "|" + Agents.scannedAt + "|" + String(Alerts.activeCount)
        + "|" + String(Approvals.pendingCount)
    property bool baselineReady: false

    function sourceFor(surface: string): url {
        switch (surface) {
        case "commandcenter":
            return Qt.resolvedUrl("CommandCenter/CommandCenter.qml");
        case "systemcontrol":
            return Qt.resolvedUrl("SystemControl/SystemControl.qml");
        case "shortcuts":
            return Qt.resolvedUrl("Shortcuts/Shortcuts.qml");
        case "aipanel":
            return Qt.resolvedUrl("AiPanel/AiPanel.qml");
        case "overview":
            return Qt.resolvedUrl("Overview/Overview.qml");
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
        // Return the IPC acknowledgement before doing synchronous QML
        // construction. This keeps the benchmark control path independent of
        // the object-tree work whose duration it is about to measure.
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
        SurfaceTiming.beginConstruction(surface, root.startedAtMs);
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
        return SurfaceTiming.constructionSample(root.selectedSurface);
    }

    function closeSelectedSurface(): string {
        if (root.selected === null)
            return "absent";
        root.selected.dismiss();
        return "closing";
    }

    function selectedSurfaceState(): string {
        if (root.selected === null)
            return "absent";
        return root.selected.ipcState();
    }

    Component.onCompleted: {
        SurfaceTiming.init();
        WorkspaceState.init();
        // Force the same always-resident singleton set into the empty-process
        // baseline before the checker reads PSS. A declared binding with no
        // reader may remain lazy; this read is the explicit baseline contract.
        root.baselineReady = root.sharedState.length > 0;
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
            if (!root.baselineReady)
                return "baseline-error";
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

        function close(): string {
            return root.closeSelectedSurface();
        }

        function surfaceState(): string {
            return root.selectedSurfaceState();
        }
    }
}
