pragma Singleton
// SurfaceTiming — event-driven interaction timing for the six user-opened
// shell surfaces.
//
// A real key chord is resolved by Hyprland, which execs the same `qs ipc
// call ... toggle` command used by the in-VM exercise.  The old exercise
// then polled both that IPC target and `hyprctl -j layers`; every poll
// spawned another process inside the interval it claimed to measure.
//
// This singleton puts both timestamps in the already-running shell instead:
// `begin()` records the first instruction of show(), and Hyprland's existing
// socket2 stream records `openlayer` for the matching `punar-*` namespace.
// No timer, process, file watch or extra socket is added.  The per-surface
// IpcHandler exposes `latency()` as a read-only probe after the event, so the
// checker cannot perturb the interval by asking whether it has finished.

import QtQuick
import Quickshell
import Quickshell.Hyprland

Singleton {
    id: root

    // Called once by shell.qml so the socket2 connection exists before the
    // first measured surface. Otherwise QML's lazy singleton creation would
    // charge only the first sample for constructing the instrument itself.
    function init(): void {
    }

    // Maps are deliberately internal instrumentation state.  No binding
    // depends on their change notifications; `sample()` reads them only in
    // response to an explicit IPC probe after the surface has mapped.
    property var openedAtMs: ({})
    property var mappedAtMs: ({})

    function begin(surface: string): void {
        root.openedAtMs[surface] = Date.now();
        root.mappedAtMs[surface] = 0;
    }

    // One string keeps the two timestamps in one IPC round trip.  `pending`
    // is an honest absence of an openlayer event, never a fabricated zero.
    function sample(surface: string): string {
        var opened = root.openedAtMs[surface];
        var mapped = root.mappedAtMs[surface];
        if (typeof opened !== "number" || typeof mapped !== "number" || mapped <= 0)
            return "pending";
        return String(opened) + "," + String(mapped);
    }

    Connections {
        target: Hyprland

        function onRawEvent(event: HyprlandEvent): void {
            if (event.name !== "openlayer" || event.data.indexOf("punar-") !== 0)
                return;

            var surface = event.data.substring(6);
            if (typeof root.openedAtMs[surface] !== "number"
                    || root.mappedAtMs[surface] > 0)
                return;
            root.mappedAtMs[surface] = Date.now();
        }
    }
}
