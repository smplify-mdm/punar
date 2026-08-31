pragma Singleton

// Qt's JavaScript engine caches the system timezone. The backend changes
// /etc/localtime atomically; this singleton tells the long-lived shell engine
// to recalculate its UTC offset and exposes a revision so clock bindings are
// reevaluated immediately instead of waiting for their next minute tick.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    property int revision: 0
    property string immediateClockText: ""
    property double immediateClockMinute: -1

    FileView {
        id: localtimeFile

        // punard replaces /etc/localtime atomically. Follow that replacement
        // directly so the resident clock does not depend on whichever UI or
        // command initiated the governed change.
        path: "/etc/localtime"
        watchChanges: true
        onFileChanged: {
            root.systemTimeZoneChanged("");
            localtimeFile.reload();
        }
        onLoadFailed: console.warn("punar-shell: cannot watch /etc/localtime")
    }

    Process {
        id: localDateProbe

        command: ["/usr/bin/date", "+%H:%M"]
        stdout: StdioCollector {
            id: localDateOut
            waitForEnd: true
            // Stream completion is the documented point at which collector
            // text is complete. Process.exited can precede parser delivery on
            // a fast one-line command, which made the refresh race the clock.
            onStreamFinished: {
                var value = String(localDateOut.text).trim();
                if (/^([01][0-9]|2[0-3]):[0-5][0-9]$/.test(value)) {
                    root.immediateClockText = value;
                    root.immediateClockMinute = Math.floor(Date.now() / 60000);
                }
                root.revision += 1;
            }
        }
    }

    function systemTimeZoneChanged(timeZone: string): void {
        // Qt exposes this extension on supported builds. The one-shot date
        // probe below remains the source of immediate visible truth when a
        // compositor build keeps an already-created Date object cached.
        try {
            if (typeof Date.timeZoneUpdated === "function")
                Date.timeZoneUpdated();
        } catch (e) {
            console.warn("punar-shell: timezone cache refresh unavailable:", e);
        }
        root.revision += 1;
        // The settings path passes the exact zone that punard accepted. This
        // avoids rediscovering it through process-global libc/Qt caches. An
        // external /etc/localtime change supplies an empty zone and removes
        // any inherited TZ override so date reads the canonical system link.
        var environment = timeZone !== "" ? ({ "TZ": timeZone }) : ({ "TZ": null });
        // exec() deliberately restarts an in-flight read. A second timezone
        // choice must always win, even when it follows the first immediately.
        localDateProbe.exec({
            command: ["/usr/bin/date", "+%H:%M"],
            environment: environment
        });
    }

    function format(date: var, pattern: string): string {
        var observedRevision = root.revision;
        if (observedRevision < 0)
            return "";
        // SystemClock's current Date object may still carry the offset it had
        // at its last minute tick. Preserve its instant, but create a fresh
        // Date after timeZoneUpdated() so a successful settings change is
        // visible now rather than as much as 59 seconds later.
        var instant = date && date.getTime ? date.getTime() : Date.now();
        if (pattern === "HH:mm"
                && root.immediateClockText !== ""
                && root.immediateClockMinute === Math.floor(instant / 60000))
            return root.immediateClockText;
        return Qt.formatDateTime(new Date(instant), pattern);
    }
}
