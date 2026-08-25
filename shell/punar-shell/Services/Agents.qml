pragma Singleton
// Agents — AI-panel display state (Milestone 7).
//
// Follows `/run/punar/agents.json`, the summary file punar-agentd
// rewrites atomically (tmp+rename) at startup and on every registry
// change — register, end, reap, detection diff (side contract:
// docs/api/ipc.md §11; design: milestone-7.md §8.2). The shell watches
// it with a FileView change watch (inotify — the Services/Status.qml
// pattern): event-driven, ZERO polling, no socket client in the shell.
//
// The file is summary-only display data — no pids, no cmdlines, no
// secrets, no ledger data (M8) — in a user-owned directory; anything
// root-trusted stays on the agentd socket (ipc.md §11's
// non-authoritative caveat, verbatim from the status.json precedent).
//
// Fail CLOSED (milestone-7.md §8.2): a missing or unparsable file reads
// as "no agent sessions" — the calm empty panel, never an error surface.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string agentsPath: "/run/punar/agents.json"

    // Registered sessions (managed/observed, `ended` included) and
    // heuristic detections (unknown · suspected) — the ipc.md §11
    // objects, verbatim; the AiPanel renders them without reshaping.
    property var sessions: []
    property var detections: []

    // Session counts for the masthead: the file's counts{} when present,
    // else derived (active sessions by classification; detections are
    // the unknown count).
    property int managedCount: 0
    property int observedCount: 0
    property int unknownCount: 0

    // Top-level policy citation: "personal-defaults" on an unenrolled
    // device, the org policy id (e.g. "eng-ai-v3") while enrolled
    // (ipc.md §10.3). "" = no data — consumers fall back to the personal
    // wording (DESIGN_LANGUAGE §8: authority always has a named source).
    property string policyCitation: ""

    // RFC 3339 timestamp of the last detection pass ("" = no data).
    property string scannedAt: ""

    function countByClass(entries: var, cls: string): int {
        var n = 0;
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            if (e !== null && typeof e === "object"
                    && e.classification === cls && e.status === "active")
                n++;
        }
        return n;
    }

    // Fail-closed default: the calm empty panel (milestone-7.md §8.2).
    function resetEmpty(): void {
        root.sessions = [];
        root.detections = [];
        root.managedCount = 0;
        root.observedCount = 0;
        root.unknownCount = 0;
        root.policyCitation = "";
        root.scannedAt = "";
    }

    function loadAgents(): void {
        var j = null;
        try {
            j = JSON.parse(agentsFile.text());
        } catch (e) {
            j = null;
        }
        if (j === null || typeof j !== "object") {
            root.resetEmpty();
            return;
        }
        root.sessions = Array.isArray(j.sessions) ? j.sessions : [];
        root.detections = Array.isArray(j.detections) ? j.detections : [];
        var c = (j.counts !== null && typeof j.counts === "object")
            ? j.counts : ({});
        root.managedCount = typeof c.managed === "number"
            ? c.managed : root.countByClass(root.sessions, "managed");
        root.observedCount = typeof c.observed === "number"
            ? c.observed : root.countByClass(root.sessions, "observed");
        root.unknownCount = typeof c.unknown === "number"
            ? c.unknown : root.detections.length;
        root.policyCitation = typeof j.policy_citation === "string"
            ? j.policy_citation : "";
        root.scannedAt = typeof j.scanned_at === "string"
            ? j.scanned_at : "";
    }

    // One-shot re-read on user action (panel open) — covers a file that
    // did not exist when the watch was armed (agentd started after the
    // shell). An event per open, not a poll.
    function refresh(): void {
        agentsFile.reload();
    }

    FileView {
        id: agentsFile
        path: root.agentsPath
        // agentd replaces the file atomically; the inotify watch follows
        // the change — event-driven, never a timer (PERFORMANCE_BUDGETS.md:
        // no polling loops).
        watchChanges: true
        onLoaded: root.loadAgents()
        onFileChanged: agentsFile.reload()
        // Absent file: agentd not running, or nothing ever registered —
        // calm empty panel either way.
        onLoadFailed: root.resetEmpty()
    }
}
