pragma Singleton
// Ledger — AI access-ledger display state (Milestone 8), for THIS person.
//
// WHERE THE ROWS COME FROM. `punarctl agents access <session> --json`: the
// terminal verb, which asks punar-agentd's `agents.access` — owner or root
// (docs/api/ipc.md §12.2). A person therefore sees the ledger of their own
// sessions and nobody else's, through the same command a terminal runs
// (terminal parity), and the answer is exactly the object that method
// returns: `summary`, `detail`, `not_yet_observed`, `retention`, `privacy`,
// and `purged_at` on a session the person deleted.
//
// WHY NOT THE SIDE FILE ANY MORE. This used to follow
// `/run/punar-agentd/ledger.json` with a FileView. That file holds EVERY
// person's rows, and it was `0640 root:punar` — readable by every account on
// the device, so on a shared device each person could read each person's
// agent ledger. It is now `root:punar-audit`, a group no person is in (the
// audit trail's pattern, F0-S3), and this singleton asks agentd instead.
//
// WHEN IT ASKS. On user action only — opening the panel, moving to a
// session, a purge that went through — never on a clock. One process at a
// time; a request made while one runs replaces any earlier queued one.
//
// Fail CLOSED: no answer, a refusal or an unparsable one reads as "no ledger
// recorded for this session yet" — never an error surface of its own. What
// went wrong is kept in `error` for the panel's agentd line.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    // session_id → the per-session ledger view `agents.access` returned.
    property var views: ({})

    // When the last answer arrived (RFC 3339-ish local stamp; "" = none).
    property string updatedAt: ""

    // True once any answer has parsed, so the panel can tell "not asked
    // yet" from "this session has no rows".
    property bool loaded: false

    // The last refusal or failure, in punarctl's words ("" when the last
    // ask was answered).
    property string error: ""

    // The session to ask about once the running ask finishes.
    property string queued: ""

    // The record for one session, or null. Callers must treat null as
    // "nothing recorded yet", never as an error.
    function view(sessionId: string): var {
        if (sessionId === "")
            return null;
        var v = root.views[sessionId];
        return (v !== undefined && v !== null && typeof v === "object") ? v : null;
    }

    function has(sessionId: string): bool {
        return root.view(sessionId) !== null;
    }

    /// Ask agentd for one of this person's sessions. Fixed argv, never a
    /// shell string; the daemon is the authorization point.
    function fetch(sessionId: string): void {
        if (sessionId === "")
            return;
        if (access.running) {
            root.queued = sessionId;
            return;
        }
        access.sessionId = sessionId;
        access.command = ["punarctl", "agents", "access", sessionId, "--json"];
        try {
            access.running = true;
        } catch (e) {
            root.error = "punarctl could not be started";
        }
    }

    /// Re-ask for every session already on hand (panel open). The newest
    /// asked-for session goes first; the rest follow one at a time.
    function refresh(): void {
        var ids = Object.keys(root.views);
        for (var i = 0; i < ids.length; i++)
            root.fetch(ids[i]);
    }

    function keep(sessionId: string, record: var): void {
        var next = ({});
        for (var key in root.views)
            next[key] = root.views[key];
        next[sessionId] = record;
        root.views = next;
        root.updatedAt = new Date().toISOString();
        root.loaded = true;
    }

    Process {
        id: access

        property string sessionId: ""

        stdout: StdioCollector {
            id: accessOut
            waitForEnd: true
        }
        stderr: StdioCollector {
            id: accessErr
            waitForEnd: true
        }

        // Connected, not declared: see Probe in SystemControl/ControlData.qml.
        Component.onCompleted: access.exited.connect(function (exitCode) {
            var asked = access.sessionId;
            if (exitCode === 0) {
                var record = null;
                try {
                    record = JSON.parse(String(accessOut.text));
                } catch (e) {
                    record = null;
                }
                if (record !== null && typeof record === "object") {
                    root.keep(asked, record);
                    root.error = "";
                } else {
                    root.error = "agents access answered something unreadable";
                }
            } else {
                var said = String(accessErr.text).trim().split("\n")[0];
                root.error = said !== "" ? said : "punarctl exited with " + exitCode;
            }
            var next = root.queued;
            root.queued = "";
            if (next !== "" && next !== asked)
                root.fetch(next);
        })
    }
}
