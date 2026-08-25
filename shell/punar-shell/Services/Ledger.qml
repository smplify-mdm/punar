pragma Singleton
// Ledger — AI access-ledger display state (Milestone 8).
//
// Follows `/run/punar-agentd/ledger.json`, the side file punar-agentd
// rewrites atomically at the same points it rewrites `agents.json`
// (side contract: docs/api/ipc.md §13.2; design: milestone-8.md §8.2).
// Watched with a FileView change watch (inotify — the Services/Status.qml
// and Services/Agents.qml pattern): event-driven, ZERO polling, no socket
// client in the shell.
//
// WHY A SECOND FILE, AND WHY NOT IN /run/punar (milestone-8.md §8.2):
// a ledger is personal data. `agents.json` is world-readable and lives in
// a user-writable directory, so it carries only the counts-only ledger
// FINGERPRINT (ipc.md §12.4) — never a class name, a zone or an `evt_` id.
// The rows below come from `/run/punar-agentd/ledger.json`, `0640
// root:punar`, inside the root-owned agentd runtime directory: only group
// `punar` (the agentd socket's own admission set) can read it, and because
// the directory is root-owned a local user cannot unlink it and substitute
// a forgery.
//
// NON-AUTHORITATIVE, exactly as §9/§11/§13.2 state: the socket is the
// authority and `punarctl agents access` is the authenticated view. This
// is display data for the user's own panel.
//
// Fail CLOSED: a missing or unparsable file, or a session with no record,
// reads as "no ledger recorded for this session yet" — never an error
// surface (milestone-8.md §8.2).

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string ledgerPath: "/run/punar-agentd/ledger.json"

    // session_id → the per-session ledger view, which is the same object
    // `agents.access` returns (ipc.md §12.2): `summary`, `detail`,
    // `not_yet_observed`, `retention`, `privacy`, and `purged_at` on a
    // session the user deleted.
    property var views: ({})

    // RFC 3339 timestamp of the file itself ("" = no data).
    property string updatedAt: ""

    // True once a parse has succeeded, so the panel can tell "agentd has
    // not written a ledger yet" from "this session has no rows".
    property bool loaded: false

    function resetEmpty(): void {
        root.views = ({});
        root.updatedAt = "";
        root.loaded = false;
    }

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

    // The session id a record belongs to. The primary spelling is the one
    // `agents.access` uses (`summary.session_id`); a top-level
    // `session_id` is accepted too so the daemon may key its own file
    // either way without the panel going blank.
    function idOf(entry: var): string {
        if (entry === null || entry === undefined || typeof entry !== "object")
            return "";
        if (typeof entry.session_id === "string")
            return entry.session_id;
        var s = entry.summary;
        if (s !== null && s !== undefined && typeof s === "object"
                && typeof s.session_id === "string")
            return s.session_id;
        return "";
    }

    function loadLedger(): void {
        var j = null;
        try {
            j = JSON.parse(ledgerFile.text());
        } catch (e) {
            j = null;
        }
        if (j === null || typeof j !== "object") {
            root.resetEmpty();
            return;
        }
        var out = ({});
        var sessions = j.sessions;
        if (Array.isArray(sessions)) {
            for (var i = 0; i < sessions.length; i++) {
                var id = root.idOf(sessions[i]);
                if (id !== "")
                    out[id] = sessions[i];
            }
        } else if (sessions !== null && sessions !== undefined && typeof sessions === "object") {
            // Keyed-by-id spelling: the key wins, the record is kept whole.
            var keys = Object.keys(sessions);
            for (var k = 0; k < keys.length; k++) {
                var entry = sessions[keys[k]];
                if (entry !== null && entry !== undefined && typeof entry === "object")
                    out[keys[k]] = entry;
            }
        }
        root.views = out;
        root.updatedAt = typeof j.ts === "string" ? j.ts
            : (typeof j.updated_at === "string" ? j.updated_at : "");
        root.loaded = true;
    }

    // One-shot re-read on user action (panel open) — covers a file that
    // did not exist when the watch was armed (agentd started after the
    // shell). An event per open, not a poll.
    function refresh(): void {
        ledgerFile.reload();
    }

    FileView {
        id: ledgerFile
        path: root.ledgerPath
        // agentd replaces the file atomically; the inotify watch follows
        // the change — event-driven, never a timer (PERFORMANCE_BUDGETS.md:
        // no polling loops).
        watchChanges: true
        onLoaded: root.loadLedger()
        onFileChanged: ledgerFile.reload()
        // Absent or unreadable: agentd not running, or this user is not in
        // group punar. Either way the panel says so calmly.
        onLoadFailed: root.resetEmpty()
    }
}
