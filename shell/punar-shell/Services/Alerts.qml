pragma Singleton
// Alerts — shadow-AI detection alert state (Milestone 10).
//
// Follows `/run/punar-agentd/alerts.json`, the side file punar-agentd
// rewrites atomically (tmp + fsync + rename) ONLY when the alert set
// changes (side contract: milestone-10.md §5.3 / §13.4, landing as
// docs/api/ipc.md §20). Watched with a FileView change watch (inotify —
// the Services/Status.qml, Services/Agents.qml, Services/Ledger.qml and
// Services/Approvals.qml pattern): event-driven, ZERO polling, no socket
// client in the shell, no timer of any kind in this file.
//
// WHY /run/punar-agentd AND NOT /run/punar (milestone-10.md §5.3, the M9
// lesson restated): `/run/punar` is `0755 punar:punar` — user-writable. A
// forged card reading "Unknown AI activity suspected · your-bank-helper"
// with an Inspect action is a phishing primitive, so the file that tells
// a human what to believe lives in the already-root-owned
// `/run/punar-agentd` (`0750 root:punar`) at `0640 root:punar`, exactly
// where `ledger.json` lives (ipc.md §13.2). The shell only ever reads it.
//
// NON-AUTHORITATIVE (milestone-10.md §5.3): the agentd socket is the
// authority and this file is display data. Dismissal sends ONLY the
// `alert_id` to `punarctl`, agentd re-derives everything from its own
// record, and the next FileView change is what the surface believes.
//
// ANTI-NAG IS THE DAEMON'S JOB, NOT THIS FILE'S (milestone-10.md §5.2):
// agentd raises at most one alert per `signature_id`, suppresses while
// any live detection of that signature exists and for 24 h after the last
// one clears. The shell therefore never counts, never re-raises and never
// keeps a suppression state of its own — it draws the records it is given
// and keys them by `alert_id` so a file rewrite can never produce a
// second card for the same alert.
//
// Fail CLOSED (milestone-10.md §5.3, verbatim): a missing or unparsable
// file means NO alert — never a placeholder alert, never an error card.
// The absence of evidence is drawn as nothing at all.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string alertsPath: "/run/punar-agentd/alerts.json"

    // The §5.3 records, verbatim and unreshaped:
    //   {alert_id, signature_id, agent, executable, owner, first_seen,
    //    last_seen, live, detection_id, signature, policy_citation, state}
    // No pids, no cmdlines, no hashes of anything secret — by the shape of
    // the contract, not by a filter here.
    property var alerts: []

    // RFC 3339 timestamp of the file itself ("" = no data).
    property string updatedAt: ""

    // True once a parse has succeeded, so a surface can tell "agentd has
    // not written the file yet" from "nothing is suspected".
    property bool loaded: false

    // ---- record accessors (tolerant, never throwing) ----

    function str(obj: var, key: string): string {
        if (obj === null || obj === undefined || typeof obj !== "object")
            return "";
        var v = obj[key];
        return typeof v === "string" ? v : "";
    }

    function flag(obj: var, key: string): bool {
        if (obj === null || obj === undefined || typeof obj !== "object")
            return false;
        return obj[key] === true;
    }

    function id(alert: var): string {
        return root.str(alert, "alert_id");
    }

    // `live` | `cleared` | `dismissed`, or `unknown` for a record whose
    // state the shell cannot read. An unreadable state is never assumed to
    // be live: a card must not be manufactured out of a missing field.
    function alertState(alert: var): string {
        var s = root.str(alert, "state");
        return s === "" ? "unknown" : s;
    }

    function isDismissed(alert: var): bool {
        return root.alertState(alert) === "dismissed"
            || root.str(alert, "dismissed_at") !== "";
    }

    // The process behind the signature was still running at the last pass.
    // `live` is the boolean the record carries; `state` is the register the
    // daemon files it under. Both are read, neither is inferred.
    function isLive(alert: var): bool {
        return root.flag(alert, "live") || root.alertState(alert) === "live";
    }

    // Cards a surface may draw: everything the record does not mark
    // dismissed. Dismissal FILES, it never destroys (milestone-10.md §5.4)
    // — the alert stays in `punarctl agents alerts` and in the detection
    // record; it simply stops occupying the screen.
    readonly property var active: {
        var out = [];
        for (var i = 0; i < root.alerts.length; i++) {
            var a = root.alerts[i];
            if (a === null || a === undefined || typeof a !== "object")
                continue;
            if (root.id(a) === "")
                continue; // no id, no dismissal path, no card
            if (root.isDismissed(a))
                continue;
            out.push(a);
        }
        return out;
    }

    readonly property int activeCount: root.active.length

    // The record with this id, or null. Callers treat null as "gone".
    function byId(alertId: string): var {
        if (alertId === "")
            return null;
        for (var i = 0; i < root.alerts.length; i++) {
            if (root.id(root.alerts[i]) === alertId)
                return root.alerts[i];
        }
        return null;
    }

    // ---- time ----

    // `HH:mm` in local time, or "" for anything unparsable. Plate D-009's
    // meta row prints a clock time and nothing else; a stamp the shell
    // cannot read prints nothing rather than a guess (spec 1.22).
    function hhmm(iso: string): string {
        if (iso === "")
            return "";
        var at = Date.parse(iso);
        if (isNaN(at))
            return "";
        return Qt.formatDateTime(new Date(at), "HH:mm");
    }

    // ---- loading ----

    function resetEmpty(): void {
        root.alerts = [];
        root.updatedAt = "";
        root.loaded = false;
    }

    function loadAlerts(): void {
        var j = null;
        try {
            j = JSON.parse(alertsFile.text());
        } catch (e) {
            j = null;
        }
        if (j === null || typeof j !== "object") {
            root.resetEmpty();
            return;
        }
        root.alerts = Array.isArray(j.alerts) ? j.alerts : [];
        root.updatedAt = typeof j.updated_at === "string" ? j.updated_at : "";
        root.loaded = true;
    }

    // One-shot re-read on user action — covers a file that did not exist
    // when the watch was armed (agentd started after the shell). An event
    // per action, not a poll.
    function refresh(): void {
        alertsFile.reload();
    }

    FileView {
        id: alertsFile
        path: root.alertsPath
        // agentd replaces the file atomically and ONLY on a change; the
        // inotify watch follows it — event-driven, never a timer
        // (PERFORMANCE_BUDGETS.md / spec 6.3: no polling loops).
        watchChanges: true
        onLoaded: root.loadAlerts()
        onFileChanged: alertsFile.reload()
        // Absent or unreadable: agentd not running, nothing ever
        // suspected, or this user is not in group punar. Every one of
        // those means NO alert.
        onLoadFailed: root.resetEmpty()
    }
}
