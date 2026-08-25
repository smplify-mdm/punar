pragma Singleton
// Approvals — approval-gate and privilege-grant display state (Milestone 9).
//
// Follows `/run/punard/approvals.json`, the side file punard rewrites
// atomically (tmp + fsync + rename) at EVERY approval state transition and
// every grant change (side contract: docs/api/ipc.md §15; design:
// milestone-9.md §8.1). Watched with a FileView change watch (inotify —
// the Services/Status.qml and Services/Ledger.qml pattern): event-driven,
// ZERO polling, no socket client in the shell.
//
// WHY /run/punard AND NOT /run/punar (milestone-9.md §8.1): `/run/punar` is
// `0755 punar:punar` — user-writable. A local process could unlink a file
// there and bind its own. For `agents.json` (counts and names) that is a
// nuisance; for THE FILE THAT TELLS A HUMAN WHAT THEY ARE ABOUT TO
// AUTHORIZE it is a spoofing primitive: show a benign contract block over a
// dangerous `apr_` id and the human presses A. So it lives inside the
// already-root-owned `/run/punard` (`0750 root:punar`) at `0640 root:punar`
// — the same argument that put `ledger.json` in `/run/punar-agentd`.
//
// NON-AUTHORITATIVE, exactly as §9/§11/§13.2/§15 state: the socket is the
// authority. The overlay's Approve action sends ONLY the `approval_id`, and
// punard re-derives the contract from its own record before executing
// anything. Nothing here is trusted to decide; it is trusted to draw.
//
// Fail CLOSED: a missing or unparsable file reads as "no approvals
// pending" — never an error surface, never a spurious gate.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    readonly property string approvalsPath: "/run/punard/approvals.json"

    // Every approval punard is holding: pending first, plus recently
    // resolved ones so a verdict can be drawn after the decision.
    property var approvals: []

    // Live just-in-time privilege grants (Plate D-012's bar chip).
    property var grants: []

    // RFC 3339 timestamp of the file itself ("" = no data).
    property string updatedAt: ""

    // True once a parse has succeeded, so a surface can tell "punard has
    // not written the file yet" from "nothing is pending".
    property bool loaded: false

    // Pending approvals, in file order. Expiry is NOT filtered here: the
    // consumer computes the countdown locally and renders
    // "Expired · denied by timeout" the moment the clock reaches zero,
    // whether or not punard has swept yet (ipc.md §14.4). Dropping the
    // record early would hide the verdict the human is owed.
    readonly property var pending: {
        var out = [];
        for (var i = 0; i < root.approvals.length; i++) {
            if (root.status(root.approvals[i]) === "pending")
                out.push(root.approvals[i]);
        }
        return out;
    }

    readonly property int pendingCount: root.pending.length

    function resetEmpty(): void {
        root.approvals = [];
        root.grants = [];
        root.updatedAt = "";
        root.loaded = false;
    }

    // ---- record accessors (tolerant, never throwing) ----

    function str(obj: var, key: string): string {
        if (obj === null || obj === undefined || typeof obj !== "object")
            return "";
        var v = obj[key];
        return typeof v === "string" ? v : "";
    }

    function id(approval: var): string {
        return root.str(approval, "approval_id");
    }

    function status(approval: var): string {
        var s = root.str(approval, "status");
        // A record with no status is not assumed to be pending: an
        // unreadable state must never manufacture a gate.
        return s === "" ? "unknown" : s;
    }

    // The record with this id, or null. Callers treat null as "gone".
    function byId(approvalId: string): var {
        if (approvalId === "")
            return null;
        for (var i = 0; i < root.approvals.length; i++) {
            if (root.id(root.approvals[i]) === approvalId)
                return root.approvals[i];
        }
        return null;
    }

    // ---- time, computed by the consumer from expires_at (ipc.md §15) ----

    // Seconds until `iso`, negative once past. Returns 0 for anything
    // unparsable — a card with no readable expiry renders as expired
    // rather than as endless, because failing closed is the whole point
    // of this surface.
    //
    // Clamped to ±[clampSeconds] seconds so the result always fits the `int`
    // return: an approval lives at most 300 s (ipc.md §14.4) and a grant
    // at most 60 minutes (§14.8), so nothing real is ever clipped — but a
    // malformed far-future stamp must not wrap around into a negative
    // number and silently read as EXPIRED.
    readonly property int clampSeconds: 86400

    function secondsUntil(iso: string, nowMs: real): int {
        if (iso === "")
            return 0;
        var at = Date.parse(iso);
        if (isNaN(at))
            return 0;
        var delta = Math.floor((at - nowMs) / 1000);
        return Math.max(-root.clampSeconds, Math.min(root.clampSeconds, delta));
    }

    // `M:SS`, tabular, never negative (Plate D-003's countdown).
    function clock(seconds: int): string {
        var s = Math.max(0, seconds);
        var m = Math.floor(s / 60);
        var r = s % 60;
        return m + ":" + (r < 10 ? "0" + r : String(r));
    }

    // `MM:SS` — the bar chip's wider spelling (Plate D-012:
    // "ELEVATED · 14:32 REMAINING").
    function clockWide(seconds: int): string {
        var s = Math.max(0, seconds);
        var m = Math.floor(s / 60);
        var r = s % 60;
        return (m < 10 ? "0" + m : String(m)) + ":" + (r < 10 ? "0" + r : String(r));
    }

    // The grant with the least time left that is still alive at `nowMs`,
    // or null. One chip, the one about to lapse — privilege is visible
    // for exactly as long as it exists, and the chip that matters is the
    // one whose clock is running out.
    function liveGrant(nowMs: real): var {
        var best = null;
        var bestLeft = 0;
        for (var i = 0; i < root.grants.length; i++) {
            var g = root.grants[i];
            var left = root.secondsUntil(root.str(g, "expires_at"), nowMs);
            if (left <= 0)
                continue;
            if (best === null || left < bestLeft) {
                best = g;
                bestLeft = left;
            }
        }
        return best;
    }

    function loadApprovals(): void {
        var j = null;
        try {
            j = JSON.parse(approvalsFile.text());
        } catch (e) {
            j = null;
        }
        if (j === null || typeof j !== "object") {
            root.resetEmpty();
            return;
        }
        root.approvals = Array.isArray(j.approvals) ? j.approvals : [];
        root.grants = Array.isArray(j.grants) ? j.grants : [];
        root.updatedAt = typeof j.updated_at === "string" ? j.updated_at : "";
        root.loaded = true;
    }

    // One-shot re-read on user action — covers a file that did not exist
    // when the watch was armed (punard started after the shell). An event
    // per action, not a poll.
    function refresh(): void {
        approvalsFile.reload();
    }

    FileView {
        id: approvalsFile
        path: root.approvalsPath
        // punard replaces the file atomically; the inotify watch follows
        // the change — event-driven, never a timer (PERFORMANCE_BUDGETS.md:
        // no polling loops).
        watchChanges: true
        onLoaded: root.loadApprovals()
        onFileChanged: approvalsFile.reload()
        // Absent or unreadable: punard not running, or this user is not in
        // group punar. Either way: nothing is pending, calmly.
        onLoadFailed: root.resetEmpty()
    }
}
