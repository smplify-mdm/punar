pragma Singleton
// Status — enrollment / compliance context for masthead meta rows.
//
// Milestone 5: wired to punard's `/run/punar/status.json` summary file
// (side contract: docs/api/ipc.md §9; design: milestone-5.md §8). punard
// rewrites the file atomically (tmp+rename within /run/punar) at startup
// and whenever the summary tuple changes; this singleton follows it with
// a FileView change watch (inotify — event-driven, ZERO polling; the
// presetFile pattern in WorkspaceState.qml) and maps the summary onto the
// word/dot grammar of DESIGN_LANGUAGE.md §2.
//
// UNMANAGED-FIRST (DESIGN_LANGUAGE.md §8): an unenrolled device shows NO
// org chrome — org state is additive annotation, its absence is calm
// paper, and a personal device must never imply it is being measured.
// Fail CLOSED, enforced here at the source: a missing or unparsable
// status.json reads as personal (`enrolled: false`). The file is
// non-authoritative display data in a user-owned directory (ipc.md §9);
// anything root-trusted stays on the punard socket.

import QtQuick
import Quickshell
import Quickshell.Io
import "../Theme"

Singleton {
    id: root

    readonly property string statusPath: "/run/punar/status.json"

    // True only while status.json says so. Consumers render org chrome
    // only when this is true — the §8 rule (Bar gates every org element,
    // dot included, on it).
    property bool enrolled: false

    // Organization display name ("Acme Engineering"); "" when personal.
    property string orgName: ""

    // Raw spec §52 `compliance_overall` from status.json ("compliant",
    // "non_compliant", "remediating", "exception", "unknown"). "" is the
    // personal sentinel — no org data — under which the derived
    // state/label keep the pre-M5 stub defaults, so unenrolled surfaces
    // (the command-center masthead) render exactly as before.
    property string complianceState: ""

    // "ok" | "warn" | "bad" — maps 1:1 to spec §52 decision states.
    readonly property string state: {
        switch (root.complianceState) {
        case "non_compliant":
            return "bad";
        case "":
        case "compliant":
            return "ok";
        default:
            return "warn"; // remediating / exception / unknown / future
        }
    }

    // Word shown next to the dot. Uppercased by the consuming label.
    readonly property string label: {
        switch (root.complianceState) {
        case "non_compliant":
            return "Non-compliant";
        case "remediating":
            return "Remediating";
        case "exception":
            return "Exception";
        case "":
        case "compliant":
            return "Compliant";
        default:
            return "Unknown";
        }
    }

    // Active project placeholder — the bar shows real workspace names
    // (M2); this remains for the command-center masthead meta row.
    readonly property string project: "Local"

    readonly property color color: {
        switch (root.state) {
        case "warn":
            return Theme.statusWarn;
        case "bad":
            return Theme.statusBad;
        default:
            return Theme.statusOk;
        }
    }

    // Fail-closed default: personal calm paper (design §8).
    function resetPersonal(): void {
        root.enrolled = false;
        root.orgName = "";
        root.complianceState = "";
    }

    function loadStatus(): void {
        var j = null;
        try {
            j = JSON.parse(statusFile.text());
        } catch (e) {
            j = null;
        }
        if (j === null || typeof j !== "object") {
            root.resetPersonal();
            return;
        }
        root.enrolled = j.enrolled === true;
        root.orgName = (root.enrolled && typeof j.org_name === "string")
            ? j.org_name : "";
        // Enrolled with a missing or non-string overall reads as
        // "unknown" — never silently green on a managed device.
        root.complianceState = root.enrolled
            ? (typeof j.compliance_overall === "string"
               && j.compliance_overall !== ""
               ? j.compliance_overall : "unknown")
            : "";
    }

    FileView {
        id: statusFile
        path: root.statusPath
        // punard replaces the file atomically; the inotify watch follows
        // the change — event-driven, never a timer (PERFORMANCE_BUDGETS.md:
        // no polling loops).
        watchChanges: true
        onLoaded: root.loadStatus()
        onFileChanged: statusFile.reload()
        // Absent file: personal device, or punard not started (dev
        // machines) — calm paper either way.
        onLoadFailed: root.resetPersonal()
    }
}
