pragma Singleton
// Status — compliance / project context for masthead meta rows.
//
// M1 STUB. Milestone 5 wires this to punard's real compliance state over
// typed IPC (spec §52 states, §63 device standing). Until then the device
// reports the only state M1 can honestly claim for a local, policy-free
// session: compliant, no managed project. The word/dot grammar follows
// DESIGN_LANGUAGE.md §2 (status colors are the only real colors) and the
// masthead in docs/design/mockups/command-approval.html
// ("Atlas · Compliant" with the ok dot).

import QtQuick
import Quickshell
import "../Theme"

Singleton {
    id: root

    // "ok" | "warn" | "bad" — maps 1:1 to spec §52 decision states.
    readonly property string state: "ok"

    // Word shown next to the dot. Uppercased by the consuming label.
    readonly property string label: {
        switch (root.state) {
        case "warn":
            return "Remediating";
        case "bad":
            return "Non-compliant";
        default:
            return "Compliant";
        }
    }

    // Active project placeholder — real named projects arrive in M2.
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
}
