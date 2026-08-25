pragma Singleton
// Status — compliance / project context for masthead meta rows.
//
// M1 STUB. Milestone 5 wires this to punard's real compliance state over
// typed IPC (spec §52 states, §63 device standing). UNMANAGED-FIRST
// (DESIGN_LANGUAGE.md §8): an unenrolled device shows NO compliance chrome
// — org state is additive annotation, its absence is calm paper, and a
// personal device must never imply it is being measured. `enrolled` stays
// false until M5's enrollment exists; the word/dot grammar below then
// follows §2 and the command-approval mockup masthead.

import QtQuick
import Quickshell
import "../Theme"

Singleton {
    id: root

    // False until M5 enrollment exists. Consumers render nothing while
    // unenrolled — the §8 rule, enforced here at the source.
    readonly property bool enrolled: false

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
