// Bar — the top bar, a paper masthead (DESIGN_LANGUAGE.md §5 "Masthead
// meta rows": tracked mono, middle-dot separators, left context / right
// data, closed by a rule — here the hairline bottom border).
//
// Deliberately calm (§2: a screen with no status to report contains no
// color): left context, empty center, right data. No battery/net widgets
// in M1 — calm beats complete; the VM target has neither.

import QtQuick
import Quickshell
import Quickshell.Wayland
import Quickshell.Hyprland
import "../Theme"
import "../Services"

PanelWindow {
    id: root

    // Emitted once the bar object tree is complete — shell.qml uses this
    // to write the desktop ready marker (see shell.qml).
    signal barCreated()

    anchors {
        top: true
        left: true
        right: true
    }
    implicitHeight: 30
    color: Theme.paperSurface
    WlrLayershell.namespace: "punar-bar"

    Component.onCompleted: root.barCreated()

    // Active Hyprland workspace: named workspaces show their name, numeric
    // ones their number (Quickshell.Hyprland keeps this live via IPC).
    readonly property string workspaceLabel: {
        var ws = Hyprland.focusedWorkspace;
        if (ws === null)
            return "1";
        return String(ws.name !== "" ? ws.name : ws.id);
    }

    // Meta-row label grammar: Geist Mono, tracked, uppercase (§1 type roles).
    component MetaLabel: Text {
        font.family: Theme.fontMono
        font.pixelSize: 11 // bar meta: 10–11px per type-role table
        font.weight: 500
        font.letterSpacing: Theme.tracking(11, 0.14)
        font.capitalization: Font.AllUppercase
        color: Theme.ink3
    }

    Item {
        anchors.fill: parent

        // Left: PUNAR · <workspace> — brand strong in ink, context in ink-3.
        Row {
            anchors.left: parent.left
            anchors.leftMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 0

            MetaLabel {
                text: "Punar"
                font.weight: 600
                color: Theme.ink
            }
            MetaLabel {
                text: " · " + root.workspaceLabel
            }
        }

        // Center intentionally empty — calm.

        // Right: compliance dot + word, then the clock (data is always mono
        // tabular; Geist Mono is inherently tabular).
        Row {
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 6

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 5
                height: 5
                radius: 2.5
                color: Status.color // stub singleton — M5 wires real compliance
            }
            MetaLabel {
                anchors.verticalCenter: parent.verticalCenter
                text: Status.label + " · "
            }
            MetaLabel {
                anchors.verticalCenter: parent.verticalCenter
                text: Qt.formatDateTime(clock.date, "HH:mm")
                color: Theme.ink2
            }
        }

        // The rule that closes the masthead (§3: structure drawn with rules).
        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: Theme.hairline
            color: Theme.border
        }
    }

    SystemClock {
        id: clock
        precision: SystemClock.Minutes
    }
}
