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

    // Active Hyprland workspace in the masthead grammar (M2 named project
    // workspaces): a named workspace shows its NAME, an unnamed one falls
    // back to the number — Hyprland reports unnamed workspaces with the
    // numeric id as the name, which WorkspaceState.isNamed filters out.
    // Quickshell.Hyprland keeps this live via socket2 events (no polling);
    // renames land here the moment `renameworkspace` fires.
    readonly property string workspaceLabel: {
        var ws = Hyprland.focusedWorkspace;
        if (ws === null)
            return "1";
        return WorkspaceState.isNamed(ws) ? ws.name : String(ws.id);
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

        // Right: org name + compliance dot + word (enrolled only), then the
        // clock (data is always mono tabular; Geist Mono is inherently
        // tabular).
        Row {
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 6

            // Unmanaged-first (§8): org chrome renders only when enrolled —
            // a personal device's bar stays name + clock, byte-identical to
            // the pre-M5 bar (Row positioners skip invisible items).
            // Enrolled grammar (M5; system-control mockup masthead
            // compressed to bar scale — org name + state; policy ids stay
            // in punarctl): ORG NAME · <dot> STATE-WORD · CLOCK.
            MetaLabel {
                anchors.verticalCenter: parent.verticalCenter
                visible: Status.enrolled
                text: Status.orgName + " · "
            }
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 5
                height: 5
                radius: 2.5
                visible: Status.enrolled
                color: Status.color // live compliance via status.json (M5)
            }
            MetaLabel {
                anchors.verticalCenter: parent.verticalCenter
                visible: Status.enrolled
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
