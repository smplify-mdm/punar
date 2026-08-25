// Bar — the top bar, a paper masthead (DESIGN_LANGUAGE.md §5 "Masthead
// meta rows": tracked mono, middle-dot separators, left context / right
// data, closed by a rule — here the hairline bottom border).
//
// Deliberately calm (§2: a screen with no status to report contains no
// color): left context, empty center, right data. No battery/net widgets
// in M1 — calm beats complete; the VM target has neither.
//
// M9 adds ONE element, and only while it is true: the ELEVATED countdown
// chip of docs/design/mockups/identity-elevation.html (Plate D-012 Sect
// I.03) — `ELEVATED · 14:32 REMAINING`, green while the grant is alive,
// amber in its final minute, GONE the moment it lapses. Privilege is
// never invisible on this device, and it is never permanent: there is no
// generic unrestricted root-shell API to fall back to. The chip is fed by
// the same summary file as the approval overlay (docs/api/ipc.md §15,
// which carries a `grants[]` array), read through the Approvals
// singleton's inotify FileView — no socket client in the bar.

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

    // ---- M9: the live privilege grant (Plate D-012 Sect I.03) ----

    // The grant about to lapse, recomputed every tick of `elevClock` —
    // which only runs while a grant exists (see below), so an unelevated
    // device pays nothing for this.
    readonly property var grant: Approvals.liveGrant(root.grantNowMs)

    readonly property real grantNowMs: elevClock.date ? elevClock.date.getTime() : 0

    readonly property int grantSecondsLeft: root.grant === null ? 0
        : Approvals.secondsUntil(Approvals.str(root.grant, "expires_at"), root.grantNowMs)

    // Green while active, amber in the final minute (D-012), gone at
    // zero — `grant` itself goes null, because `liveGrant` only returns
    // one with time left.
    readonly property color grantColor: root.grantSecondsLeft < 60 ? Theme.statusWarn
                                                                   : Theme.statusOk

    // Two-step revoke: armed by the first click, cleared by the second,
    // by the grant lapsing, or by a new grant replacing it.
    property bool revokeArmed: false

    onGrantChanged: root.revokeArmed = false

    function revokeGrant(): void {
        var id = Approvals.str(root.grant, "grant_id");
        if (id === "")
            return;
        if (!root.revokeArmed) {
            root.revokeArmed = true;
            return;
        }
        root.revokeArmed = false;
        try {
            Quickshell.execDetached(["punarctl", "privilege", "revoke", id]);
        } catch (e) {
            // No punarctl on a dev machine: the grant stands, and the
            // daemon remains the only thing that can end it.
            console.warn("punar-shell: privilege revoke unavailable:", e);
        }
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

        // Right: the elevation chip (only while a grant is alive), org
        // name + compliance dot + word (enrolled only), then the clock
        // (data is always mono tabular; Geist Mono is inherently tabular).
        Row {
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 6

            // Plate D-012's `.elevchip`. Absent by default: a calm bar is
            // a bar with no privilege to report, and its appearance is
            // the signal (Row positioners skip invisible items, so an
            // unelevated bar is byte-identical to the pre-M9 bar).
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                visible: root.grant !== null
                width: elevRow.implicitWidth + 16
                height: elevRow.implicitHeight + 6
                radius: Theme.radiusTag
                color: "transparent"
                border.width: Theme.hairline
                border.color: root.grantColor

                Row {
                    id: elevRow

                    anchors.centerIn: parent
                    spacing: 7

                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 5
                        height: 5
                        radius: 2.5
                        color: root.grantColor
                    }
                    MetaLabel {
                        anchors.verticalCenter: parent.verticalCenter
                        font.pixelSize: 9
                        font.letterSpacing: Theme.tracking(9, 0.13)
                        color: root.grantColor
                        // Tabular by construction — Geist Mono is.
                        text: "Elevated · " + Approvals.clockWide(root.grantSecondsLeft)
                            + " remaining"
                    }
                }

                // Revoking is one action, and it is real: the same fixed
                // argv `punarctl privilege revoke <gnt_id>` the CLI runs,
                // detached, with the daemon as the authorization point.
                // Two-step, like the AI panel's SHIFT+DEL — the first
                // click arms and the chip asks, the second acts — because
                // dropping privilege by accident is a surprise, and Punar
                // does not surprise.
                //
                // HONEST DEVIATION (stated, not hidden): D-012 draws `R`
                // as the binding. The bar is a non-focusable layer
                // surface and making it grab the keyboard to own one
                // letter would break every other keystroke on the
                // desktop, so M9 ships the click here and the keystroke
                // with the graphical elevation dialog (M13). The verb
                // itself already exists: punarctl privilege revoke.
                MouseArea {
                    anchors.fill: parent
                    cursorShape: Qt.PointingHandCursor
                    onClicked: root.revokeGrant()
                }
            }

            MetaLabel {
                anchors.verticalCenter: parent.verticalCenter
                visible: root.grant !== null && root.revokeArmed
                color: Theme.statusBad
                text: "Click again to revoke · "
            }

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

    // The chip's own second hand. `enabled` is bound to the existence of
    // a grant, so this clock does not tick at all on an unelevated device
    // — a UI clock with a visible consumer (the M1 bar clock precedent),
    // never a poll (PERFORMANCE_BUDGETS.md / spec §6.3).
    SystemClock {
        id: elevClock
        precision: SystemClock.Seconds
        enabled: Approvals.grants.length > 0
    }
}
