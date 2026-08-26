pragma ComponentBehavior: Bound
// SlotPopover — the bar cluster's popover (Plate D-016 Sect III·04).
//
// POPOVER ANATOMY, verbatim from the plate: focus and hover both open it;
// it is 268px wide, anchored to the slot's right edge, clamped inside the
// display, and never covers the clock (it hangs BELOW the bar, so it
// cannot). Five parts, in order: a tracked mono TITLE with the count; a
// hairline; at most THREE ROWS of detail in registry vocabulary, with
// "and N more" beyond that — it never scrolls, because the bar summarises
// and the owning surface details; a SOURCE LINE naming the file and its
// freshness, so the OS shows its evidence; and ONE ACTION LINE. No other
// buttons. Nothing in a popover is destructive, and nothing in a popover
// is the only way to reach something.
//
// It is its own layer surface because a 30px bar cannot contain a 200px
// card. It requests NO keyboard focus and its input region is masked to
// the card alone, so the desktop underneath it stays clickable and the
// popover can never take a keystroke (Sect III·05).

import QtQuick
import Quickshell
import Quickshell.Wayland
import "../Theme"

PanelWindow {
    id: popover

    // The slot descriptor from StatusCluster.slotModel, or null.
    property var slotData: null
    // Scene-x of the active slot's right edge, in the bar's coordinates.
    property real anchorRight: 0
    // Height of the bar the popover hangs from.
    property int barHeight: 30

    readonly property bool shown: popover.slotData !== null

    readonly property int cardWidth: 268

    visible: popover.shown
    anchors {
        top: true
        left: true
        right: true
    }
    implicitHeight: popover.barHeight + card.height + 20
    exclusionMode: ExclusionMode.Ignore
    color: "transparent"
    WlrLayershell.namespace: "punar-bar-popover"
    WlrLayershell.layer: WlrLayer.Overlay
    // Never — the bar's cluster owns the keyboard while it is focused,
    // and this surface must not compete for it.
    WlrLayershell.keyboardFocus: WlrKeyboardFocus.None
    // Only the card takes pointer input; the rest of this surface is
    // click-through, so a popover hanging over a window never eats a
    // click meant for it.
    mask: Region {
        item: card
    }

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 11
        font.weight: 500
        font.letterSpacing: Theme.tracking(11, 0.1)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        wrapMode: Text.WordWrap
    }

    function toneColor(tone: string): color {
        switch (tone) {
        case "bad":
            return Theme.shellStatusBad;
        case "warn":
            return Theme.shellStatusWarn;
        case "ok":
            return Theme.shellStatusOk;
        default:
            return Theme.shellFg;
        }
    }

    Rectangle {
        id: card

        width: popover.cardWidth
        // Anchored to the slot's right edge and clamped inside the
        // display, with the bar's own 12px margin as the floor.
        x: Math.max(12, Math.min(popover.width - popover.cardWidth - 12,
                                 popover.anchorRight - popover.cardWidth))
        y: popover.barHeight + 8
        height: body.implicitHeight + 24
        color: Theme.shellSurface
        border.width: Theme.hairline
        border.color: Theme.shellBorder
        radius: Theme.radius
        opacity: popover.shown ? 1 : 0

        // The soft drop shadow of the mockup is deliberately omitted, the
        // same M1 deviation the command center and overview make: blur is
        // costly on the llvmpipe VM path and the hairline carries the
        // separation (PERFORMANCE_BUDGETS.md).

        Behavior on opacity {
            NumberAnimation {
                duration: Theme.durStandard
                easing.type: Easing.BezierSpline
                easing.bezierCurve: Theme.easingCurve
            }
        }

        MouseArea {
            // The popover is a statement, not a control surface: it
            // absorbs clicks so they do not fall through, and does
            // nothing with them.
            anchors.fill: parent
        }

        Column {
            id: body

            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.leftMargin: 14
            anchors.rightMargin: 14
            anchors.topMargin: 12
            spacing: 7

            // 1 · title
            Meta {
                width: parent.width
                font.weight: 600
                font.letterSpacing: Theme.tracking(11, 0.14)
                color: Theme.shellFg
                text: popover.slotData === null ? "" : popover.slotData.title
            }

            // 2 · hairline
            Rectangle {
                width: parent.width
                height: Theme.hairline
                color: Theme.shellBorder
            }

            // 3 · at most three rows, in registry vocabulary
            Column {
                width: parent.width
                spacing: 3

                Repeater {
                    model: popover.slotData === null ? [] : popover.slotData.rows

                    delegate: Meta {
                        required property var modelData

                        width: parent === null ? 0 : parent.width
                        text: modelData.text
                        color: popover.toneColor(modelData.tone)
                        font.weight: modelData.tone === "none" ? 500 : 600
                    }
                }
            }

            // 4 · the source line — the OS showing its evidence
            Rectangle {
                width: parent.width
                height: Theme.hairline
                color: Theme.shellBorder
            }
            Meta {
                width: parent.width
                font.pixelSize: 9
                font.letterSpacing: Theme.tracking(9, 0.1)
                color: Theme.shellInputBorder
                text: popover.slotData === null ? "" : popover.slotData.source
            }

            // 5 · one action line, and no other buttons
            Meta {
                width: parent.width
                font.weight: 600
                font.letterSpacing: Theme.tracking(11, 0.12)
                color: Theme.shellFg
                text: popover.slotData === null ? "" : popover.slotData.action
            }
        }
    }
}
