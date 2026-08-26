// StatusSlot — one doorway in the bar's status cluster (Plate D-016,
// docs/design/mockups/menubar.html Sect V·03).
//
// The plate's component contract, verbatim: `label`, `value`, `severity`
// ("none" | "warn" | "bad"), `operating` (false draws the dashed underbar
// — DESIGN_LANGUAGE.md §7's production-claim rule applied to our own
// chrome), `detailLevel` (3 → 0, driven by the cluster measuring
// implicitWidth against the width it has — pure layout, never a data
// change), and an `activated()` signal.
//
// COLOUR DISCIPLINE (D-016 Sect II·03, binding): the bar spends no colour
// on things that are merely TRUE. A running agent, a live environment, a
// valid credential are facts and render in ink. `severity` is only ever
// "warn" for something pending or expiring and "bad" for something
// unrecognised — a decision or a deviation, never a state of health.
//
// THE UNMISSABLE ONE (Sect II·04): the flag group is the unknown-AI
// reinforcement — a WORD and not a glyph, in the bad colour, immune to
// every collapse rule. It is deliberately phrased as an observation: the
// bar counts what was detected and never claims the absence of what was
// not (spec §23, §1.22).
//
// NOTHING HERE ANIMATES AT REST (Sect II·05): no pulse, no blink, no
// spinner, no progress sweep. The arrival fade-and-slide is owned by the
// cluster and runs once, on arrival.

import QtQuick
import "../Theme"

Item {
    id: slot

    // ---- the plate's contract ----
    property string label: ""
    property string value: ""
    // Shed first when the row runs out of room (Sect I·05): the agent
    // name, the environment name, the credential name, the org name.
    property string detail: ""
    property string severity: "none" // "none" | "warn" | "bad"
    property bool operating: true
    property int detailLevel: 3

    // The unknown-AI reinforcement. Empty = absent, which is the calm case.
    property string flagLabel: ""
    property string flagValue: ""

    // Focus/selection state, owned by the cluster.
    property bool selected: false
    readonly property alias hovered: hoverArea.containsMouse

    signal activated()
    signal pressedOnce()

    implicitWidth: content.implicitWidth + 6
    implicitHeight: 22
    // A slot with nothing to say does not exist (Sect I·04 "absent when
    // over"): presence is information, so an empty slot is never drawn
    // greyed out waiting to light up.
    visible: slot.label !== "" || slot.flagLabel !== ""

    readonly property color severityColor: {
        switch (slot.severity) {
        case "bad":
            return Theme.shellStatusBad;
        case "warn":
            return Theme.shellStatusWarn;
        default:
            return Theme.shellFg;
        }
    }

    // Detail is shed, never presence (Sect I·05). Level 3 is the full
    // row; below 2 the optional detail string goes and nothing else does.
    readonly property bool showDetail: slot.detail !== "" && slot.detailLevel >= 2

    component SlotLabel: Text {
        font.family: Theme.fontMono
        font.pixelSize: 11
        font.weight: 500
        font.letterSpacing: Theme.tracking(11, 0.12)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    Row {
        id: content

        anchors.centerIn: parent
        spacing: 5

        // The dot carries the colour when the word has to go (Sect I·05:
        // "the compliance word (the dot keeps the colour)").
        Rectangle {
            anchors.verticalCenter: parent.verticalCenter
            visible: slot.severity !== "none"
            width: 5
            height: 5
            radius: 2.5
            color: slot.severityColor
        }

        SlotLabel {
            text: slot.label
            color: slot.severity === "none" ? Theme.shellInk3 : slot.severityColor
        }

        SlotLabel {
            visible: slot.value !== ""
            text: slot.value
            font.weight: 600
            color: slot.severity === "none" ? Theme.shellFg : slot.severityColor
        }

        SlotLabel {
            visible: slot.showDetail
            text: slot.detail
        }

        // The one thing that may never be missed: a word, in the bad
        // colour, never collapsed at any width.
        Rectangle {
            anchors.verticalCenter: parent.verticalCenter
            visible: slot.flagLabel !== ""
            width: 5
            height: 5
            radius: 2.5
            color: Theme.shellStatusBad
        }
        SlotLabel {
            visible: slot.flagLabel !== ""
            text: slot.flagLabel
            font.weight: 600
            color: Theme.shellStatusBad
        }
        SlotLabel {
            visible: slot.flagLabel !== "" && slot.flagValue !== ""
            text: slot.flagValue
            font.weight: 600
            color: Theme.shellStatusBad
        }
    }

    // §7 stroke semantics on our own chrome: a slot whose whole path is
    // not yet operating wears a dashed underbar. Nothing rendered on a
    // real machine today sets this false — the slots whose mechanisms are
    // not operating (environments, credentials) do not render at all,
    // which is the stronger form of the same claim.
    Canvas {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: 2
        visible: !slot.operating

        onPaint: {
            var ctx = getContext("2d");
            ctx.clearRect(0, 0, width, height);
            ctx.strokeStyle = String(Theme.shellInputBorder);
            ctx.lineWidth = 1;
            ctx.setLineDash([3, 3]);
            ctx.beginPath();
            ctx.moveTo(0, 0.5);
            ctx.lineTo(width, 0.5);
            ctx.stroke();
        }
        onVisibleChanged: if (visible)
            requestPaint()
        onWidthChanged: requestPaint()
    }

    // Focus ring: 2px ink drawn INSET — a 30px bar has no room for a 2px
    // offset — and with no colour dependence (DESIGN_LANGUAGE.md §9.4,
    // D-016 Sect III·05).
    Rectangle {
        anchors.fill: parent
        visible: slot.selected
        color: "transparent"
        radius: 4
        border.width: 2
        border.color: Theme.shellFg
    }

    // The mouse still works (Sect III·02): the first click focuses the
    // slot and opens its popover, a second click opens the surface. The
    // cluster owns which of the two this is.
    MouseArea {
        id: hoverArea

        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: slot.pressedOnce()
    }
}
