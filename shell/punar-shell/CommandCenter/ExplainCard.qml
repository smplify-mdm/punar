pragma ComponentBehavior: Bound
// ExplainCard — the §40 answer, rendered inside the command center.
//
// D-003 Sect I state 04 ("Questions"): a question typed into the same
// field that launches applications answers inline with the effective
// value, its named source, whether the reader may change it, and the
// compliance state — spec §40's information set, reached from spec
// §12.2's one input.
//
// The content is NOT composed here. It is the verbatim result of
// `punarctl --json policy explain <path>` (contract §5.8), parsed by the
// caller: the graphical shell and the terminal read the same bytes from
// the same daemon, which is spec §10's promise made visible.
//
// Honesty rules kept here:
//   - the card draws NO button. The mockup's "Open policy" control has no
//     surface behind it on this build, and spec §1.22 forbids a control
//     that does nothing; what ships instead is the exact `punarctl` verb
//     that changes the value — the M13 decision-13 / D-014 precedent
//     ("every row prints the verb that changes it").
//   - colour appears only when the answer carries a decision: an override
//     the reader may not make is the amber approval-required voice, a
//     non-compliant state is the red one. A compliant, user-owned value
//     is pure monochrome (DESIGN_LANGUAGE §2).
//   - a failed call says the call failed. It never renders a blank card
//     that reads as "no restrictions".

import QtQuick
import "../Theme"

Item {
    id: root

    // "asking" · "answered" · "failed"
    property string phase: "asking"
    property string path: ""

    // Parsed §5.8 body (only meaningful while phase === "answered").
    property string effective: ""
    property string sourceName: ""
    property string policyId: ""
    property bool overridePermitted: false
    property string compliance: ""

    // Why the call could not answer (phase === "failed").
    property string failure: ""

    implicitHeight: body.implicitHeight + 32

    readonly property string changeVerb: "punarctl capabilities set " + root.path + " <state>"
    readonly property string askVerb: "punarctl policy explain " + root.path

    readonly property bool complianceIsPlain: root.compliance === "" || root.compliance === "compliant"

    readonly property color complianceColor: {
        switch (root.compliance) {
        case "non_compliant":
            return Theme.shellStatusBad;
        case "compliant":
        case "":
            return Theme.shellStatusOk;
        default:
            return Theme.shellStatusWarn; // remediating · exception · unknown
        }
    }

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 500
        font.letterSpacing: Theme.tracking(9, 0.12)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        wrapMode: Text.WordWrap
    }

    Column {
        id: body
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        anchors.topMargin: 16
        spacing: 4

        // The assertion (mockup .explain .st): one load-bearing sentence.
        Text {
            width: parent.width
            wrapMode: Text.WordWrap
            font.family: Theme.fontSans
            font.pixelSize: 16 // mockup 15.5px
            font.weight: 500
            lineHeight: 1.45
            lineHeightMode: Text.ProportionalHeight
            color: Theme.shellFg
            text: {
                if (root.phase === "asking")
                    return "Asking punard about " + root.path + "…";
                if (root.phase === "failed")
                    return "This device could not answer that.";
                return root.path + " is " + root.effective + " on this device.";
            }
        }

        // The reasoning (mockup .explain .why).
        Text {
            width: parent.width
            wrapMode: Text.WordWrap
            font.family: Theme.fontSans
            font.pixelSize: 14 // mockup 13.5px
            font.weight: 400
            color: Theme.shellInk2
            bottomPadding: 8
            text: {
                if (root.phase === "asking")
                    return "The policy engine is being asked for the effective value, its source, and your override permission.";
                if (root.phase === "failed")
                    return root.failure;
                return "Set by " + root.sourceName + ". " + (root.overridePermitted ? "You may change it — it is your device." : "A higher-precedence source pins this value, so your own override is not permitted.");
            }
        }

        // The named source (mockup .explain .pol) — authority always has a
        // name, personal or organizational (DESIGN_LANGUAGE §8).
        Meta {
            width: parent.width
            visible: root.phase === "answered"
            text: "Policy · " + root.sourceName + " · " + root.policyId
        }

        // Compliance, coloured only when it has something to report.
        Row {
            spacing: 6
            visible: root.phase === "answered" && root.compliance !== ""
            bottomPadding: 10

            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: 5
                height: 5
                radius: 2.5
                visible: !root.complianceIsPlain
                color: root.complianceColor
            }
            Meta {
                anchors.verticalCenter: parent.verticalCenter
                text: "Compliance · " + root.compliance.split("_").join(" ")
                color: root.complianceIsPlain ? Theme.shellInk3 : root.complianceColor
            }
        }

        // The action row (mockup .explain .acts) — statements, not buttons.
        Row {
            width: parent.width
            spacing: 8
            topPadding: root.phase === "answered" ? 0 : 8

            // The exact verb that changes this value, or — while the answer
            // is in flight or lost — the exact verb that asks for it.
            Rectangle {
                visible: root.phase !== "answered" || root.overridePermitted
                width: verbText.implicitWidth + 22
                height: verbText.implicitHeight + 12
                radius: Theme.radiusTag
                color: Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellFg

                Text {
                    id: verbText
                    anchors.centerIn: parent
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 600
                    font.letterSpacing: Theme.tracking(9, 0.1)
                    font.capitalization: Font.AllUppercase
                    color: Theme.shellFg
                    text: root.phase === "answered" ? root.changeVerb : root.askVerb
                }
            }

            // An override the reader may not make is an approval-required
            // decision, and wears the amber voice (DESIGN_LANGUAGE §2).
            Rectangle {
                visible: root.phase === "answered" && !root.overridePermitted
                width: pinText.implicitWidth + 20
                height: pinText.implicitHeight + 10
                radius: Theme.radiusTag
                color: Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellStatusWarn

                Text {
                    id: pinText
                    anchors.centerIn: parent
                    font.family: Theme.fontMono
                    font.pixelSize: 9
                    font.weight: 600
                    font.letterSpacing: Theme.tracking(9, 0.12)
                    font.capitalization: Font.AllUppercase
                    color: Theme.shellStatusWarn
                    text: "Pinned by " + root.policyId + " · ask the policy owner"
                }
            }
        }
    }
}
