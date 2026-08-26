// BindRow — one binding in the help surface (Plate D-017 Sect IV).
//
// Modifiers chain outward-in, in the canonical order, joined by an ink-3
// plus: Super + Shift + H. Both modifiers recede identically, so
// SUPER+SHIFT+H and SUPER+H differ by one inserted grey object and the
// same black key sits at the end of both — the reader compares the ENDS
// of the rows, which is where the meaning is. The plus is deliberately
// the keyboard vernacular and not a middle dot; the middle dot is the
// field note's separator for facts of equal weight, and these are not.
//
// A BARE SUBMAP KEY (Sect IV·05) arrives here with an empty `chordMods`,
// so it gets the cap silhouette with no companion and never appears
// outside the bounded mode block its parent draws. It would be cheaper to
// print it as plain text, and it would be wrong: bare text reads as
// prose, and this is still something you press.
//
// DEVIATION, STATED: the mockup marks the matched substring of a filtered
// label with a muted background. This row does not — every visible row
// already contains the query, and a rich-text pass over strings that come
// from a user-editable config file is a cost this surface does not need
// to pay to be read.

import QtQuick
import "../Theme"

Item {
    id: bindRow

    property var chordMods: []
    property string keyText: ""
    property string label: ""
    property bool isMode: false
    property bool repeats: false
    property bool selected: false

    signal revealRequested()

    implicitHeight: content.implicitHeight + 3
    height: implicitHeight

    onSelectedChanged: {
        if (bindRow.selected)
            bindRow.revealRequested();
    }

    // Selection is the 2px ink ring, inset, with no colour dependence —
    // the only ink on this surface that is not type (DESIGN_LANGUAGE.md
    // §9.4).
    Rectangle {
        anchors.fill: parent
        visible: bindRow.selected
        color: "transparent"
        radius: Theme.radiusTag
        border.width: 2
        border.color: Theme.shellFg
    }

    Row {
        id: content

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 4
        anchors.rightMargin: 4
        anchors.verticalCenter: parent.verticalCenter
        spacing: 7

        Row {
            anchors.verticalCenter: parent.verticalCenter
            spacing: 3

            Repeater {
                model: bindRow.chordMods

                delegate: Row {
                    id: modItem

                    required property string modelData

                    spacing: 3

                    ChordCap {
                        anchors.verticalCenter: parent.verticalCenter
                        kind: "mod"
                        text: modItem.modelData
                    }
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        text: "+"
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        color: Theme.shellInk3
                    }
                }
            }

            ChordCap {
                anchors.verticalCenter: parent.verticalCenter
                kind: "term"
                text: bindRow.keyText
            }
        }

        // The label, verbatim from the compositor's own `description`
        // field — never rewritten, never title-cased by the shell.
        Text {
            anchors.verticalCenter: parent.verticalCenter
            width: Math.max(0, content.width - x - tag.width - content.spacing)
            text: bindRow.label
            elide: Text.ElideRight
            font.family: Theme.fontSans
            font.pixelSize: 14
            color: Theme.shellInk2
        }

        // The MODE tag is derived from the dispatcher being `submap`, not
        // from a hand annotation, so it never reads as one more toggle.
        // The repeat flag is the one the JSON already carries, rather
        // than a comment claiming it.
        Rectangle {
            id: tag

            anchors.verticalCenter: parent.verticalCenter
            visible: bindRow.isMode || bindRow.repeats
            width: visible ? tagText.implicitWidth + 10 : 0
            height: tagText.implicitHeight + 4
            radius: Theme.radiusTag
            color: "transparent"
            border.width: Theme.hairline
            border.color: Theme.shellBorder

            Text {
                id: tagText

                anchors.centerIn: parent
                text: bindRow.isMode ? "Mode" : "Repeats"
                font.family: Theme.fontMono
                font.pixelSize: 9
                font.weight: 500
                font.letterSpacing: Theme.tracking(9, 0.14)
                font.capitalization: Font.AllUppercase
                color: Theme.shellInk3
            }
        }
    }
}
