// ChordCap — one key cap in a chord (Plate D-017 Sect IV,
// docs/design/mockups/shortcuts.html).
//
// A chord is TYPESET, not spelled: the modifier is the constant and the
// key is the variable, and the type says which is which before the words
// are read.
//
//   · A MODIFIER cap is ink-3 on a `border` hairline with no fill — it
//     recedes, because on a page of PUNAR chords it carries no
//     information.
//   · A TERMINAL KEY cap is ink on an input-weight hairline with the
//     muted fill — it is the thing that varies and the thing the reader
//     is looking for. It carries a min-width so a one-character key and a
//     five-character key make the same silhouette down a column.
//
// Tracking is 0.10em rather than the 0.12–0.14em of meta rows because a
// cap is a UNIT, not a label: it must hold together as one object.
//
// MONOCHROME ON PURPOSE (Sect IV·06): a keyboard reference has no status
// to report — nothing here is compliant, pending, expiring or denied — so
// neither surface contains a single status colour. The only ink that is
// not ink is the focus ring, and it is ink too.

import QtQuick
import "../Theme"

Rectangle {
    id: cap

    // "mod" | "term"
    property string kind: "term"
    property string text: ""
    property int fontSize: 10

    implicitWidth: Math.max(cap.kind === "term" ? 22 : 0, glyph.implicitWidth + 14)
    implicitHeight: glyph.implicitHeight + 5
    radius: Theme.radiusTag
    color: cap.kind === "term" ? Theme.shellMuted : "transparent"
    border.width: Theme.hairline
    border.color: cap.kind === "term" ? Theme.shellInputBorder : Theme.shellBorder

    Text {
        id: glyph

        anchors.centerIn: parent
        text: cap.text
        font.family: Theme.fontMono
        font.pixelSize: cap.fontSize
        font.weight: 500
        font.letterSpacing: Theme.tracking(cap.fontSize, 0.1)
        font.capitalization: Font.AllUppercase
        color: cap.kind === "term" ? Theme.shellFg : Theme.shellInk3
    }
}
