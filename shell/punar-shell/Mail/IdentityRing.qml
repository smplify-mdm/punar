// The identity ring — the colours a person's own labels and calendars carry.
//
// NOT NAMED Palette, AND THAT IS NOT TASTE. QtQuick registers a built-in
// `Palette` type (QtQuick/Palette 6.0), so a file of that name collides with
// it: qmllint resolved Qt's type and reported every member of this one
// missing, while the runtime preferred the local file and rendered correctly.
// A warning at every call site and a screenshot that looks right is the worst
// pairing available — the lint says the code is wrong and the picture says it
// is fine. Do not name a QML file after a Qt type.
//
// Eight slots: seven hues on a fixed CIELAB LCh ring plus a neutral. Designed
// and measured in docs/design/calendar.md §2; labels and calendars are the same
// kind of thing (a name the person assigned) and share one palette rather than
// growing two that drift.
//
// WHY THESE VALUES AND NOT PRETTIER ONES. DESIGN_LANGUAGE.md §2's "Application
// color" amendment permits colour in an application on four conditions, and
// three of them are arithmetic:
//
//   · The ok/warn/bad triad stays reserved. Identity accents sit at C* 30 while
//     the paper triad measures C* 49.0 / 52.3 / 59.4, and the minimum ΔE*76
//     from any slot to any status value is 26.4 — above the 25 floor
//     ThemeContrast already uses to keep the three statuses apart. A green
//     label can never be read as a compliance verdict.
//   · Identity colour is a TINT and never the colour of a word that must be
//     read. The fill carries the hue; the text stays ink.
//   · Nothing is colour-only. A chip prints its label's NAME; the hue is a
//     second channel on top of a word, never instead of one.
//
// THE TINTS ARE ALL AT L* 93, and that is the load-bearing decision rather than
// a coincidence. CIE L* is a pure function of relative luminance, so every tint
// at the same L* has the same luminance and therefore the same contrast ratio
// against any text colour. Measured: ink2 on any of these is 10.56–10.61:1 and
// ink3 is 4.80–4.82:1. One proof binds all eight, and any hue added later.
//
// Panel values are not inversions. On panel the triad is a different, lighter
// set with less chroma headroom, so the accents lift to L* 58 and the tints
// drop to L* 20; panelInk3 measures 3.39:1 on a panel tint and FAILS the 4.5
// text floor, which is why panel chip text is panelInk2 at 5.81:1.

import QtQuick

QtObject {
    id: root

    readonly property var names: ["rose", "clay", "olive", "moss", "teal", "indigo", "plum", "stone"]

    readonly property var paperTint: ["#FFE4EB", "#FFE6DB", "#EFECD6", "#DBF0E1",
                                      "#D1F1F3", "#DBEDFF", "#F1E7FC", "#EEEBE3"]
    readonly property var panelTint: ["#402A31", "#3E2C24", "#333121", "#233429",
                                      "#183537", "#213240", "#342D3D", "#2E3036"]

    readonly property var paperAccent: ["#B16D82", "#AC745A", "#88834E", "#548D69",
                                        "#1B8F96", "#4887B3", "#8D78AA", "#83817A"]
    readonly property var panelAccent: ["#BD778D", "#B77E64", "#928D58", "#5E9873",
                                        "#2C99A1", "#5491BE", "#9882B5", "#888C92"]

    // Slot 7 (stone) is the neutral and the right answer for anything the
    // person has not coloured — not a hue chosen on their behalf.
    readonly property int neutralSlot: 7

    // NO MOOD DECISION AND NO Theme IMPORT. This file is values only. Deciding
    // paper-versus-panel belongs to the surface, which already imports Theme —
    // and importing it here also broke qmllint's view of the type through the
    // implicit directory import, so the members went unresolvable at every call
    // site while the runtime worked. A data file with no dependencies cannot
    // have that problem.
}
