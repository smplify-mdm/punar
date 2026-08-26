// Wallpaper — the desktop field (Plate D-015, docs/design/mockups/wallpaper.html).
//
// "The desktop is the sheet a plate is drawn on, not a picture hung on a wall."
// The background is the same instrument that draws the boot ring — a sixty-slot
// dial, four concentric hairlines, dashed radials, one datum point — printed on
// the field at watermark contrast, with the boot dial's progress arc REMOVED,
// because an idle desktop is not doing anything and a ring that implied
// progress would be a claim (D-015 Sect I.01, design language §7).
//
// This is Plate D-015 Sect V.03 "Delivery — recommended", implemented exactly
// as the plate specifies it: a Quickshell background layer window inside the
// existing punar-shell process. No hyprpaper, no second daemon, no new unit, no
// new socket (Sect V.04).
//
// ZERO INPUTS (Sect V.01). This is the only shell surface with no data behind
// it: it does not read /run/punar/status.json, agents.json, alerts.json or
// approvals.json, it holds no IPC subscription, and it has no timer of any
// kind. Nothing the machine can observe is allowed to change the field — which
// is also why it can never lie (spec §1.22). The only thing it follows is the
// active theme, and a theme is a preference the user set, not an observation.
//
// ZERO IDLE COST (Sect IV.04, spec §6.3). No animation, no script, no polling.
// The SVG is rasterized once per output, at the size that output actually is,
// and is a static texture thereafter. It is re-rasterized only on two events:
// the output's resolution changing (the anchored layer surface resizes, and
// `sourceSize` is bound to that size) and the theme changing (an inotify event
// on the pointer or the theme document, through Theme). Output add/remove is
// handled by `Variants` over `Quickshell.screens`, which is a live list — no
// enumeration loop anywhere.
//
// NOT KEYBOARD-OPERABLE, AND CORRECTLY SO (spec §12). The field carries no
// control, so there is nothing to operate and nothing to focus; it takes no
// keyboard focus at all (layer-shell keyboard-interactivity none, the default
// for the background layer) so it can never steal a keystroke from a surface
// that does have controls. Adding a focus ring to a picture would be exactly
// the "control that does nothing" spec §1.22 forbids.
//
// FOLLOWS THE THEME (theme-system.md §7.3, with one measured correction to its
// panel row that is argued in full in ../Theme/Theme.qml). One template, three
// substitutions, and the paper/panel variant IS the active mood:
//
//   variant   field           hairline                              emphasis
//   paper     paper.surface   paper.muted                           paper.raise2
//   panel     panel.surface   mix(panel.surface, panel.edge, 0.42)  mix(panel.surface, panel.edge, 0.75)
//
// Everything else in the drawing — the 1600x1000 viewBox, the dial at
// (1152, 500) radius 208, the overscanned flat field, the 60-slot Morse rim —
// is geometry, and geometry is grammar. A theme cannot move the dial.
//
// On the paper side the marks stay strictly quieter than a window border in
// every SELECTABLE theme because validator rule R7 (theme-system.md §4.2)
// refuses a palette where they would not: contrast(border, surface) must
// strictly exceed both contrast(raise2, surface) and contrast(muted, surface).
// Plate D-015 Sect II.02 states that rule; R7 is where it is now enforced. On
// the panel side the 0.75 factor is what keeps the emphasis strictly under
// panel.edge, which §7.2 binds the inactive window border to.
//
// MEMORY. One texture per output at the fitted size, RGBA8888: ~7.5 MB at
// 1920x1080, ~30 MB at 3840x2160, plus ~5 KB of parsed SVG and one shared
// template string. That is the figure Plate D-015 Sect V.03 already budgeted
// ("about 8 MB at 1080p, 33 MB at 4K"). punar-shell is a USER process and is
// not part of the spec §6.2 daemon RSS gate, which sums the punar daemons; this
// surface adds no daemon and changes that sum by zero.
//
// PACKAGING. Rendering SVG needs Qt's svg image-format plugin
// (/usr/lib/qt6/plugins/imageformats/libqsvg.so, package qt6-svg). It is
// present in the punar-desktop image today only TRANSITIVELY: `quickshell`
// 0.3.0-3 lists qt6-svg as a hard dependency, so pacman installs it. It is NOT
// named in os/images/mkosi.profiles/desktop/mkosi.conf. Depending on another
// package's dependency list for a file this surface reads directly is exactly
// the kind of unstated assumption spec §1.22 exists to stop — the integrator
// should add `qt6-svg` to that Packages list explicitly.

// `Bound` because the per-output delegate below reads the shared template and
// the sheet geometry from this file's root: it makes those captures explicit
// (and qmllint-clean) instead of relying on dynamic scope, and it is safe here
// because the delegate already declares `required property var modelData`.
pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Theme"

Scope {
    id: root

    // The reference sheet (D-015 Sect III.01): a 16:10 drawing, dial at 72%
    // horizontally and vertically centred, so the tightest landscape crop
    // cannot touch it.
    readonly property int sheetWidth: 1600
    readonly property int sheetHeight: 1000

    // The template ships beside this file, so one path works in both the
    // installed layout (/usr/share/punar/shell/Wallpaper/) and the repo
    // (shell/punar-shell/Wallpaper/) — no candidate walking needed.
    readonly property string templatePath: Quickshell.shellDir + "/Wallpaper/punar-wallpaper.svg.in"

    property string template: ""

    // The three substitutions of theme-system.md §7.3, and nothing else.
    // Reading Theme.wallpaper* here is what makes a theme switch repaint the
    // desktop with no restart: the pointer's FileView fires, Theme's derived
    // properties re-evaluate, this string rebuilds, and the Image re-rasterizes.
    readonly property string svg: {
        if (root.template === "")
            return "";
        return root.template.split("__FIELD__").join(Theme.wallpaperField).split("__HAIRLINE__").join(Theme.wallpaperHairline).split("__EMPHASIS__").join(Theme.wallpaperEmphasis);
    }

    FileView {
        id: templateFile
        path: root.templatePath
        // Blocking, so the very first frame is already the drawing and not a
        // flat rectangle. It is ~5 KB and read exactly once.
        blockLoading: true
        onLoaded: root.template = templateFile.text()
        onLoadFailed: {
            // Backstop (D-015 Sect V.05): with no template the layer window is
            // still the field colour, which is what the compositor's
            // misc:background_color already paints. The desktop degrades to
            // "flat token colour" — precisely the state the system was in
            // before this surface existed, never to black and never to an error.
            console.warn("punar-shell: wallpaper template not found at", templateFile.path, "— desktop falls back to the flat field colour");
            root.template = "";
        }
    }

    // ---- why the substituted drawing goes through a file, not a data: URI ----
    //
    // Feeding the substituted SVG to Image as
    // "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg) renders
    // correctly — but it LEAKS. Measured on Quickshell 0.3.0 / Qt 6.11.2 /
    // qt6-svg 6.11.2 (headless sway, 1920x1080, 2026-08-26), cycling the seven
    // shipped themes: the data-URI source grows RSS by ~4.4 MB per switch,
    // linearly, with no plateau — 320 MB at start, 752 MB after sixty switches.
    // `cache: true` does not help (~4.6 MB per switch). The same drawing loaded
    // from a `file://` URL does not grow at all (it tracks the -2.6 MB per
    // switch downward drift the process shows with no Image present). Roughly
    // one decoded image is retained per data-URL load, and a desktop that gains
    // a third of a gigabyte because someone tried the palettes is not shippable.
    //
    // So the substituted drawing is written once per theme change into the
    // session's runtime directory and loaded from there. That is ~5 KB of tmpfs,
    // session-scoped, gone at logout, written only on a deliberate user action,
    // and shared by every output. The generation counter in the query string is
    // what makes the URL differ so the Image reloads; the path it resolves to is
    // the same file.
    //
    // This is the one thing in this surface that is a workaround rather than a
    // design, and it is written down as one.
    readonly property string runtimeDir: {
        var rt = Quickshell.env("XDG_RUNTIME_DIR");
        return rt ? rt : "";
    }

    readonly property string renderPath: root.runtimeDir === "" ? "" : root.runtimeDir + "/punar/wallpaper.svg"

    property int generation: 0
    property string svgSource: ""

    function renderSvg(): void {
        if (root.svg === "" || root.renderPath === "") {
            root.svgSource = "";
            return;
        }
        // atomicWrites: QSaveFile tmp+rename, parent directories created. The
        // source is set from onSaved, so the Image is never pointed at a file
        // whose bytes are still in flight.
        renderFile.setText(root.svg);
    }

    onSvgChanged: root.renderSvg()

    FileView {
        id: renderFile
        path: root.renderPath
        atomicWrites: true
        watchChanges: false // this surface is the only writer
        printErrors: false
        onSaved: {
            root.generation += 1;
            root.svgSource = "file://" + root.renderPath + "?g=" + root.generation;
        }
        onSaveFailed: {
            console.warn("punar-shell: could not write the wallpaper drawing to", root.renderPath, "— desktop falls back to the flat field colour");
            root.svgSource = "";
        }
    }

    // One background layer window per output. Quickshell.screens is a live
    // list, so an output plugged in gets a window and an output removed takes
    // its window with it, with no enumeration loop and no polling.
    Variants {
        model: Quickshell.screens

        PanelWindow {
            id: field

            required property var modelData

            screen: field.modelData

            // All four edges: the field is the whole output.
            anchors {
                top: true
                bottom: true
                left: true
                right: true
            }

            // A background must never take space from anything: no exclusive
            // zone, and it must not react to anyone else's.
            exclusionMode: ExclusionMode.Ignore
            exclusiveZone: 0

            WlrLayershell.layer: WlrLayer.Background
            WlrLayershell.namespace: "punar-wallpaper"
            WlrLayershell.keyboardFocus: WlrKeyboardFocus.None

            // Backstop 1 of 3 (D-015 Sect V.05): the window's own colour is the
            // field token. It is also what fills the letterbox bars below, and
            // because the field is one FLAT colour those bars are invisible on
            // every aspect ratio.
            color: Theme.wallpaperField

            // The fit scale of D-015 Sect III.03: the dial's diameter is always
            // 41.6% of the fitted height and its horizontal position always 72%
            // of the fitted width. The composition is a constant; only its
            // scale moves.
            readonly property real fitScale: (field.width <= 0 || field.height <= 0) ? 0 : Math.min(field.width / root.sheetWidth, field.height / root.sheetHeight)

            Image {
                anchors.fill: parent

                // Rasterize at EXACTLY the fitted 16:10 size rather than at the
                // output size. The SVG carries preserveAspectRatio="xMidYMid
                // meet", but Qt's SVG reader is not required to honour it when
                // handed a scaled size, and a stretched dial is an ellipse.
                // Fixing the raster's aspect makes the drawing's geometry
                // independent of that question, and PreserveAspectFit then
                // paints it at 1:1 with no resampling.
                sourceSize: Qt.size(Math.round(root.sheetWidth * field.fitScale), Math.round(root.sheetHeight * field.fitScale))
                fillMode: Image.PreserveAspectFit

                // Asynchronous so the layer surface maps immediately in the
                // field colour; the drawing arrives a frame or two later on the
                // same colour, so there is no flash of anything else.
                asynchronous: true

                // Every output rasterizes a different size and a theme switch
                // replaces the source outright — a cache keyed on a 9 KB data
                // URI would only hold dead textures.
                cache: false

                source: root.svgSource
                visible: root.svgSource !== "" && field.fitScale > 0
            }
        }
    }
}
