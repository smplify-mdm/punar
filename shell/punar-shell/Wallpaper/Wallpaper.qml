// Wallpaper — the quiet desktop field.
//
// The owner brief now calls for an inviting high-resolution desktop field.
// One original artwork and three curated 3840x2400 photographs ship beside
// the theme-derived Field drawing, which remains the ultra-lean option.
// Source, author, licence and modifications are recorded in SOURCES.md.
//
// PERFORMANCE CONTRACT. This is still one background window inside the one
// punar-shell process: no wallpaper daemon, service, process, timer, network
// fetch, animation or polling loop. Qt decodes only WallpaperState.activeFile
// at the output's requested size.  The other choices cost installed bytes but
// no resident memory; selection changes are atomic FileView writes and inotify
// events. Reset runs one fixed-argv `rm -f`. A 16:10 RGBA texture costs about
// 1920x1080 or 35.2 MiB at 3840x2160, regardless of which raster is selected.
//
// The background never accepts input or focus.  A person selects it through
// the keyboard-first command center or the typed `wallpaper` IPC target.  The
// default, Stillpoint, uses generous negative space so application windows
// stay visually primary. Field follows Theme.wallpaper* and preserves
// D-015's original 1600x1000 geometry.

// `Bound` because the per-output delegate below reads the shared template and
// the sheet geometry from this file's root: it makes those captures explicit
// (and qmllint-clean) instead of relying on dynamic scope, and it is safe here
// because the delegate already declares `required property var modelData`.
pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Services"
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
        if (!WallpaperState.activeIsVector || root.template === "")
            return "";
        return root.template.split("__FIELD__").join(Theme.wallpaperField).split("__HAIRLINE__").join(Theme.wallpaperHairline).split("__EMPHASIS__").join(Theme.wallpaperEmphasis);
    }

    readonly property string photoSource: WallpaperState.activeIsVector || WallpaperState.activeFile === "" ? "" : "file://" + Quickshell.shellDir + "/Wallpaper/assets/" + WallpaperState.activeFile
    readonly property string activeSource: WallpaperState.activeIsVector ? root.svgSource : root.photoSource

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

            // A missing/corrupt image degrades to a deliberate theme field,
            // never black and never an error surface.
            color: Theme.wallpaperField

            // The fit scale of D-015 Sect III.03: the dial's diameter is always
            // 41.6% of the fitted height and its horizontal position always 72%
            // of the fitted width. The composition is a constant; only its
            // scale moves.
            readonly property real fitScale: (field.width <= 0 || field.height <= 0) ? 0 : Math.min(field.width / root.sheetWidth, field.height / root.sheetHeight)
            readonly property real coverScale: (field.width <= 0 || field.height <= 0) ? 0 : Math.max(field.width / root.sheetWidth, field.height / root.sheetHeight)

            Image {
                anchors.fill: parent

                // Field is rendered at its exact fitted 16:10 geometry.  The
                // photographs are already 16:10 and request only the output's
                // decoded size; PreserveAspectCrop handles non-16:10 screens.
                sourceSize: WallpaperState.activeIsVector ? Qt.size(Math.round(root.sheetWidth * field.fitScale), Math.round(root.sheetHeight * field.fitScale)) : Qt.size(Math.round(root.sheetWidth * field.coverScale), Math.round(root.sheetHeight * field.coverScale))
                fillMode: WallpaperState.activeIsVector ? Image.PreserveAspectFit : Image.PreserveAspectCrop

                // Asynchronous so the layer surface maps immediately in the
                // field colour; the drawing arrives a frame or two later on the
                // same colour, so there is no flash of anything else.
                asynchronous: true

                // Every output rasterizes a different size and a theme switch
                // replaces the source outright — a cache keyed on a 9 KB data
                // URI would only hold dead textures.
                cache: false

                source: root.activeSource
                visible: root.activeSource !== "" && field.width > 0 && field.height > 0
            }
        }
    }
}
