pragma Singleton
// Theme — the single owner of every design value in punar-shell.
//
// Loads shell/theme/punar-tokens.json at runtime and exposes typed
// properties. Per docs/design/DESIGN_LANGUAGE.md §8 non-negotiable 1,
// UI code consumes tokens — no color may be hardcoded outside this file.
// The literal values below are *fallbacks only*, mirroring
// punar-tokens.json 0.1.0, used if neither token file can be read.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    // Installed location (punar-desktop image; see README for install layout),
    // with a dev fallback relative to the shell dir (repo layout:
    // shell/punar-shell/ next to shell/theme/).
    readonly property string installedPath: "/usr/share/punar/theme/punar-tokens.json"
    readonly property string devPath: Quickshell.shellDir + "/../theme/punar-tokens.json"

    property var tokens: ({})

    FileView {
        id: tokenFile
        path: root.installedPath
        // Block until read so the first frame is already tokened (no unstyled flash).
        blockLoading: true
        onLoaded: {
            try {
                root.tokens = JSON.parse(tokenFile.text());
            } catch (e) {
                console.warn("punar-shell: failed to parse tokens at", tokenFile.path, e);
            }
        }
        onLoadFailed: {
            if (tokenFile.path === root.installedPath) {
                console.warn("punar-shell: tokens not installed, falling back to dev path");
                tokenFile.path = root.devPath;
            } else {
                console.warn("punar-shell: no token file found; using built-in fallbacks");
            }
        }
    }

    // Walk `tokens` by key path; fall back if absent. Accessing root.tokens
    // here keeps every derived property reactive to a token reload.
    function tok(path: list<string>, fallback: var): var {
        var node = root.tokens;
        for (var i = 0; i < path.length; i++) {
            if (node === null || node === undefined || typeof node !== "object")
                return fallback;
            node = node[path[i]];
        }
        return (node === undefined || node === null) ? fallback : node;
    }

    // ---- color · paper surface (DESIGN_LANGUAGE.md §2) ----
    readonly property color paperSurface: tok(["color", "paper", "surface"], "#FAF9F6")
    readonly property color ink: tok(["color", "paper", "ink"], "#000000")
    readonly property color ink2: tok(["color", "paper", "ink2"], "#333333")
    readonly property color ink3: tok(["color", "paper", "ink3"], "#666666")
    readonly property color muted: tok(["color", "paper", "muted"], "#F4F2EC")
    readonly property color raise2: tok(["color", "paper", "raise2"], "#EDEAE2")
    readonly property color border: tok(["color", "paper", "border"], "#E6E4DE")
    readonly property color inputBorder: tok(["color", "paper", "inputBorder"], "#8C8880")

    // ---- color · panel surface ----
    readonly property color panelSurface: tok(["color", "panel", "surface"], "#08090A")
    readonly property color panelFg: tok(["color", "panel", "fg"], "#F2F3F5")
    readonly property color panelInk2: tok(["color", "panel", "ink2"], "#A8ADB6")
    readonly property color panelInk3: tok(["color", "panel", "ink3"], "#7B8290")
    readonly property color panelEdge: tok(["color", "panel", "edge"], "#26282E")

    // ---- color · status (the only "real" colors; §2 status table) ----
    readonly property color statusOk: tok(["color", "paper", "status", "ok"], "#2E6B21")
    readonly property color statusWarn: tok(["color", "paper", "status", "warn"], "#8A5A00")
    readonly property color statusBad: tok(["color", "paper", "status", "bad"], "#A31F2C")
    readonly property color panelStatusOk: tok(["color", "panel", "status", "ok"], "#A3E047")
    readonly property color panelStatusWarn: tok(["color", "panel", "status", "warn"], "#F2BE85")
    readonly property color panelStatusBad: tok(["color", "panel", "status", "bad"], "#FF7A7A")

    // ---- color · action (DESIGN_LANGUAGE.md §2 "Action color") ----
    readonly property color actionBg: tok(["color", "action", "paper", "bg"], "#2E6B21")
    readonly property color actionFg: tok(["color", "action", "paper", "fg"], "#FAF9F6")
    readonly property color destructive: tok(["color", "action", "destructive", "paper"], "#A31F2C")

    // Warm ink wash for overlay scrims: the shadow-family warm ink base
    // (rgb(28 24 16), the base of the shadow tokens) at 22% — matches
    // .scrim in docs/design/mockups/command-approval.html ("the scrim is
    // the warm ink wash at 22%, never a blur-only dim").
    readonly property color inkWash: Qt.rgba(28 / 255, 24 / 255, 16 / 255, 0.22)

    // ---- typography (DESIGN_LANGUAGE.md §1) ----
    readonly property string fontSans: tok(["font", "sans", "family"], "Instrument Sans")
    readonly property string fontMono: tok(["font", "mono", "family"], "Geist Mono")
    readonly property real trackingLabelEm: tok(["font", "trackingLabelEm"], 0.12)
    readonly property int labelSize: tok(["font", "labelSizePx"], 12)
    readonly property int metaSize: tok(["font", "metaSizePx"], 10)

    // letterSpacing in QML is px; the design tracks in em. Always pass the
    // em value from the mockup/type-role table explicitly.
    function tracking(sizePx: real, em: real): real {
        return sizePx * em;
    }

    // ---- shape (DESIGN_LANGUAGE.md §3) ----
    readonly property int radius: tok(["shape", "radiusPx"], 10)
    readonly property int radiusTag: tok(["shape", "radiusTagPx"], 6)
    readonly property int hairline: tok(["shape", "hairlinePx"], 1)

    // ---- motion (DESIGN_LANGUAGE.md §4 — fluid, not decorative) ----
    readonly property int durMicro: tok(["motion", "durationMs", "micro"], 150)
    readonly property int durStandard: tok(["motion", "durationMs", "standard"], 300)
    readonly property int durSpatial: tok(["motion", "durationMs", "spatial"], 450)

    // cubic-bezier(0.2, 0, 0, 1) from tokens, in Easing.BezierSpline form
    // (control points + the terminal 1,1 pair).
    readonly property var easingCurve: {
        var e = tok(["motion", "ease"], [0.2, 0, 0, 1]);
        return [e[0], e[1], e[2], e[3], 1, 1];
    }
}
