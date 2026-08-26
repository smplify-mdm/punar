pragma Singleton
// ThemeContrast — the theme legibility gate, in the shell.
//
// docs/design/theme-system.md §4 "Validation as a feature" is the binding
// specification; this file is its live-path implementation. Punar refuses to
// SELECT a theme it cannot prove is legible, because these surfaces exist to
// explain restrictions and "a theme that hides a denial is a safety problem,
// not a taste problem" (§4). The gate is therefore not a lint warning and not
// advice — Theme.applyTheme() will not write the pointer unless validate()
// passes.
//
// PURE. This file reads no file, holds no state, starts no timer, touches no
// daemon and knows nothing about Punar's surfaces: it is arithmetic over hex
// strings (§4.1 "no network, no fonts, no display, no daemon"). That is why it
// can also be re-implemented byte-for-byte on the punarctl side — see §4.5 and
// the note at the bottom of this file.
//
// ARITHMETIC (§4.1, WCAG 2.1, stated so it can be re-implemented):
//   c      = C / 255
//   c_lin  = c / 12.92                   if c <= 0.04045
//          = ((c + 0.055) / 1.055) ^ 2.4 otherwise
//   L      = 0.2126*R_lin + 0.7152*G_lin + 0.0722*B_lin
//   ratio  = (max(L1,L2) + 0.05) / (min(L1,L2) + 0.05)
// Comparison is at full double precision; REPORTING is to two decimals, and a
// pair computing 4.497 fails a 4.5 floor and prints "4.50" next to FAIL — the
// validator never lets rounding pass a pair (§4.1). roundedRatio() is the one
// place that rounds, and compare() is the one place that compares; they are
// deliberately not the same function.
//
// Hue/saturation are plain HSL over sRGB. Perceptual separation is CIE ΔE*76
// over CIELAB with a D65 white point (Xn,Yn,Zn = 0.95047, 1.0, 1.08883);
// chroma is C* = sqrt(a*² + b*²).
//
// VERIFIED against docs/design/theme-system.md §5.3 and §5.4: for all seven
// shipped themes this implementation reproduces the published minText,
// minNonText, status hues, max C* and min derived-ANSI figures exactly, and
// every shipped theme returns pass with zero failures.

import QtQuick

QtObject {
    id: root

    // ---- format (R2) ----

    // §3.2: hex only, uppercase, sRGB. No rgba(), no hsl(), no alpha, no
    // colour names, no references to other tokens.
    readonly property var hexRe: /^#[0-9A-F]{6}$/

    function isHex(value: var): bool {
        return typeof value === "string" && root.hexRe.test(value);
    }

    // [r, g, b] in 0..255, or null when `hex` is not a strict theme colour.
    function channels(hex: string): var {
        if (!root.isHex(hex))
            return null;
        return [parseInt(hex.substr(1, 2), 16), parseInt(hex.substr(3, 2), 16), parseInt(hex.substr(5, 2), 16)];
    }

    function toHex(r: int, g: int, b: int): string {
        function pair(v) {
            var c = Math.max(0, Math.min(255, Math.round(v)));
            return (c < 16 ? "0" : "") + c.toString(16).toUpperCase();
        }
        return "#" + pair(r) + pair(g) + pair(b);
    }

    // ---- WCAG relative luminance and contrast (§4.1) ----

    function linearize(channel8: real): real {
        var c = channel8 / 255.0;
        return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
    }

    function luminance(hex: string): real {
        var ch = root.channels(hex);
        if (ch === null)
            return -1;
        return 0.2126 * root.linearize(ch[0]) + 0.7152 * root.linearize(ch[1]) + 0.0722 * root.linearize(ch[2]);
    }

    // Full double precision. -1 when either input is not a valid colour, so a
    // malformed value can never silently read as "infinite contrast".
    function contrast(a: string, b: string): real {
        var la = root.luminance(a);
        var lb = root.luminance(b);
        if (la < 0 || lb < 0)
            return -1;
        var hi = Math.max(la, lb);
        var lo = Math.min(la, lb);
        return (hi + 0.05) / (lo + 0.05);
    }

    // The ONLY rounding in this file, and it is for display only (§4.1).
    function roundedRatio(ratio: real): real {
        return Math.round(ratio * 100) / 100;
    }

    // The ONLY comparison. A pair passes when its ROUNDED value still clears
    // the floor, so 4.497 fails 4.5 and prints as 4.50 (§4.1).
    function meetsFloor(ratio: real, floor: real): bool {
        return ratio >= 0 && root.roundedRatio(ratio) >= floor;
    }

    // ---- HSL over sRGB (R4) ----

    // Degrees, 0..360. -1 for an invalid colour.
    function hue(hex: string): real {
        var ch = root.channels(hex);
        if (ch === null)
            return -1;
        var r = ch[0] / 255, g = ch[1] / 255, b = ch[2] / 255;
        var mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
        if (d === 0)
            return 0;
        var h;
        if (mx === r)
            h = ((g - b) / d) % 6;
        else if (mx === g)
            h = (b - r) / d + 2;
        else
            h = (r - g) / d + 4;
        h = h * 60;
        return h < 0 ? h + 360 : h;
    }

    // 0..1. -1 for an invalid colour.
    function saturation(hex: string): real {
        var ch = root.channels(hex);
        if (ch === null)
            return -1;
        var r = ch[0] / 255, g = ch[1] / 255, b = ch[2] / 255;
        var mx = Math.max(r, g, b), mn = Math.min(r, g, b), d = mx - mn;
        if (d === 0)
            return 0;
        var l = (mx + mn) / 2;
        return l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn);
    }

    // ---- CIELAB / D65 (R5, R6, and the §7.1 terminal derivation) ----

    readonly property real whiteX: 0.95047
    readonly property real whiteY: 1.0
    readonly property real whiteZ: 1.08883

    // [L*, a*, b*], or null.
    function lab(hex: string): var {
        var ch = root.channels(hex);
        if (ch === null)
            return null;
        var r = root.linearize(ch[0]), g = root.linearize(ch[1]), b = root.linearize(ch[2]);
        var x = (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / root.whiteX;
        var y = (0.2126729 * r + 0.7151522 * g + 0.0721750 * b) / root.whiteY;
        var z = (0.0193339 * r + 0.1191920 * g + 0.9503041 * b) / root.whiteZ;
        function f(t) {
            return t > 216 / 24389 ? Math.cbrt(t) : (841 / 108) * t + 4 / 29;
        }
        var fx = f(x), fy = f(y), fz = f(z);
        return [116 * fy - 16, 500 * (fx - fy), 200 * (fy - fz)];
    }

    function deltaE76(a: string, b: string): real {
        var la = root.lab(a), lb = root.lab(b);
        if (la === null || lb === null)
            return -1;
        var dl = la[0] - lb[0], da = la[1] - lb[1], db = la[2] - lb[2];
        return Math.sqrt(dl * dl + da * da + db * db);
    }

    // C* = sqrt(a*² + b*²) — "near-monochrome by default" as a number (R6).
    function chroma(hex: string): real {
        var l = root.lab(hex);
        return l === null ? -1 : Math.sqrt(l[1] * l[1] + l[2] * l[2]);
    }

    // CIELAB -> sRGB hex, gamut-clamped per channel (§7.1 "gamut-clamped").
    function labToHex(lStar: real, aStar: real, bStar: real): string {
        var fy = (lStar + 16) / 116, fx = fy + aStar / 500, fz = fy - bStar / 200;
        function g(t) {
            var t3 = t * t * t;
            return t3 > 216 / 24389 ? t3 : (108 / 841) * (t - 4 / 29);
        }
        var x = g(fx) * root.whiteX, y = g(fy) * root.whiteY, z = g(fz) * root.whiteZ;
        var r = 3.2404542 * x - 1.5371385 * y - 0.4985314 * z;
        var gr = -0.9692660 * x + 1.8760108 * y + 0.0415560 * z;
        var b = 0.0556434 * x - 0.2040259 * y + 1.0572252 * z;
        function encode(c) {
            var v = Math.max(0, Math.min(1, c));
            v = v <= 0.0031308 ? 12.92 * v : 1.055 * Math.pow(v, 1 / 2.4) - 0.055;
            return v * 255;
        }
        return root.toHex(encode(r), encode(gr), encode(b));
    }

    function lchToHex(lStar: real, cStar: real, hueDeg: real): string {
        var rad = hueDeg * Math.PI / 180;
        return root.labToHex(lStar, cStar * Math.cos(rad), cStar * Math.sin(rad));
    }

    // Linear interpolation in sRGB (the §7.1 bright-slot recipe and the §7.3
    // panel wallpaper hairline both say mix_sRGB, not mix in a linear space).
    function mix(a: string, b: string, t: real): string {
        var ca = root.channels(a), cb = root.channels(b);
        if (ca === null || cb === null)
            return a;
        return root.toHex(ca[0] + (cb[0] - ca[0]) * t, ca[1] + (cb[1] - ca[1]) * t, ca[2] + (cb[2] - ca[2]) * t);
    }

    // ---- the derived terminal palette (§7.1), needed by R8 ----

    // Slot 0 (black) is bound to panel.edge — the structural/dim slot by
    // terminal convention, and the one slot R8 exempts. Slots 4/5/6 are hue
    // rotations at fixed chroma around the theme's own secondary ink, which is
    // how the scheme stays near-monochrome with a single accent in EVERY theme
    // rather than only in the one that was hand-tuned.
    function ansiSlots(panelBlock: var): var {
        if (!panelBlock || !panelBlock.status)
            return null;
        var fg = panelBlock.fg;
        var inkLab = root.lab(panelBlock.ink2);
        if (inkLab === null)
            return null;
        var l2 = inkLab[0];
        var slots = [panelBlock.edge, panelBlock.status.bad, panelBlock.status.ok, panelBlock.status.warn, root.lchToHex(l2, 18, 271), root.lchToHex(l2, 18, 302), root.lchToHex(l2, 18, 214), fg];
        for (var i = 1; i <= 6; i++)
            slots[i + 8] = root.mix(slots[i], fg, 0.28);
        slots[8] = panelBlock.ink3;
        slots[15] = "#FFFFFF";
        return slots;
    }

    // ---- the measured pairs (§4.2) ----

    // Twenty-four per theme. The list is part of the contract: a first-party
    // surface that introduces a new text-on-fill combination must add its pair
    // here in the same change (§4.2). CI item §4.7.4 asserts this length is 24.
    function measuredPairs(palette: var): var {
        var p = palette.paper, n = palette.panel;
        return [
            // 1-2 · the ink is the system's anchor mark. AAA, deliberately above AA.
            {
                "name": "paper · ink on surface",
                "fg": p.ink,
                "bg": p.surface,
                "floor": 7.0,
                "kind": "text"
            }, {
                "name": "paper · ink on raise2",
                "fg": p.ink,
                "bg": p.raise2,
                "floor": 7.0,
                "kind": "text"
            },
            // 3-4 · body prose, 16px regular — WCAG 2.1 AA normal text.
            {
                "name": "paper · ink2 on surface",
                "fg": p.ink2,
                "bg": p.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · ink2 on muted",
                "fg": p.ink2,
                "bg": p.muted,
                "floor": 4.5,
                "kind": "text"
            },
            // 5-7 · tracked mono labels and meta rows. Punar claims NO large-text
            // exemption for them (§4.3): tracking raises letter separation, not
            // luminance contrast, and WCAG grants no credit for it. Pair 7 is in
            // practice the tightest in the whole system.
            {
                "name": "paper · ink3 on surface",
                "fg": p.ink3,
                "bg": p.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · ink3 on muted",
                "fg": p.ink3,
                "bg": p.muted,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · ink3 on raise2",
                "fg": p.ink3,
                "bg": p.raise2,
                "floor": 4.5,
                "kind": "text"
            },
            // 8-13 · status words are text, and the approval card puts them on a
            // raised fill.
            {
                "name": "paper · status.ok on surface",
                "fg": p.status.ok,
                "bg": p.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · status.ok on raise2",
                "fg": p.status.ok,
                "bg": p.raise2,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · status.warn on surface",
                "fg": p.status.warn,
                "bg": p.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · status.warn on raise2",
                "fg": p.status.warn,
                "bg": p.raise2,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · status.bad on surface",
                "fg": p.status.bad,
                "bg": p.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "paper · status.bad on raise2",
                "fg": p.status.bad,
                "bg": p.raise2,
                "floor": 4.5,
                "kind": "text"
            },
            // 14 · the one filled affirmative button. Both halves are DERIVED
            // (§2): action.bg = status.ok, action.fg = surface.
            {
                "name": "paper · action fg on action bg",
                "fg": p.surface,
                "bg": p.status.ok,
                "floor": 4.5,
                "kind": "text"
            },
            // 15-16 · WCAG 2.1 §1.4.11 non-text contrast. An input boundary is a
            // UI component boundary, and keyboard operability is spec §12.
            {
                "name": "paper · inputBorder on surface",
                "fg": p.inputBorder,
                "bg": p.surface,
                "floor": 3.0,
                "kind": "nontext"
            }, {
                "name": "paper · focus ring on surface",
                "fg": p.ink,
                "bg": p.surface,
                "floor": 3.0,
                "kind": "nontext"
            },
            // 17-24 · the panel side. There is no text-on-raised-panel pair in
            // the system, because the panel block has no muted/raise2: on panel
            // surfaces elevation is stated with an edge, not a fill (§2).
            {
                "name": "panel · fg on surface",
                "fg": n.fg,
                "bg": n.surface,
                "floor": 7.0,
                "kind": "text"
            }, {
                "name": "panel · ink2 on surface",
                "fg": n.ink2,
                "bg": n.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "panel · ink3 on surface",
                "fg": n.ink3,
                "bg": n.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "panel · status.ok on surface",
                "fg": n.status.ok,
                "bg": n.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "panel · status.warn on surface",
                "fg": n.status.warn,
                "bg": n.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "panel · status.bad on surface",
                "fg": n.status.bad,
                "bg": n.surface,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "panel · action fg on action bg",
                "fg": n.surface,
                "bg": n.status.ok,
                "floor": 4.5,
                "kind": "text"
            }, {
                "name": "panel · focus ring on surface",
                "fg": n.fg,
                "bg": n.surface,
                "floor": 3.0,
                "kind": "nontext"
            }
        ];
    }

    // ---- the theme contract shape (R1) ----

    readonly property var rootKeys: ["$schema", "kind", "meta", "color"]
    readonly property var metaRequired: ["id", "name", "intent", "defaultMood"]
    readonly property var metaOptional: ["author", "version", "grammar"]
    readonly property var paperKeys: ["surface", "ink", "ink2", "ink3", "muted", "raise2", "border", "inputBorder", "status"]
    readonly property var panelKeys: ["surface", "fg", "ink2", "ink3", "edge", "status"]
    readonly property var statusKeys: ["ok", "warn", "bad"]
    readonly property var moods: ["paper", "panel"]
    readonly property var idRe: /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/

    // R4 hue windows. A theme may pick any green; it may not make "allow" blue.
    readonly property real okHueLow: 70
    readonly property real okHueHigh: 170
    readonly property real warnHueLow: 20
    readonly property real warnHueHigh: 70
    readonly property real badHueLow: 330
    readonly property real badHueHigh: 20
    readonly property real minStatusSaturation: 0.25
    readonly property real minStatusSeparation: 25   // ΔE*76, status ↔ status
    readonly property real minStatusInkSeparation: 20 // ΔE*76, status ↔ ink3
    readonly property real maxNeutralChroma: 14
    readonly property real minHairlineContrast: 1.15
    readonly property real minAnsiContrast: 4.5

    function fail(rule: string, detail: string, measured: var, floor: var): var {
        return {
            "rule": rule,
            "detail": detail,
            "measured": measured,
            "floor": floor
        };
    }

    // ---- R1: shape ----
    //
    // Unknown keys are REFUSED, not ignored, because silently dropping a key
    // teaches theme authors that the contract is negotiable (§2). A theme that
    // tries to set font, shape, motion, terminal or semantics is refused
    // naming the key.
    function checkShape(doc: var, failures: var): bool {
        if (doc === null || doc === undefined || typeof doc !== "object")
            return false;
        var k;
        for (k in doc)
            if (root.rootKeys.indexOf(k) === -1)
                failures.push(root.fail("R1", "unknown top-level key \"" + k + "\" — a theme is nineteen colours and four strings", null, null));
        if (doc.kind !== "PunarTheme")
            failures.push(root.fail("R1", "kind must be \"PunarTheme\"", null, null));

        var meta = doc.meta;
        if (!meta || typeof meta !== "object") {
            failures.push(root.fail("R1", "missing meta block", null, null));
            return false;
        }
        for (k in meta)
            if (root.metaRequired.indexOf(k) === -1 && root.metaOptional.indexOf(k) === -1)
                failures.push(root.fail("R1", "unknown meta key \"" + k + "\"", null, null));
        for (var i = 0; i < root.metaRequired.length; i++)
            if (typeof meta[root.metaRequired[i]] !== "string" || meta[root.metaRequired[i]] === "")
                failures.push(root.fail("R1", "missing meta." + root.metaRequired[i], null, null));
        if (typeof meta.id === "string" && (!root.idRe.test(meta.id) || meta.id.length > 24))
            failures.push(root.fail("R1", "meta.id \"" + meta.id + "\" is not a lowercase slug of 24 chars or fewer", null, null));
        if (typeof meta.name === "string" && meta.name.length > 24)
            failures.push(root.fail("R1", "meta.name is longer than 24 characters", null, null));
        // "a theme that cannot say what it is for does not belong in the set".
        if (typeof meta.intent === "string" && meta.intent.length > 96)
            failures.push(root.fail("R1", "meta.intent is longer than 96 characters", null, null));
        if (typeof meta.defaultMood === "string" && root.moods.indexOf(meta.defaultMood) === -1)
            failures.push(root.fail("R1", "meta.defaultMood must be \"paper\" or \"panel\"", null, null));

        var color = doc.color;
        if (!color || typeof color !== "object" || !color.paper || !color.panel) {
            failures.push(root.fail("R1", "missing color.paper and/or color.panel — no inheritance, no cascade, no partial themes", null, null));
            return false;
        }
        for (k in color)
            if (k !== "paper" && k !== "panel")
                failures.push(root.fail("R1", "unknown color block \"" + k + "\"", null, null));
        var ok = true;
        ok = root.checkBlock("paper", color.paper, root.paperKeys, failures) && ok;
        ok = root.checkBlock("panel", color.panel, root.panelKeys, failures) && ok;
        return ok;
    }

    function checkBlock(name: string, block: var, keys: var, failures: var): bool {
        var ok = true, k, i;
        for (k in block)
            if (keys.indexOf(k) === -1) {
                failures.push(root.fail("R1", "unknown key color." + name + "." + k, null, null));
                ok = false;
            }
        for (i = 0; i < keys.length; i++) {
            var key = keys[i];
            if (key === "status")
                continue;
            if (block[key] === undefined || block[key] === null) {
                failures.push(root.fail("R1", "missing color." + name + "." + key, null, null));
                ok = false;
            } else if (!root.isHex(block[key])) {
                // R2 format: uppercase #RRGGBB only.
                failures.push(root.fail("R2", "color." + name + "." + key + " = " + block[key] + " is not #RRGGBB uppercase sRGB", null, null));
                ok = false;
            }
        }
        var status = block.status;
        if (!status || typeof status !== "object") {
            failures.push(root.fail("R1", "missing color." + name + ".status", null, null));
            return false;
        }
        for (k in status)
            if (root.statusKeys.indexOf(k) === -1) {
                failures.push(root.fail("R1", "unknown key color." + name + ".status." + k + " — a theme picks WHICH green, never what green says", null, null));
                ok = false;
            }
        for (i = 0; i < root.statusKeys.length; i++) {
            var sk = root.statusKeys[i];
            if (status[sk] === undefined || status[sk] === null) {
                failures.push(root.fail("R1", "missing color." + name + ".status." + sk, null, null));
                ok = false;
            } else if (!root.isHex(status[sk])) {
                failures.push(root.fail("R2", "color." + name + ".status." + sk + " = " + status[sk] + " is not #RRGGBB uppercase sRGB", null, null));
                ok = false;
            }
        }
        return ok;
    }

    function inWindow(h: real, low: real, high: real): bool {
        // A window that wraps 360 (bad: [330,360) ∪ [0,20)) is expressed as
        // low > high.
        return low <= high ? (h >= low && h < high) : (h >= low || h < high);
    }

    // ---- R1-R9, the whole gate (§4.2, §4.5 "punarctl theme validate") ----
    //
    // Returns {pass, failures[], pairs[], minText, minNonText, maxChroma,
    // minStatusDeltaE, minStatusInkDeltaE, minAnsi, pairCount}. `pairs` is the
    // full §5.4-shaped table so a surface can print measured-vs-floor rows
    // without recomputing anything.
    function validate(doc: var, installedGrammarMajor: int): var {
        var failures = [];
        var result = {
            "pass": false,
            "failures": failures,
            "pairs": [],
            "pairCount": 0,
            "minText": -1,
            "minNonText": -1,
            "maxChroma": -1,
            "minStatusDeltaE": -1,
            "minStatusInkDeltaE": -1,
            "minAnsi": -1
        };
        if (!root.checkShape(doc, failures))
            return result;

        var palette = doc.color;
        var blocks = [["paper", palette.paper], ["panel", palette.panel]];
        var i, j, b, blockName, block;

        // R3 · the twenty-four measured pairs.
        var pairs = root.measuredPairs(palette);
        var minText = Infinity, minNonText = Infinity;
        for (i = 0; i < pairs.length; i++) {
            var pair = pairs[i];
            var ratio = root.contrast(pair.fg, pair.bg);
            pair.measured = root.roundedRatio(ratio);
            pair.pass = root.meetsFloor(ratio, pair.floor);
            if (!pair.pass)
                failures.push(root.fail("R3", pair.name, pair.measured, pair.floor));
            if (pair.kind === "text")
                minText = Math.min(minText, ratio);
            else
                minNonText = Math.min(minNonText, ratio);
        }
        result.pairs = pairs;
        result.pairCount = pairs.length;
        result.minText = root.roundedRatio(minText);
        result.minNonText = root.roundedRatio(minNonText);

        // R4 · status hue windows and saturation floor, on BOTH blocks. This is
        // the semantic promise made checkable: green = allow, amber =
        // approval_required, red = deny, learned once and never lying.
        var windows = {
            "ok": [root.okHueLow, root.okHueHigh],
            "warn": [root.warnHueLow, root.warnHueHigh],
            "bad": [root.badHueLow, root.badHueHigh]
        };
        for (b = 0; b < blocks.length; b++) {
            blockName = blocks[b][0];
            block = blocks[b][1];
            for (j = 0; j < root.statusKeys.length; j++) {
                var role = root.statusKeys[j];
                var hex = block.status[role];
                var h = root.hue(hex);
                var w = windows[role];
                if (!root.inWindow(h, w[0], w[1]))
                    failures.push(root.fail("R4", blockName + " · status." + role + " hue " + Math.round(h) + "° outside " + w[0] + "°-" + w[1] + "°", Math.round(h), null));
                var s = root.saturation(hex);
                if (s < root.minStatusSaturation)
                    failures.push(root.fail("R4", blockName + " · status." + role + " saturation " + Math.round(s * 100) + "% — a greyed status stops reading as a decision", Math.round(s * 100), 25));
            }
        }

        // R5 · perceptual separation. Three statuses must be told apart at a
        // glance, and a status word must not read as a label.
        var minStatusDe = Infinity, minStatusInkDe = Infinity;
        var combos = [["ok", "warn"], ["ok", "bad"], ["warn", "bad"]];
        for (b = 0; b < blocks.length; b++) {
            blockName = blocks[b][0];
            block = blocks[b][1];
            for (j = 0; j < combos.length; j++) {
                var de = root.deltaE76(block.status[combos[j][0]], block.status[combos[j][1]]);
                minStatusDe = Math.min(minStatusDe, de);
                if (de < root.minStatusSeparation)
                    failures.push(root.fail("R5", blockName + " · status." + combos[j][0] + " vs status." + combos[j][1] + " ΔE*76 " + de.toFixed(1), Number(de.toFixed(1)), root.minStatusSeparation));
            }
            for (j = 0; j < root.statusKeys.length; j++) {
                var din = root.deltaE76(block.status[root.statusKeys[j]], block.ink3);
                minStatusInkDe = Math.min(minStatusInkDe, din);
                if (din < root.minStatusInkSeparation)
                    failures.push(root.fail("R5", blockName + " · status." + root.statusKeys[j] + " vs ink3 ΔE*76 " + din.toFixed(1), Number(din.toFixed(1)), root.minStatusInkSeparation));
            }
        }
        result.minStatusDeltaE = Number(minStatusDe.toFixed(1));
        result.minStatusInkDeltaE = Number(minStatusInkDe.toFixed(1));

        // R6 · neutral chroma cap. "Near-monochrome by default" as a number:
        // warm paper fits, a lilac "surface" does not.
        var maxC = 0;
        for (b = 0; b < blocks.length; b++) {
            blockName = blocks[b][0];
            block = blocks[b][1];
            for (var key in block) {
                if (key === "status")
                    continue;
                var c = root.chroma(block[key]);
                maxC = Math.max(maxC, c);
                if (c > root.maxNeutralChroma)
                    failures.push(root.fail("R6", blockName + " · " + key + " C* " + c.toFixed(1), Number(c.toFixed(1)), root.maxNeutralChroma));
            }
        }
        result.maxChroma = Number(maxC.toFixed(1));

        // R7 · elevation order. Raises must stack in the right direction,
        // hairlines must be visible, and the wallpaper marks (derived from
        // muted/raise2, §7.3) must stay strictly quieter than a window border —
        // the rule Plate D-015 Sect II states, here enforced.
        var p = palette.paper;
        var cMuted = root.contrast(p.muted, p.surface);
        var cRaise = root.contrast(p.raise2, p.surface);
        var cBorder = root.contrast(p.border, p.surface);
        if (cRaise < cMuted)
            failures.push(root.fail("R7", "paper · raise2 (" + cRaise.toFixed(3) + ") is quieter than muted (" + cMuted.toFixed(3) + ")", null, null));
        if (cBorder <= cRaise || cBorder <= cMuted)
            failures.push(root.fail("R7", "paper · border " + cBorder.toFixed(3) + " must strictly exceed both raises — a wallpaper mark may never out-rank a window border", null, null));
        if (cBorder < root.minHairlineContrast)
            failures.push(root.fail("R7", "paper · border on surface " + cBorder.toFixed(3), Number(cBorder.toFixed(3)), root.minHairlineContrast));
        var cEdge = root.contrast(palette.panel.edge, palette.panel.surface);
        if (cEdge < root.minHairlineContrast)
            failures.push(root.fail("R7", "panel · edge on surface " + cEdge.toFixed(3), Number(cEdge.toFixed(3)), root.minHairlineContrast));

        // R8 · derived terminal legibility. Slot 0 (black = panel.edge) is
        // exempt: it is the structural/dim slot by terminal convention, which
        // is exactly why it is bound to the edge token.
        var slots = root.ansiSlots(palette.panel);
        var minAnsi = Infinity;
        if (slots !== null) {
            for (i = 1; i <= 15; i++) {
                var ar = root.contrast(slots[i], palette.panel.surface);
                minAnsi = Math.min(minAnsi, ar);
                if (!root.meetsFloor(ar, root.minAnsiContrast))
                    failures.push(root.fail("R8", "derived ANSI slot " + i + " (" + slots[i] + ") on panel.surface", root.roundedRatio(ar), root.minAnsiContrast));
            }
            result.minAnsi = root.roundedRatio(minAnsi);
        }

        // R9 · grammar compatibility. Renaming or removing a token is a MAJOR
        // bump and refuses themes from the previous MAJOR — no silent breakage.
        var grammar = doc.meta.grammar;
        if (typeof grammar === "string" && grammar !== "") {
            var major = parseInt(grammar.split(".")[0], 10);
            if (isNaN(major) || major !== installedGrammarMajor)
                failures.push(root.fail("R9", "meta.grammar " + grammar + " is not compatible with the installed grammar major " + installedGrammarMajor, null, null));
        }

        result.pass = failures.length === 0;
        return result;
    }

    // ---- the refusal, in the spec §73 voice (§4.6) ----
    //
    // Names the failing pair, gives measured and required numbers in the same
    // units as the input, cites the rule's home, and — because this is a
    // personal device — says explicitly that the floor is not an
    // organisation's doing. Design language §8: authority always has a named
    // source, and here the source is the OS itself.
    function refusalRows(result: var): var {
        var rows = [];
        for (var i = 0; i < result.failures.length; i++) {
            var f = result.failures[i];
            rows.push({
                "rule": f.rule,
                "detail": f.detail,
                "measured": f.measured === null ? "—" : root.roundedRatio(f.measured).toFixed(2),
                "floor": f.floor === null ? "—" : Number(f.floor).toFixed(2)
            });
        }
        return rows;
    }

    readonly property string refusalPolicyLine: "Policy: theme contract — docs/design/theme-system.md §4 (not an organization policy; this floor applies on every Punar device)."

    // ---- NOTE FOR THE punarctl SIDE (crates/punarctl, NOT edited here) ----
    //
    // theme-system.md §4.5 puts the same gate behind `punarctl theme validate`
    // and in the write path of `punarctl theme set`. A Rust re-implementation
    // needs exactly what is above and nothing else:
    //
    //   1. the §4.1 arithmetic at f64 precision, rounding ONLY for display, and
    //      comparing the ROUNDED value against the floor (so 4.497 fails 4.5);
    //   2. the 24-pair table of measuredPairs() in the same order, so
    //      `theme show` prints the same rows as the picker;
    //   3. R1-R9 with the constants published as properties above
    //      (25% saturation, ΔE 25 / 20, C* 14, 1.15 hairline, 4.5 ANSI);
    //   4. the §7.1 ANSI derivation, because R8 measures DERIVED values —
    //      lchToHex() and mix() must match, or R8 will disagree across the two
    //      implementations for the blue/magenta/cyan slots;
    //   5. exit code 6 for a refusal, which is deliberately NOT 3: a refusal is
    //      not an authorization decision and must not be read as one by a
    //      script;
    //   6. on `theme set`, write the §3.3 pointer with a fresh `validated`
    //      receipt (at / grammar / digest / minText / minNonText) — the shell
    //      trusts that receipt on passive load rather than re-running the
    //      arithmetic every startup (§6.3), and re-runs the full gate itself
    //      only when it is asked to SELECT a theme.
    //
    // CI item §4.7.3 is the contract between the two: `punarctl theme validate`
    // must reproduce the §5.3 table to two decimals. This implementation does;
    // it was checked against all seven shipped themes.
}
