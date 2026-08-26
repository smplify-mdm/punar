pragma Singleton
// Theme — the single owner of every design value in punar-shell.
//
// Loads shell/theme/punar-tokens.json (the GRAMMAR file) plus, since the theme
// system landed, an active-theme POINTER and a PALETTE document, and exposes
// typed properties. Per docs/design/DESIGN_LANGUAGE.md §9 non-negotiable 1,
// UI code consumes tokens — no color may be hardcoded outside this file.
// The literal values below are *fallbacks only*, mirroring
// punar-tokens.json 0.1.0, used if neither token file can be read.
//
// ---------------------------------------------------------------------------
// THE THEME SYSTEM (docs/design/theme-system.md — binding on adoption)
// ---------------------------------------------------------------------------
//
// "A theme may change what Punar is made of. It may never change what Punar
// means." A theme is a TOKEN SET: nineteen colours, a name, an intent line and
// a default mood (§2). It cannot carry a font, a radius, a duration, a stroke
// semantic, or an opinion about what a colour MEANS. Everything else on the
// machine — ANSI slots, window borders, wallpaper marks, the action colours —
// is DERIVED, never authored (§7).
//
// Three files, three FileViews, all inotify-driven, zero polling (§6.3):
//
//   punar-tokens.json          grammar + built-in fallback palette
//   <pointer>                  which theme is active, and at which mood
//   <themes>/<id>.theme.json   the nineteen colours
//
// A system with no themes/ directory behaves EXACTLY as the shipped image did
// before this file changed: the grammar file's `color` block is the fallback
// palette, and its absence is not a failure mode (§3.1).
//
// SWITCHING WITHOUT RESTART (§6.3): every consumer already binds through
// Theme.*, and tok() reads root.effectivePalette, so a pointer change repaints
// every open surface — bar, command center, approval overlay, AI panel,
// notifications, wallpaper — with no restart, no relaunch and no
// re-instantiation of any surface. The swap is INSTANT and there is no
// crossfade: motion in Punar explains a change in system state (design
// language §4), and a theme change is the observer changing their mind.
//
// SELECTION IS GATED (§4). applyTheme() runs the full R1-R9 validator in
// ThemeContrast before it writes the pointer, and refuses in the §73 voice if
// the theme cannot be proven legible. Passive load does the cheap half (R1
// shape + R2 format) only, because §6.3 keeps the shell dumb: the receipt in
// the pointer is the record of the gate that already passed.
//
// NOT IMPLEMENTED HERE, DELIBERATELY (spec §1.22 — no control that does
// nothing):
//   - Org pinning (§8). It needs an `appearance` block in
//     schemas/desired-state/desired-state.json, which does not model one yet
//     (§0 claim 08 is dashed). No pin is read, so no pin is ever shown, and no
//     surface hints that one could exist — design language §8: on a personal
//     device the calm state is the default state.
//   - mood "auto" (§6.3). Reserved in the pointer schema, needs a clock source
//     that costs no idle CPU, and is unbuilt. A pointer that says "auto" here
//     falls through to the theme's own defaultMood.
//   - The SHA-256 digest half of the §3.3 `validated` receipt. QML offers only
//     Qt.md5; a pointer written by this file therefore carries at / grammar /
//     minText / minNonText and NO digest. `punarctl theme set` is the writer
//     that can complete the receipt.

import QtQuick
import Qt.labs.folderlistmodel
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    // Installed location (punar-desktop image; see README for install layout),
    // with a dev fallback relative to the shell dir (repo layout:
    // shell/punar-shell/ next to shell/theme/).
    readonly property string installedPath: "/usr/share/punar/theme/punar-tokens.json"
    readonly property string devPath: Quickshell.shellDir + "/../theme/punar-tokens.json"

    readonly property string installedThemeDir: "/usr/share/punar/theme/themes"
    readonly property string devThemeDir: Quickshell.shellDir + "/../theme/themes"
    readonly property string siteThemeDir: "/etc/punar/themes"

    readonly property string homeDir: {
        var h = Quickshell.env("HOME");
        return h ? h : "";
    }
    readonly property string userThemeDir: root.homeDir === "" ? "" : root.homeDir + "/.config/punar/themes"

    // §3.4 resolution order for the POINTER: the user's own file first, then
    // the system pointer, then the shipped one. (Rank 1, the org pin, is not
    // implemented — see the header.)
    readonly property string userPointerPath: root.homeDir === "" ? "" : root.homeDir + "/.config/punar/theme.json"
    readonly property var systemPointerCandidates: ["/etc/punar/theme.json", root.installedThemeDir + "/default.json", root.devThemeDir + "/default.json"]

    property var tokens: ({})

    // ---- pointer state ----

    property var userPointer: null
    property var systemPointer: null

    readonly property var pointer: root.userPointer !== null ? root.userPointer : root.systemPointer

    // §3.4 rank 5: with no pointer anywhere, "paper" — which is also the
    // grammar file's own colour block, so the fallback and the default can
    // never disagree (§4.7 CI item 3).
    readonly property string activeId: {
        var p = root.pointer;
        if (p !== null && typeof p.active === "string" && p.active !== "")
            return p.active;
        return "paper";
    }

    readonly property string requestedMood: {
        var p = root.pointer;
        if (p !== null && typeof p.mood === "string" && p.mood !== "")
            return p.mood;
        return "default";
    }

    // Where the active pointer came from, for `theme status` and for the
    // picker's footer. Never an org policy id: no pin is read (see header).
    readonly property string activeSource: root.userPointer !== null ? "user preference" : (root.systemPointer !== null ? "system pointer" : "built-in fallback")

    // ---- palette state ----

    // The document for activeId, once its shape (R1) and format (R2) check
    // out. Null means "no theme document resolved" — tok() then falls through
    // to the grammar file's colour block, which is the paper palette.
    property var palette: null

    // §6.4 live preview: moving the highlight in the picker sets an in-memory
    // override and repaints the session immediately. It WRITES NOTHING. `esc`
    // clears it and the previous look returns; Enter runs applyTheme(), and the
    // resulting pointer change makes the preview permanent through the ordinary
    // FileView path. Preview is free; commitment goes through the gate.
    property var previewPalette: null
    property string previewMood: ""

    readonly property var effectivePalette: root.previewPalette !== null ? root.previewPalette : root.palette

    readonly property var paletteColor: {
        var p = root.effectivePalette;
        return (p !== null && p !== undefined && p.color) ? p.color : null;
    }

    readonly property string activeName: {
        var p = root.effectivePalette;
        return (p !== null && p !== undefined && p.meta && p.meta.name) ? p.meta.name : "Field Paper";
    }

    readonly property string activeIntent: {
        var p = root.effectivePalette;
        return (p !== null && p !== undefined && p.meta && p.meta.intent) ? p.meta.intent : "The reference palette: warm paper, black ink, panel terminal.";
    }

    // §2.1 — mood is the second axis and it is orthogonal to palette. It
    // decides which block the SHELL surfaces render on. It never touches the
    // terminal, code editors, plates or OSD overlays: those are ALWAYS panel
    // (design language §6), which is why every theme must define both blocks.
    readonly property string mood: {
        if (root.previewMood === "paper" || root.previewMood === "panel")
            return root.previewMood;
        var m = root.requestedMood;
        if (m === "paper" || m === "panel")
            return m;
        var p = root.effectivePalette;
        if (p !== null && p !== undefined && p.meta && (p.meta.defaultMood === "paper" || p.meta.defaultMood === "panel"))
            return p.meta.defaultMood;
        return "paper";
    }

    readonly property bool moodPanel: root.mood === "panel"

    // ---- file loading (three FileViews, inotify only — spec §6.3) ----

    FileView {
        id: tokenFile
        path: root.installedPath
        // Block until read so the first frame is already tokened (no unstyled flash).
        blockLoading: true
        watchChanges: true
        onFileChanged: tokenFile.reload()
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

    // The user pointer — the file a switch writes (§3.1). Watched, so
    // `punarctl theme set` repaints this session without touching the shell.
    //
    // HONEST LIMIT: an inotify watch on a path that does not exist yet cannot
    // be relied on to fire when the file is FIRST created. applyTheme() reloads
    // this view itself after its own write, and `qs -p /usr/share/punar/shell
    // ipc call theme reload` forces a re-read; a punarctl-side `theme set`
    // should make that call after it writes, exactly as it calls
    // `hyprctl reload` for the compositor half (§6.2 step 6).
    FileView {
        id: userPointerFile
        path: root.userPointerPath
        blockLoading: true
        watchChanges: true
        onFileChanged: userPointerFile.reload()
        onLoaded: {
            try {
                var doc = JSON.parse(userPointerFile.text());
                root.userPointer = (doc && doc.kind === "PunarThemePointer") ? doc : null;
            } catch (e) {
                console.warn("punar-shell: unparsable theme pointer at", userPointerFile.path, e);
                root.userPointer = null;
            }
        }
        onLoadFailed: root.userPointer = null
    }

    FileView {
        id: systemPointerFile
        blockLoading: true
        watchChanges: true
        onFileChanged: systemPointerFile.reload()
        onLoaded: {
            try {
                var doc = JSON.parse(systemPointerFile.text());
                root.systemPointer = (doc && doc.kind === "PunarThemePointer") ? doc : null;
            } catch (e) {
                console.warn("punar-shell: unparsable theme pointer at", systemPointerFile.path, e);
                root.systemPointer = null;
            }
        }
        // The path handed to this view already exists (resolveFirst() checked),
        // so a failure here means the file went away under us.
        onLoadFailed: root.systemPointer = null
    }

    // The palette document for activeId, searched per §3.4: the user's own
    // themes, then site/org-delivered ones, then the shipped set.
    FileView {
        id: paletteFile
        blockLoading: true
        watchChanges: true
        onFileChanged: paletteFile.reload()
        onLoaded: {
            var doc = null;
            try {
                doc = JSON.parse(paletteFile.text());
            } catch (e) {
                console.warn("punar-shell: unparsable theme document at", paletteFile.path, e);
                root.palette = null;
                return;
            }
            // Cheap half of the gate on passive load (§6.3): a document that is
            // not even SHAPED like a theme cannot be painted, so R1+R2 run here.
            // The full R1-R9 gate runs in applyTheme(), which is the selection
            // path, and its verdict is recorded in the pointer's receipt.
            var shapeFailures = [];
            if (ThemeContrast.checkShape(doc, shapeFailures)) {
                root.palette = doc;
            } else {
                console.warn("punar-shell: theme document at", paletteFile.path, "does not meet the §3.2 contract (" + shapeFailures.length + " failures); falling back to the grammar palette");
                root.palette = null;
            }
        }
        onLoadFailed: root.palette = null
    }

    // §3.4 is a SEARCH, and a search must not be expressed by reassigning a
    // watching FileView's `path` from inside its own onLoadFailed handler:
    // measured on Quickshell 0.3.0 (headless sway, 2026-08-26), the second such
    // hop is dropped — "got operation finished from dropped operation" — and
    // the chain stalls silently on candidate three, leaving every theme
    // unresolved. So the search runs SYNCHRONOUSLY through the blocking scratch
    // reader, and the watching views are only ever handed a path that already
    // resolved. That also keeps blockLoading meaningful: the first frame is
    // painted with the real palette rather than with the fallback while an
    // async chain catches up.
    function resolveFirst(candidates: var): string {
        for (var i = 0; i < candidates.length; i++) {
            if (candidates[i] === "")
                continue;
            if (root.readDoc(candidates[i]) !== null)
                return candidates[i];
        }
        return "";
    }

    readonly property var themeSearchDirs: [root.userThemeDir, root.siteThemeDir, root.installedThemeDir, root.devThemeDir]

    function themePathCandidates(id: string): var {
        var out = [];
        for (var i = 0; i < root.themeSearchDirs.length; i++)
            if (root.themeSearchDirs[i] !== "")
                out.push(root.themeSearchDirs[i] + "/" + id + ".theme.json");
        return out;
    }

    function loadPalette(): void {
        var path = root.resolveFirst(root.themePathCandidates(root.activeId));
        if (path === "") {
            // §3.4 rank 5: no document for this id anywhere. tok() falls
            // through to the grammar file's colour block, which IS the paper
            // palette — the system looks exactly as it did before themes.
            root.palette = null;
            return;
        }
        if (paletteFile.path === path)
            paletteFile.reload();
        else
            paletteFile.path = path;
    }

    function loadSystemPointer(): void {
        var path = root.resolveFirst(root.systemPointerCandidates);
        if (path === "")
            root.systemPointer = null;
        else
            systemPointerFile.path = path;
    }

    onActiveIdChanged: root.loadPalette()

    Component.onCompleted: {
        root.loadSystemPointer();
        root.loadPalette();
    }

    // ---- token lookup ----

    function dig(node: var, path: var): var {
        var cursor = node;
        for (var i = 0; i < path.length; i++) {
            if (cursor === null || cursor === undefined || typeof cursor !== "object")
                return undefined;
            cursor = cursor[path[i]];
        }
        return cursor;
    }

    // Walk the active palette first, then `tokens`; fall back if absent.
    // Accessing root.tokens and root.paletteColor here keeps every derived
    // property reactive to BOTH a token reload and a theme switch — which is
    // the whole no-restart mechanism (§6.3).
    function tok(path: list<string>, fallback: var): var {
        if (path.length > 1 && path[0] === "color") {
            var sub = [];
            for (var i = 1; i < path.length; i++)
                sub.push(path[i]);
            var themed = root.dig(root.paletteColor, sub);
            if (themed !== undefined && themed !== null)
                return themed;
        }
        var v = root.dig(root.tokens, path);
        return (v === undefined || v === null) ? fallback : v;
    }

    // Same lookup, kept as a raw hex STRING. Needed wherever a colour has to be
    // substituted into text rather than assigned to a QML color property — the
    // wallpaper template is the only such consumer today.
    function tokHex(path: list<string>, fallback: string): string {
        var v = root.tok(path, fallback);
        return typeof v === "string" ? v : fallback;
    }

    // ---- color · paper block (DESIGN_LANGUAGE.md §2) ----
    //
    // These are LITERAL block accessors: paperX is always the theme's paper
    // block and panelX is always its panel block, whatever the mood. The
    // mood-aware set is shellX, below.
    readonly property color paperSurface: root.tok(["color", "paper", "surface"], "#FAF9F6")
    readonly property color ink: root.tok(["color", "paper", "ink"], "#000000")
    readonly property color ink2: root.tok(["color", "paper", "ink2"], "#333333")
    readonly property color ink3: root.tok(["color", "paper", "ink3"], "#666666")
    readonly property color muted: root.tok(["color", "paper", "muted"], "#F4F2EC")
    readonly property color raise2: root.tok(["color", "paper", "raise2"], "#EDEAE2")
    readonly property color border: root.tok(["color", "paper", "border"], "#E6E4DE")
    readonly property color inputBorder: root.tok(["color", "paper", "inputBorder"], "#8C8880")

    // ---- color · panel block ----
    readonly property color panelSurface: root.tok(["color", "panel", "surface"], "#08090A")
    readonly property color panelFg: root.tok(["color", "panel", "fg"], "#F2F3F5")
    readonly property color panelInk2: root.tok(["color", "panel", "ink2"], "#A8ADB6")
    readonly property color panelInk3: root.tok(["color", "panel", "ink3"], "#7B8290")
    readonly property color panelEdge: root.tok(["color", "panel", "edge"], "#26282E")

    // ---- color · status (the only "real" colors; §2 status table) ----
    readonly property color statusOk: root.tok(["color", "paper", "status", "ok"], "#2E6B21")
    readonly property color statusWarn: root.tok(["color", "paper", "status", "warn"], "#8A5A00")
    readonly property color statusBad: root.tok(["color", "paper", "status", "bad"], "#A31F2C")
    readonly property color panelStatusOk: root.tok(["color", "panel", "status", "ok"], "#A3E047")
    readonly property color panelStatusWarn: root.tok(["color", "panel", "status", "warn"], "#F2BE85")
    readonly property color panelStatusBad: root.tok(["color", "panel", "status", "bad"], "#FF7A7A")

    // ---- color · action (DESIGN_LANGUAGE.md §2 "Action color") ----
    //
    // DERIVED, never authored (theme-system.md §2): action.bg = status.ok of
    // the block, action.fg = its surface, destructive = status.bad. Deriving
    // them makes the design language's promise structural — the affirmative
    // button is coloured BECAUSE it is a decision, using the same green the
    // decision itself uses. (For the shipped default these are byte-identical
    // to the grammar file's `color.action` block, so nothing changes today.)
    readonly property color actionBg: root.statusOk
    readonly property color actionFg: root.paperSurface
    readonly property color destructive: root.statusBad
    readonly property color panelActionBg: root.panelStatusOk
    readonly property color panelActionFg: root.panelSurface
    readonly property color panelDestructive: root.panelStatusBad

    // ---- the mood-aware set (theme-system.md §2.1) ----
    //
    // Shell surfaces — bar, command center, System Control, approvals, AI
    // panel, privacy panel, notifications, greeter — render on the block the
    // active mood selects. A surface that consumes these follows the mood; a
    // surface that consumes paperX/panelX pins itself to one block, which is
    // correct for the terminal, plates and OSD overlays (design language §6).
    readonly property color shellSurface: root.moodPanel ? root.panelSurface : root.paperSurface
    readonly property color shellFg: root.moodPanel ? root.panelFg : root.ink
    readonly property color shellInk2: root.moodPanel ? root.panelInk2 : root.ink2
    readonly property color shellInk3: root.moodPanel ? root.panelInk3 : root.ink3

    // §2 deliberate asymmetry: the panel block has NO muted/raise2, because on
    // panel surfaces elevation is stated with an edge, not a fill. In panel
    // mood a raised card is therefore the same surface plus shellBorder — which
    // is also why the system has no text-on-raised-panel pair to measure.
    readonly property color shellMuted: root.moodPanel ? root.panelSurface : root.muted
    readonly property color shellRaise2: root.moodPanel ? root.panelSurface : root.raise2
    readonly property color shellBorder: root.moodPanel ? root.panelEdge : root.border

    // An input boundary is a UI component boundary and must clear 3:1 (measured
    // pair 15). panel.edge is a hairline at ~1.3:1 and would fail that, so in
    // panel mood the input boundary is panel.ink3 — the same token measured at
    // pair 19, which every theme must get above 4.5:1.
    readonly property color shellInputBorder: root.moodPanel ? root.panelInk3 : root.inputBorder

    readonly property color shellStatusOk: root.moodPanel ? root.panelStatusOk : root.statusOk
    readonly property color shellStatusWarn: root.moodPanel ? root.panelStatusWarn : root.statusWarn
    readonly property color shellStatusBad: root.moodPanel ? root.panelStatusBad : root.statusBad
    readonly property color shellActionBg: root.moodPanel ? root.panelActionBg : root.actionBg
    readonly property color shellActionFg: root.moodPanel ? root.panelActionFg : root.actionFg
    readonly property color shellDestructive: root.moodPanel ? root.panelDestructive : root.destructive

    // Non-negotiable 4: a 2px ink (or panel-fg) ring, offset 2px, NO colour
    // dependence — measured pairs 16 and 24 keep it above 3:1 in every theme.
    readonly property color shellFocusRing: root.shellFg

    // Warm ink wash for overlay scrims: the shadow-family warm ink base
    // (rgb(28 24 16), the base of the shadow tokens) at 22% — matches
    // .scrim in docs/design/mockups/command-approval.html ("the scrim is
    // the warm ink wash at 22%, never a blur-only dim"). Translucency in Punar
    // is a scrim recipe in the grammar, not a token (§3.2), so a theme cannot
    // reach it.
    readonly property color inkWash: Qt.rgba(28 / 255, 24 / 255, 16 / 255, 0.22)

    // The mood-aware scrim — added at integration, because the warm wash above
    // is a PAPER recipe and a shell running in panel mood has no paper behind
    // it. Over a near-black field (#08090A at ~0.003 relative luminance) a 22%
    // warm-ink wash does not darken anything; it very slightly LIGHTENS the
    // field, so the modal's own ground stops being the subject and the
    // wallpaper's marks stay exactly as loud as they were. That is the one
    // thing a scrim exists to prevent.
    //
    // On panel the scrim is therefore neutral black at 55%: it takes the field
    // and its watermark marks down together, and the card — which in panel mood
    // is the SAME colour as the field, because §2's panel block has no raised
    // fill — is separated by its shellBorder hairline, which is the panel
    // grammar for elevation (design language §3, "on panel surfaces prefer
    // edges to shadows"). Like inkWash this is a recipe in the grammar, not a
    // token: a theme author cannot reach it, and it is derived from nothing a
    // theme document says beyond the mood it selects (theme-system.md §3.2).
    readonly property color shellScrim: root.moodPanel ? Qt.rgba(0, 0, 0, 0.55) : root.inkWash

    // ---- derived · wallpaper (theme-system.md §7.3 · Plate D-015 Sect II) ----
    //
    // "A theme author writes nineteen colours. Everything else in the system is
    // computed from them." The wallpaper template carries exactly three
    // placeholders — field, hairline, emphasis — and the variant is the mood.
    //
    //   variant   field           hairline                              emphasis
    //   paper     paper.surface   paper.muted                           paper.raise2
    //   panel     panel.surface   mix(panel.surface, panel.edge, 0.42)  mix(panel.surface, panel.edge, 0.75)
    //
    // The PAPER row is theme-system.md §7.3 verbatim, and validator rule R7 is
    // what keeps those two marks strictly quieter than a window border in every
    // selectable theme — the rule Plate D-015 Sect II.02 states.
    //
    // THE PANEL ROW DELIBERATELY DEVIATES FROM §7.3's TABLE, and the deviation
    // is measured, not stylistic. §7.3 lists the panel hairline as
    // mix(surface, edge, 0.55) and the panel emphasis as `panel.edge` at full
    // strength. But §7.2 binds the INACTIVE WINDOW BORDER to `panel.edge` as
    // well, so taking §7.3 literally makes the loudest wallpaper stroke exactly
    // equal to the border it must stay under. Measured on all seven shipped
    // themes, §7.3-literal gives emphasis 1.353 / 1.353 / 1.298 / 1.280 / 1.274
    // / 1.280 / 4.119 against the field — tying the border in every single one,
    // and exceeding Plate D-015 Sect II.01's stated ceiling ("no wallpaper
    // stroke may exceed 1.25:1 against its own field") in every single one.
    // D-015 is a reference mockup of the BINDING design language (§10) and its
    // Sect II is the legibility contract for this exact asset, so it wins.
    //
    // The factors used here are not invented either: the shipped panel asset
    // docs/design/assets/punar-wallpaper-panel.svg draws its two tones as
    // `panel.edge` at stroke-opacity .42 and .75 over the flat field, and
    // compositing a flat opacity over a flat field IS an sRGB mix at that
    // factor. For the default palette this reproduces the shipped drawing
    // byte-for-byte — #151619 at 1.101:1 and #1E2025 at 1.223:1, which are the
    // 1.10:1 and 1.22:1 D-015 Sect II.01 publishes — and across the whole
    // shipped set it keeps the border strictly ahead of the emphasis
    // (1.353 > 1.223, 1.298 > 1.192, 1.280 > 1.188, 1.274 > 1.184,
    // 1.280 > 1.188, 4.119 > 2.688).
    //
    // ONE HONEST EXCEEDANCE: `contrast` (High Contrast) has a deliberately loud
    // panel.edge (#6E6E6E), so its panel emphasis lands at 2.688:1 — well over
    // D-015's 1.25 ceiling. That ceiling exists to stop the field competing with
    // a window border, and it still does not (4.119 > 2.688). The legibility
    // consequence was measured rather than assumed: panel.fg over that stroke is
    // 7.4:1, still above AAA's 7:1, so no text class boundary is crossed. A user
    // who selects High Contrast has asked for exactly this.
    //
    // The one-line reconciliation for whoever owns theme-system.md: change the
    // §7.3 panel row to read mix(panel.surface, panel.edge, 0.42) and
    // mix(panel.surface, panel.edge, 0.75). That makes the two documents agree
    // and changes no shipped pixel.
    readonly property string wallpaperVariant: root.moodPanel ? "panel" : "paper"

    readonly property string wallpaperField: root.moodPanel ? root.tokHex(["color", "panel", "surface"], "#08090A") : root.tokHex(["color", "paper", "surface"], "#FAF9F6")

    readonly property string wallpaperHairline: root.moodPanel ? ThemeContrast.mix(root.tokHex(["color", "panel", "surface"], "#08090A"), root.tokHex(["color", "panel", "edge"], "#26282E"), 0.42) : root.tokHex(["color", "paper", "muted"], "#F4F2EC")

    readonly property string wallpaperEmphasis: root.moodPanel ? ThemeContrast.mix(root.tokHex(["color", "panel", "surface"], "#08090A"), root.tokHex(["color", "panel", "edge"], "#26282E"), 0.75) : root.tokHex(["color", "paper", "raise2"], "#EDEAE2")

    // ---- derived · terminal (theme-system.md §7.1) ----
    //
    // Exposed so a surface can PRINT the derivation (punarctl theme render
    // --target foot writes it). The shell does not restyle any terminal: foot
    // reads its own config, and already-running terminals keep the palette they
    // started with. Slot 0 is panel.edge, the structural/dim slot, and is the
    // one slot R8 exempts.
    readonly property var ansiSlots: {
        var p = root.paletteColor;
        if (p !== null && p.panel)
            return ThemeContrast.ansiSlots(p.panel);
        return ThemeContrast.ansiSlots({
            "surface": root.tokHex(["color", "panel", "surface"], "#08090A"),
            "fg": root.tokHex(["color", "panel", "fg"], "#F2F3F5"),
            "ink2": root.tokHex(["color", "panel", "ink2"], "#A8ADB6"),
            "ink3": root.tokHex(["color", "panel", "ink3"], "#7B8290"),
            "edge": root.tokHex(["color", "panel", "edge"], "#26282E"),
            "status": {
                "ok": root.tokHex(["color", "panel", "status", "ok"], "#A3E047"),
                "warn": root.tokHex(["color", "panel", "status", "warn"], "#F2BE85"),
                "bad": root.tokHex(["color", "panel", "status", "bad"], "#FF7A7A")
            }
        });
    }

    // ---- typography (DESIGN_LANGUAGE.md §1) — GRAMMAR, not themeable (§2) ----
    readonly property string fontSans: root.tok(["font", "sans", "family"], "Instrument Sans")
    readonly property string fontMono: root.tok(["font", "mono", "family"], "Geist Mono")
    readonly property real trackingLabelEm: root.tok(["font", "trackingLabelEm"], 0.12)
    readonly property int labelSize: root.tok(["font", "labelSizePx"], 12)
    readonly property int metaSize: root.tok(["font", "metaSizePx"], 10)

    // letterSpacing in QML is px; the design tracks in em. Always pass the
    // em value from the mockup/type-role table explicitly.
    function tracking(sizePx: real, em: real): real {
        return sizePx * em;
    }

    // ---- shape (DESIGN_LANGUAGE.md §3) — GRAMMAR ----
    readonly property int radius: root.tok(["shape", "radiusPx"], 10)
    readonly property int radiusTag: root.tok(["shape", "radiusTagPx"], 6)
    readonly property int hairline: root.tok(["shape", "hairlinePx"], 1)

    // ---- motion (DESIGN_LANGUAGE.md §4 — fluid, not decorative) — GRAMMAR ----
    readonly property int durMicro: root.tok(["motion", "durationMs", "micro"], 150)
    readonly property int durStandard: root.tok(["motion", "durationMs", "standard"], 300)
    readonly property int durSpatial: root.tok(["motion", "durationMs", "spatial"], 450)

    // cubic-bezier(0.2, 0, 0, 1) from tokens, in Easing.BezierSpline form
    // (control points + the terminal 1,1 pair).
    readonly property var easingCurve: {
        var e = root.tok(["motion", "ease"], [0.2, 0, 0, 1]);
        return [e[0], e[1], e[2], e[3], 1, 1];
    }

    // The grammar version a theme records itself against (§9.2). R9 refuses a
    // theme from a different MAJOR, naming the removed token.
    readonly property string grammarVersion: root.tok(["meta", "version"], "0.1.0")
    readonly property int grammarMajor: {
        var n = parseInt(String(root.grammarVersion).split(".")[0], 10);
        return isNaN(n) ? 0 : n;
    }

    // ---- the catalog (§4.5 `theme list`, §6.4 the picker) ----
    //
    // Enumeration costs NOTHING until something asks for it: the three
    // FolderListModels have an empty `folder` until ensureCatalog() flips
    // catalogWanted, and they watch their directory through the file-system
    // watcher rather than a timer. A session that never opens the picker never
    // reads a theme document it is not using.
    property bool catalogWanted: false

    // [{id, name, intent, defaultMood, source, path, swatch[6], pass,
    //   minText, minNonText, failures[]}], sorted with the active theme first
    // and then by name. Every entry carries its FULL R1-R9 verdict, so a picker
    // can mark a refused row without recomputing anything.
    property var catalog: []

    // Enumeration is ASYNCHRONOUS — FolderListModel scans on its own worker
    // thread — so `catalog` is empty for the few milliseconds after the first
    // ensureCatalog(). A picker must bind to `catalog` and `catalogReady`
    // (both reactive) rather than read them once; the IPC `list` verb reports
    // `ready` for the same reason instead of pretending an empty first answer
    // is an empty set of themes.
    readonly property bool catalogReady: root.catalogWanted && userThemeFiles.status !== FolderListModel.Loading && siteThemeFiles.status !== FolderListModel.Loading && shippedThemeFiles.status !== FolderListModel.Loading && devThemeFiles.status !== FolderListModel.Loading

    function ensureCatalog(): void {
        root.catalogWanted = true;
        root.rebuildCatalog();
    }

    FolderListModel {
        id: userThemeFiles
        folder: (root.catalogWanted && root.userThemeDir !== "") ? "file://" + root.userThemeDir : ""
        nameFilters: ["*.theme.json"]
        showDirs: false
        sortField: FolderListModel.Name
        onCountChanged: root.rebuildCatalog()
        onStatusChanged: root.rebuildCatalog()
    }

    FolderListModel {
        id: siteThemeFiles
        folder: root.catalogWanted ? "file://" + root.siteThemeDir : ""
        nameFilters: ["*.theme.json"]
        showDirs: false
        sortField: FolderListModel.Name
        onCountChanged: root.rebuildCatalog()
        onStatusChanged: root.rebuildCatalog()
    }

    FolderListModel {
        id: shippedThemeFiles
        folder: root.catalogWanted ? "file://" + root.installedThemeDir : ""
        nameFilters: ["*.theme.json"]
        showDirs: false
        sortField: FolderListModel.Name
        onCountChanged: root.rebuildCatalog()
        onStatusChanged: root.rebuildCatalog()
    }

    // The repo layout only — on an installed image `shippedThemeFiles` finds
    // the set and this model never opens a directory at all.
    FolderListModel {
        id: devThemeFiles
        folder: (root.catalogWanted && shippedThemeFiles.count === 0) ? "file://" + root.devThemeDir : ""
        nameFilters: ["*.theme.json"]
        showDirs: false
        sortField: FolderListModel.Name
        onCountChanged: root.rebuildCatalog()
        onStatusChanged: root.rebuildCatalog()
    }

    // A single reusable blocking reader. blockLoading makes text() synchronous,
    // which is what lets the catalog be built in one pass instead of a web of
    // callbacks. It reads only when a picker asks, and each file is ~950 bytes.
    FileView {
        id: scratchFile
        blockLoading: true
        printErrors: false
    }

    function readDoc(path: string): var {
        // Clearing the path first forces a fresh read rather than handing back
        // a cached text: this view does not watch, and a user who hand-edited
        // their own theme must be validated against what is on disk NOW.
        scratchFile.path = "";
        scratchFile.path = path;
        var text = scratchFile.text();
        if (!text || text === "")
            return null;
        try {
            return JSON.parse(text);
        } catch (e) {
            return null;
        }
    }

    // §6.4: the theme's surface/ink/ink3 then its ok/warn/bad — exactly what
    // the theme controls, in the order the contract lists it. This is the ONLY
    // place in the shell where colour appears without a status meaning, and it
    // is legitimate because here the colour IS the datum. Returns [] rather
    // than throwing for a document that failed its shape check, so one broken
    // file in ~/.config/punar/themes/ cannot take the picker down with it.
    function swatchOf(doc: var): var {
        var c = doc.color;
        if (!c || !c.paper || !c.paper.status)
            return [];
        return [c.paper.surface, c.paper.ink, c.paper.ink3, c.paper.status.ok, c.paper.status.warn, c.paper.status.bad];
    }

    function rebuildCatalog(): void {
        if (!root.catalogWanted)
            return;
        var sources = [[userThemeFiles, "user"], [siteThemeFiles, "site"], [shippedThemeFiles, "shipped"], [devThemeFiles, "shipped"]];
        var byId = ({});
        var order = [];
        for (var s = 0; s < sources.length; s++) {
            var model = sources[s][0];
            var origin = sources[s][1];
            for (var i = 0; i < model.count; i++) {
                var path = String(model.get(i, "filePath"));
                var file = String(model.get(i, "fileName"));
                var id = file.replace(/\.theme\.json$/, "");
                // §3.4: the FIRST directory in the search order wins, and a
                // later one may not shadow it.
                if (byId[id] !== undefined)
                    continue;
                var doc = root.readDoc(path);
                if (doc === null)
                    continue;
                var verdict = ThemeContrast.validate(doc, root.grammarMajor);
                var meta = doc.meta ? doc.meta : ({});
                byId[id] = {
                    "id": id,
                    "name": meta.name ? meta.name : id,
                    "intent": meta.intent ? meta.intent : "",
                    // §3.2: meta.id must equal the filename stem.
                    "idMatchesFile": meta.id === id,
                    "defaultMood": meta.defaultMood ? meta.defaultMood : "paper",
                    "source": origin,
                    "path": path,
                    "swatch": root.swatchOf(doc),
                    "pass": verdict.pass,
                    "minText": verdict.minText,
                    "minNonText": verdict.minNonText,
                    "failures": verdict.failures
                };
                order.push(id);
            }
        }
        order.sort(function (a, b) {
            if (a === root.activeId)
                return -1;
            if (b === root.activeId)
                return 1;
            return byId[a].name.localeCompare(byId[b].name);
        });
        var out = [];
        for (var k = 0; k < order.length; k++)
            out.push(byId[order[k]]);
        root.catalog = out;
    }

    // ---- selection (§4, §6.2, §6.4) ----

    function themeDocument(id: string): var {
        var candidates = root.themePathCandidates(id);
        for (var i = 0; i < candidates.length; i++) {
            var doc = root.readDoc(candidates[i]);
            if (doc !== null)
                return doc;
        }
        return null;
    }

    // §6.4: preview writes nothing and repaints immediately. It accepts a
    // SHAPED theme (R1+R2) because the gate belongs on commitment, not on
    // looking — but a document that is not shaped like a theme is not previewed
    // either, because there would be nothing coherent to paint.
    function previewTheme(id: string, requestedMoodOverride: string): bool {
        var doc = root.themeDocument(id);
        if (doc === null)
            return false;
        var shapeFailures = [];
        if (!ThemeContrast.checkShape(doc, shapeFailures))
            return false;
        root.previewPalette = doc;
        root.previewMood = (requestedMoodOverride === "paper" || requestedMoodOverride === "panel") ? requestedMoodOverride : "";
        return true;
    }

    function clearPreview(): void {
        root.previewPalette = null;
        root.previewMood = "";
    }

    // §6.2 steps 1-4, in the shell. Returns the verdict record:
    //   {applied, reason, id, mood, pass, minText, minNonText, failures[]}
    //
    // THE GATE. Punar refuses to select a theme it cannot prove is legible,
    // because these surfaces exist to explain restrictions and a theme that
    // hides a denial is a safety problem, not a taste problem (§4). On refusal
    // NOTHING is written and the active theme is provably unchanged — which is
    // acceptance item §10.4.
    //
    // Steps 5-7 of §6.2 (render the derived foot/hypr artefacts, `hyprctl
    // reload`, print the D-014 verdict line) belong to punarctl and are not
    // done here: this function is the shell's own selection path, and it does
    // not reach outside the session it draws.
    function applyTheme(id: string, requestedMoodOverride: string): var {
        var verdict = {
            "applied": false,
            "reason": "",
            "id": id,
            "mood": requestedMoodOverride === "" ? "default" : requestedMoodOverride,
            "pass": false,
            "minText": -1,
            "minNonText": -1,
            "failures": []
        };
        if (root.userPointerPath === "") {
            verdict.reason = "no HOME in the environment; there is nowhere to record a preference";
            return verdict;
        }
        var doc = root.themeDocument(id);
        if (doc === null) {
            // §46's promise about stability: an id that is not installed is
            // REPORTED as not found, never silently ignored.
            verdict.reason = "theme \"" + id + "\" is not installed";
            return verdict;
        }
        var result = ThemeContrast.validate(doc, root.grammarMajor);
        verdict.pass = result.pass;
        verdict.minText = result.minText;
        verdict.minNonText = result.minNonText;
        verdict.failures = result.failures;
        if (!result.pass) {
            verdict.reason = id + " does not meet the theme contract. It was not selected; the active theme is unchanged.";
            return verdict;
        }
        var mood = (requestedMoodOverride === "paper" || requestedMoodOverride === "panel") ? requestedMoodOverride : "default";
        var pointerDoc = {
            "$schema": "https://schemas.punar.dev/v1alpha1/theme/pointer.json",
            "kind": "PunarThemePointer",
            "active": id,
            "mood": mood,
            "validated": {
                "at": new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
                "grammar": root.grammarVersion,
                "minText": result.minText,
                "minNonText": result.minNonText
            }
        };
        // atomicWrites: QSaveFile tmp+rename, and parent directories are
        // created — the same primitive Services/WorkspaceState.qml uses.
        userPointerFile.setText(JSON.stringify(pointerDoc, null, 2) + "\n");
        root.clearPreview();
        root.userPointer = pointerDoc;
        verdict.applied = true;
        verdict.reason = "active theme is now " + id;
        return verdict;
    }

    // §4.5 `theme reset` — drops the USER pointer only, so resolution falls
    // through to the system/shipped pointer. It touches exactly one path and
    // never a theme document.
    function resetTheme(): bool {
        if (root.userPointerPath === "")
            return false;
        pointerRemover.command = ["rm", "-f", root.userPointerPath];
        pointerRemover.running = true;
        root.userPointer = null;
        return true;
    }

    Process {
        id: pointerRemover
    }

    // ---- IPC (§6.5 "two paths, one gate, same voice") ----
    //
    // qs -p /usr/share/punar/shell ipc call theme <verb> [...]
    //
    // The command center's picker and punarctl both drive the same functions
    // above, so a preference set from a terminal and one set from the keyboard
    // go through the identical gate and produce the identical pointer.
    IpcHandler {
        target: "theme"

        function status(): string {
            return JSON.stringify({
                "active": root.activeId,
                "name": root.activeName,
                "mood": root.mood,
                "requestedMood": root.requestedMood,
                "source": root.activeSource,
                "previewing": root.previewPalette !== null,
                "grammar": root.grammarVersion,
                "resolved": root.palette !== null ? paletteFile.path : "built-in fallback palette"
            });
        }

        // The first call PRIMES the enumeration and will usually answer
        // ready:false with an empty set — the directory scan runs on
        // FolderListModel's worker thread. Call it again, or bind to
        // Theme.catalog from QML. `punarctl theme list` does not use this at
        // all: §4.5 makes the CLI client-side, walking §3.4 itself.
        function list(): string {
            root.ensureCatalog();
            return JSON.stringify({
                "ready": root.catalogReady,
                "themes": root.catalog
            });
        }

        function show(id: string): string {
            var doc = root.themeDocument(id);
            if (doc === null)
                return JSON.stringify({
                    "error": "not found",
                    "id": id
                });
            var verdict = ThemeContrast.validate(doc, root.grammarMajor);
            return JSON.stringify({
                "id": id,
                "meta": doc.meta,
                "color": doc.color,
                "verdict": verdict,
                // The §7.1 derivation is printed only for a document that has a
                // panel block to derive it from; a refused theme still gets its
                // full verdict, which is the part that explains the refusal.
                "ansi": (doc.color && doc.color.panel) ? ThemeContrast.ansiSlots(doc.color.panel) : null
            });
        }

        function validate(id: string): string {
            var doc = root.themeDocument(id);
            if (doc === null)
                return JSON.stringify({
                    "pass": false,
                    "id": id,
                    "failures": [{
                        "rule": "R1",
                        "detail": "theme \"" + id + "\" is not installed"
                    }]
                });
            return JSON.stringify(ThemeContrast.validate(doc, root.grammarMajor));
        }

        function preview(id: string, mood: string): string {
            return JSON.stringify({
                "previewing": root.previewTheme(id, mood),
                "id": id,
                "mood": root.mood
            });
        }

        function clear(): string {
            root.clearPreview();
            return JSON.stringify({
                "previewing": false,
                "active": root.activeId,
                "mood": root.mood
            });
        }

        function set(id: string, mood: string): string {
            return JSON.stringify(root.applyTheme(id, mood));
        }

        function reset(): string {
            return JSON.stringify({
                "reset": root.resetTheme()
            });
        }

        // Forces a re-read of the user pointer. Exists because an inotify watch
        // on a path that does not exist yet cannot be relied on to fire when
        // the file is first created; a punarctl-side `theme set` should call
        // this after its write.
        function reload(): string {
            userPointerFile.reload();
            paletteFile.reload();
            return JSON.stringify({
                "active": root.activeId,
                "mood": root.mood
            });
        }
    }
}
