pragma Singleton
pragma ComponentBehavior: Bound
// BindTable — the shortcut reference's ONLY data source (Plate D-017,
// docs/design/mockups/shortcuts.html Sect I and Sect V·05).
//
// THE ANTI-DRIFT RULE, and it is the whole reason this file exists: the
// shell renders `hyprctl binds -j` and NOTHING ELSE. Not a QML array, not
// a Markdown table, not a generated header — the live table the
// compositor is currently dispatching from. A hardcoded list is a second
// source of truth, and a second source of truth is a promise to be wrong
// later: the day someone moves the assistant scratchpad to
// PUNAR+SHIFT+A (M7 did exactly that), a hand list keeps confidently
// printing the old chord to a user who then presses it and gets nothing.
//
// NO DESCRIPTION · NO ROW (Sect I·03). A bind whose description is empty
// is EXCLUDED — not shown with its dispatcher as a fallback label, not
// shown as "unnamed", excluded. That absence is the enforcement: an
// undescribed binding is invisible to every user of the machine, so the
// pressure to write a label lands on the person adding the binding, at
// the moment they add it. The count of excluded binds is printed in the
// footer, and the number rising is the alarm.
//
// ORDER IS CONFIG ORDER (Sect I·04), and on 0.56.2 that is a fact rather
// than a hope: `hyprctl binds -j` iterates `CKeybindManager::m_keybinds`,
// which `addKeybind` only ever `emplace_back`s (Hyprland v0.56.2,
// src/debug/HyprCtl.cpp bindsRequest / src/managers/KeybindManager.cpp
// addKeybind). There is no sort function here to get wrong; the
// maintainer reorders the reference by reordering punar-binds.conf.
//
// NO POLL, NO TIMER, NO FILE WATCH (Sect V·05): the query runs ONCE per
// session, lazily, on the first open of the surface. The parsed rows are
// cached in memory and the surface re-renders from the cache. Cache
// invalidation has exactly one trigger — Hyprland's own `configreloaded`
// event on socket2, which v0.56.2 does emit
// (src/config/legacy/ConfigManager.cpp: postEvent({"configreloaded"})) —
// plus an explicit `ipc call shortcuts reload` for a human who wants to
// force it. At rest the whole feature costs one cached array.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Hyprland

Singleton {
    id: table

    // ---- cache state -------------------------------------------------

    // True once a query has completed, successfully or not — the surface
    // uses it to tell "not asked yet" from "asked and got nothing".
    property bool loaded: false
    property bool loading: false

    // Global rows (submap === ""), folded, in config order.
    property var rows: []
    // Rows that live inside a submap — a mode, not the global grammar.
    property var modeRows: []
    // Name of the submap the mode rows belong to ("" when there is none).
    property string modeName: ""

    // Footer arithmetic, all computed from the same table the rows are.
    property int rawCount: 0
    property int undescribed: 0
    property int unmapped: 0

    // "" while healthy; a plain sentence when the compositor could not be
    // asked. A malformed or empty result renders the calm empty state and
    // never an exception (Sect V·05).
    property string problem: ""

    readonly property int rowCount: table.rows.length + table.modeRows.length

    // ---- the transform (Sect I·02) -----------------------------------

    readonly property var sectionOrder: ["WINDOWS", "WORKSPACES AND PROJECTS",
        "LAYOUTS", "SURFACES", "MEDIA", "SESSION", "OTHER"]

    // A CLOSED table keyed on the dispatcher — about fifteen Hyprland
    // verbs, not forty bindings. A new binding on a verb the table
    // already knows files itself with no code change at all, which is the
    // point: the table is small, closed, and changes an order of
    // magnitude less often than the binds do.
    readonly property var bySection: ({
            "movefocus": "WINDOWS",
            "movewindow": "WINDOWS",
            "killactive": "WINDOWS",
            "submap": "WINDOWS",
            "resizeactive": "WINDOWS",
            "workspace": "WORKSPACES AND PROJECTS",
            "movetoworkspace": "WORKSPACES AND PROJECTS",
            "togglegroup": "LAYOUTS",
            "moveoutofgroup": "LAYOUTS",
            "changegroupactive": "LAYOUTS",
            "moveintogroup": "LAYOUTS",
            "fullscreen": "LAYOUTS",
            "togglefloating": "LAYOUTS",
            "pin": "LAYOUTS",
            "centerwindow": "LAYOUTS",
            "togglespecialworkspace": "SURFACES",
            "exit": "SESSION"
        })

    // `exec` is not a verb, so it is disambiguated by the command, which
    // Punar owns. A command containing `ipc call <target>` takes the
    // section of THAT SHELL TARGET — a contract the shell itself defines
    // and therefore cannot drift from — and a short command table covers
    // the rest. Rename one of those and its row does not vanish and is
    // not mislabelled: it falls to OTHER, visible, with the real chord
    // and the real description. Same enforcement shape as the missing
    // description: the mistake is loud, not silent.
    readonly property var byIpcTarget: ({
            "overview": "WORKSPACES AND PROJECTS",
            "commandcenter": "SURFACES",
            "aipanel": "SURFACES",
            "approval": "SURFACES",
            "alerts": "SURFACES",
            "notifications": "SURFACES",
            "windowactions": "WINDOWS",
            "systemcontrol": "SURFACES",
            "shortcuts": "SURFACES",
            "bar": "SURFACES",
            // Locking the session is a SESSION verb, not a surface you
            // open: the `lock` target exposes `lock` and `state` and no
            // `unlock`, so there is nothing to toggle back to.
            "lock": "SESSION"
        })

    // `wpctl` is wireplumber's own CLI and the media keys exec it
    // directly rather than going through the shell, because the OSD reads
    // the SINK rather than the keypress (Plate D-009 Sect III). It earns
    // the MEDIA section rather than falling to OTHER: OTHER is the loud
    // failure for a row nobody classified, and these rows are classified.
    readonly property var byCommand: [["punar-layout.sh", "LAYOUTS"], ["footclient", "SURFACES"], ["foot", "SURFACES"], ["chromium", "SURFACES"], ["wpctl", "MEDIA"], ["grim", "SESSION"]]

    // THE DISPATCHER CHANNEL IS GONE, AND THE SHIPPED SURFACE PROVED IT.
    // The Lua-native session registers every bind through hl.bind, and
    // `hyprctl binds -j` reports EVERY one of them with dispatcher
    // `__lua` and an opaque callback id as the arg — including the ones
    // that were `exec` under the .conf grammar, which is why byIpcTarget
    // and byCommand went dark at the same moment as bySection. The
    // captured proof reads `75 BINDS · 75 ROWS · 0 UNDESCRIBED ·
    // 75 UNMAPPED` under a single OTHER heading: not one row classified,
    // and the digit fold never fired. A person opening PUNAR+/ to learn
    // how to reach another workspace got seventy-five undifferentiated
    // rows with WORKSPACES AND PROJECTS scrolled off the bottom, which is
    // exactly the failure spec §12.3 names this surface to prevent and
    // D-017 Sect V·03 designates it the fallback for.
    //
    // So classify on what the Lua session DOES expose. surfaces-check.sh
    // states the contract in its own words: "their stable runtime
    // contract is the key and human description". The description is
    // authored in punar-binds.lua, in this repository, one line from the
    // bind it names — the same distance byCommand's command strings sit
    // from theirs.
    //
    // ORDERED, and first match wins, because the specific case must beat
    // the general one: "Move window to workspace 3" is a WORKSPACES row
    // and "Move window left" is a WINDOWS row, and they share a prefix.
    // A description this table does not know still falls to OTHER and
    // still counts as unmapped in the footer — the drift stays loud,
    // which is the property the dispatcher table was chosen for and the
    // one worth keeping.
    readonly property var byDescription: [
        ["Move window to workspace ", "WORKSPACES AND PROJECTS"],
        ["Workspace ", "WORKSPACES AND PROJECTS"],
        ["Previous workspace", "WORKSPACES AND PROJECTS"],
        ["Project overview", "WORKSPACES AND PROJECTS"],
        ["Move window into group ", "LAYOUTS"],
        ["Move window out of group", "LAYOUTS"],
        ["Move window to left monitor", "WINDOWS"],
        ["Move window to right monitor", "WINDOWS"],
        ["Move window to upper monitor", "WINDOWS"],
        ["Move window to lower monitor", "WINDOWS"],
        ["Move window ", "WINDOWS"],
        ["Focus status cluster", "SURFACES"],
        ["Focus ", "WINDOWS"],
        ["Close window", "WINDOWS"],
        ["Window actions", "WINDOWS"],
        ["Enter resize mode", "WINDOWS"],
        ["Exit resize mode", "WINDOWS"],
        ["Resize ", "WINDOWS"],
        ["Toggle window group", "LAYOUTS"],
        ["Previous window in group", "LAYOUTS"],
        ["Next window in group", "LAYOUTS"],
        ["Toggle fullscreen", "LAYOUTS"],
        ["Toggle floating", "LAYOUTS"],
        ["Pin floating window", "LAYOUTS"],
        ["Center floating window", "LAYOUTS"],
        ["Previous layout preset", "LAYOUTS"],
        ["Next layout preset", "LAYOUTS"],
        ["Open command center", "SURFACES"],
        ["Open terminal", "SURFACES"],
        ["Open browser", "SURFACES"],
        ["AI on this device", "SURFACES"],
        ["Privacy and network activity", "SURFACES"],
        ["Toggle scratchpad terminal", "SURFACES"],
        ["Toggle assistant scratchpad", "SURFACES"],
        ["Toggle notes scratchpad", "SURFACES"],
        ["Notification centre", "SURFACES"],
        ["Shortcut help", "SURFACES"],
        ["System control", "SURFACES"],
        ["Screenshot ", "SESSION"],
        ["Volume ", "MEDIA"],
        ["Toggle mute", "MEDIA"],
        ["End session", "SESSION"],
        ["Lock session", "SESSION"],
        ["Session menu", "SESSION"]
    ]

    // The keysym DISPLAY table — the one place the shell is allowed to
    // rewrite anything, and it rewrites keys, never descriptions. An
    // unrecognised keysym renders verbatim and is NEVER dropped, which is
    // why this table can stay short: growing it is cosmetic, and failing
    // to grow it costs a long cap and nothing else.
    readonly property var keyNames: ({
            "bracketleft": "[",
            "bracketright": "]",
            "comma": ",",
            "period": ".",
            "Return": "↵",
            "Space": "Space",
            "Tab": "Tab",
            "escape": "Esc",
            "left": "←",
            "right": "→",
            "up": "↑",
            "down": "↓",
            "slash": "/",
            "XF86AudioRaiseVolume": "Vol +",
            "XF86AudioLowerVolume": "Vol −",
            "XF86AudioMute": "Mute"
        })

    function keyLabel(key: string, keycode: int): string {
        if (key === "")
            // Bound by keycode rather than keysym: still a row, still
            // true, just spelled the only way the table can spell it.
            return keycode > 0 ? "Code " + keycode : "?";
        if (table.keyNames.hasOwnProperty(key))
            return table.keyNames[key];
        return key;
    }

    // Decoded against the standard modifier bits and rendered in ONE
    // canonical order — PUNAR, CTRL, SHIFT, ALT — never in bitmask order,
    // so two chords with the same modifiers always read identically.
    function modNames(mask: int): var {
        var out = [];
        if (mask & 64)
            out.push("Punar");
        if (mask & 4)
            out.push("Ctrl");
        if (mask & 1)
            out.push("Shift");
        if (mask & 8)
            out.push("Alt");
        return out;
    }

    function sectionFor(dispatcher: string, arg: string, label: string): string {
        // The dispatcher is tried FIRST and unchanged, so a session that
        // still reports real Hyprland verbs (a .conf grammar, or a future
        // Lua plugin that forwards them) classifies exactly as before and
        // this file needs no second edit to follow it back.
        var byVerb = table.sectionForDispatcher(dispatcher, arg);
        if (byVerb !== "OTHER")
            return byVerb;
        for (var d = 0; d < table.byDescription.length; d++) {
            if (label.indexOf(table.byDescription[d][0]) === 0)
                return table.byDescription[d][1];
        }
        return "OTHER";
    }

    function sectionForDispatcher(dispatcher: string, arg: string): string {
        if (dispatcher === "exec") {
            var at = arg.indexOf("ipc call ");
            if (at >= 0) {
                var rest = arg.substring(at + 9).split(" ");
                var target = rest.length > 0 ? rest[0] : "";
                if (table.byIpcTarget.hasOwnProperty(target))
                    return table.byIpcTarget[target];
                return "OTHER";
            }
            for (var i = 0; i < table.byCommand.length; i++) {
                if (arg.indexOf(table.byCommand[i][0]) >= 0)
                    return table.byCommand[i][1];
            }
            return "OTHER";
        }
        if (table.bySection.hasOwnProperty(dispatcher))
            return table.bySection[dispatcher];
        return "OTHER";
    }

    function chordText(row: var): string {
        var parts = row.submap === "" ? table.modNames(row.modmask) : [];
        parts.push(row.keyText);
        return parts.join(" + ");
    }

    // ---- parse -------------------------------------------------------

    function resetEmpty(): void {
        table.rows = [];
        table.modeRows = [];
        table.modeName = "";
        table.rawCount = 0;
        table.undescribed = 0;
        table.unmapped = 0;
    }

    function parse(text: string): void {
        var raw = null;
        try {
            raw = JSON.parse(text);
        } catch (e) {
            raw = null;
        }
        if (raw === null || !Array.isArray(raw)) {
            table.resetEmpty();
            table.problem = "The compositor returned no readable binding table.";
            table.loaded = true;
            return;
        }

        table.rawCount = raw.length;

        // 1 · exclusion — no description, no row.
        var described = [];
        var skipped = 0;
        for (var i = 0; i < raw.length; i++) {
            var b = raw[i];
            if (b === null || typeof b !== "object")
                continue;
            var desc = typeof b.description === "string" ? b.description : "";
            if (desc === "") {
                skipped++;
                continue;
            }
            described.push({
                "modmask": typeof b.modmask === "number" ? b.modmask : 0,
                "key": typeof b.key === "string" ? b.key : "",
                "keycode": typeof b.keycode === "number" ? b.keycode : 0,
                "submap": typeof b.submap === "string" ? b.submap : "",
                "dispatcher": typeof b.dispatcher === "string" ? b.dispatcher : "",
                "arg": typeof b.arg === "string" ? b.arg : "",
                "repeat": b.repeat === true,
                "label": desc
            });
        }
        table.undescribed = skipped;

        // 2 · the range fold. Rows fold when — and ONLY when — the
        // dispatcher is identical, the modmask is identical, the keys
        // form a contiguous digit run, and the descriptions differ solely
        // by that trailing integer. Mechanical, reversible, and it hides
        // nothing: both numbers are printed in the footer so the fold is
        // auditable at a glance. Directional families (Focus left/down/
        // up/right) do NOT fold — their labels differ by a word, not an
        // index, and four verbs are four things to learn.
        var globals = [];
        var modes = [];
        var submapName = "";
        var unmappedCount = 0;
        var prev = null;

        for (var j = 0; j < described.length; j++) {
            var r = described[j];
            var m = /^(.*?) (\d+)$/.exec(r.label);
            var isDigit = /^\d$/.test(r.key);

            if (m !== null && isDigit && prev !== null && prev.foldBase === m[1]
                    && prev.modmask === r.modmask && prev.dispatcher === r.dispatcher
                    && prev.submap === r.submap
                    && Number(r.key) === prev.foldLast + 1) {
                prev.foldLast = Number(r.key);
                prev.keyText = prev.foldFirst + "…" + prev.foldLast;
                prev.label = prev.foldBase + " " + prev.foldFirst + "…" + prev.foldLast;
                prev.folded = prev.foldLast - prev.foldFirst + 1;
                prev.chord = table.chordText(prev);
                continue;
            }

            var section = table.sectionFor(r.dispatcher, r.arg, r.label);
            if (section === "OTHER")
                unmappedCount++;

            var row = {
                "modmask": r.modmask,
                "key": r.key,
                "keyText": table.keyLabel(r.key, r.keycode),
                "submap": r.submap,
                "dispatcher": r.dispatcher,
                "arg": r.arg,
                "repeat": r.repeat,
                "label": r.label,
                "section": section,
                "folded": 1,
                // A submap ENTRY bind, which the bounded mode block needs
                // in order to say which chord opens it. Under Lua the
                // dispatcher is `__lua`, so the shipped surface drew a
                // "MODE · RESIZE" block whose entry row (PUNAR+R) carried
                // no Mode tag at all. The description is the other half of
                // the stable contract and punar-binds.lua writes it in one
                // shape: "Enter <name> mode".
                "isMode": (r.dispatcher === "submap" && r.arg !== "reset")
                    || (r.submap === "" && /^Enter .+ mode$/.test(r.label)),
                "foldBase": "",
                "foldFirst": 0,
                "foldLast": 0,
                "chord": ""
            };
            if (m !== null && isDigit) {
                row.foldBase = m[1];
                row.foldFirst = Number(r.key);
                row.foldLast = Number(r.key);
            }
            row.chord = table.chordText(row);

            if (row.submap !== "") {
                if (submapName === "")
                    submapName = row.submap;
                modes.push(row);
            } else {
                globals.push(row);
            }
            prev = row;
        }

        table.rows = globals;
        table.modeRows = modes;
        table.modeName = submapName;
        table.unmapped = unmappedCount;
        table.problem = "";
        table.loaded = true;
    }

    // ---- the one query per session -----------------------------------

    function ensure(): void {
        if (table.loaded || table.loading)
            return;
        table.loading = true;
        binds.running = true;
    }

    // Drop the cache. The next open re-queries — which is the whole of
    // the invalidation policy.
    function invalidate(): void {
        table.loaded = false;
        table.problem = "";
        table.resetEmpty();
    }

    Process {
        id: binds

        // `hyprctl` reads HYPRLAND_INSTANCE_SIGNATURE from the
        // environment the shell was started in by Hyprland's exec-once.
        command: ["hyprctl", "binds", "-j"]

        stdout: StdioCollector {
            id: out

            onStreamFinished: {
                table.loading = false;
                table.parse(out.text);
            }
        }

        // The process ending without a parsed table means hyprctl is not
        // there, or answered nothing. Named plainly rather than dressed
        // up: this surface is a reference, and a reference that invents
        // rows is worse than one that admits it has none.
        onRunningChanged: {
            if (binds.running)
                return;
            table.loading = false;
            if (table.loaded)
                return;
            table.resetEmpty();
            table.problem = "hyprctl could not be reached — no compositor binding table.";
            table.loaded = true;
        }
    }

    // The single invalidation trigger. Nothing here polls: socket2 is a
    // stream the shell already consumes.
    Connections {
        target: Hyprland

        function onRawEvent(event) {
            if (event.name === "configreloaded")
                table.invalidate();
        }
    }
}
