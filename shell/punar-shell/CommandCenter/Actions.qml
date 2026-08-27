pragma ComponentBehavior: Bound
// Actions — the command center's ACTION TAXONOMY, as data.
//
// D-003's law, restated so it can be checked: *intent goes in, a typed
// capability comes out*, and "the command center never generates a shell
// string". This file is where that law is kept. Every row the overlay can
// show is one of six kinds, each with exactly one execution mechanism:
//
//   KIND        WHAT IT IS                  HOW IT RUNS
//   ─────────── ─────────────────────────── ────────────────────────────────
//   app         an installed .desktop entry DesktopEntry.execute() — argv
//                                           parsed by Quickshell from Exec
//   project     a named project workspace   Hyprland `workspace <id>` and
//               (spec §14.1/§14.3, §75.3)   `renameworkspace <id> <name>`
//                                           dispatchers — typed compositor
//                                           verbs, not a command line
//   surface     a first-party shell surface Quickshell IPC call on the
//               addressed by IPC TARGET      surface's IpcHandler target
//   layout      a §13.5 layout preset       /usr/lib/punar/punar-layout.sh
//                                           <preset> (fixed argv, one
//                                           hyprctl --batch — M2 §4)
//   wallpaper   an installed desktop field  WallpaperState.setWallpaper(id)
//                                           (finite catalog, atomic pointer)
//   explain     a §40 policy question       punarctl --json policy explain
//                                           <path>, rendered inline
//
// There is no seventh kind and there is deliberately no generic "run this"
// kind: `ipc.md` §8's permanent non-goal ("no generic execution method of
// any kind") is the same promise one layer up. Every list below is DATA —
// adding a surface is one object literal, never a new branch in activate().
//
// HONESTY (spec §1.22, DESIGN_LANGUAGE §7): a surface row is only solid if
// its IPC target is actually registered in THIS shell. `availableTargets`
// is filled once per session from `qs ipc show` (see CommandCenter.qml);
// until it answers, nothing is claimed either way — see targetState().
//
// Budget: pure data and pure functions. No timers, no polling, no file
// watches of its own (PERFORMANCE_BUDGETS.md §5).

import QtQuick
import Quickshell
import Quickshell.Hyprland
import "../Services"

QtObject {
    id: root

    // ---- surface routing (wiring is data, not branches) ------------------
    //
    // `target` is the surface's `IpcHandler.target` name — the SAME string
    // Hyprland's binds use through their $variables (hyprland.conf), so the
    // command center and the keyboard reach a surface by one identifier.
    // `open` is the function every punar-shell surface exposes.
    readonly property var surfaces: [
        {
            "target": "systemcontrol",
            "name": "System Control",
            "glyph": "SY",
            "chord": "Super S",
            "milestone": "Milestone 13",
            "keywords": "settings preferences system control security compliance encryption firewall organization enrollment policies device"
        },
        {
            "target": "notifications",
            "name": "Notification center",
            "glyph": "NO",
            "chord": "Super Shift N",
            "milestone": "Milestone 13",
            "keywords": "notification notifications alerts messages history center do not disturb"
        },
        {
            "target": "shortcuts",
            "name": "Keyboard shortcuts",
            "glyph": "KB",
            "chord": "Super /",
            "milestone": "Milestone 13",
            "keywords": "keyboard shortcuts keys bindings chords help cheatsheet"
        },
        {
            "target": "aipanel",
            "name": "AI on this device",
            "glyph": "AI",
            "chord": "Super A",
            "milestone": "Milestone 7",
            "keywords": "ai agents claude assistant authority ledger privacy sessions"
        },
        {
            "target": "overview",
            "name": "Project overview",
            "glyph": "OV",
            "chord": "Super Tab",
            "milestone": "Milestone 2",
            "keywords": "overview workspaces projects windows switcher"
        }
    ]

    // ---- layout presets (spec §13.5) -------------------------------------
    //
    // punar-binds.conf names the command center as a consumer of this
    // script in so many words: "the compositor binds (SUPER+comma/period →
    // prev/next), the command center (exec, by preset name)". Five presets;
    // `grid` is not shipped (no native grid algorithm in Hyprland 0.56.2)
    // and therefore is not offered.
    readonly property string layoutScript: "/usr/lib/punar/punar-layout.sh"
    readonly property var layouts: [
        {
            "preset": "balanced",
            "name": "Balanced layout",
            "note": "Even splits"
        },
        {
            "preset": "columns",
            "name": "Columns layout",
            "note": "Scrolling columns"
        },
        {
            "preset": "rows",
            "name": "Rows layout",
            "note": "Hero row on top"
        },
        {
            "preset": "focus",
            "name": "Focus layout",
            "note": "One large plus stack"
        },
        {
            "preset": "stack",
            "name": "Stack layout",
            "note": "One window at a time"
        }
    ]

    // ---- policy paths (spec §40 explain) ---------------------------------
    //
    // Seeded with the capability ids punard actually registers today
    // (crates/punard/src/backends/), and REPLACED at runtime by the paths
    // `punarctl --json policy effective` reports, so this table can never
    // outlive the daemon's registry. Keywords are what makes a plain
    // question resolve to a typed path.
    readonly property var policySeeds: [
        {
            "path": "security.firewall",
            "keywords": "firewall network ports blocked connection nftables traffic"
        },
        {
            "path": "time.timezone",
            "keywords": "timezone time zone clock region"
        },
        {
            "path": "system.hostname",
            "keywords": "hostname host name device name computer name"
        }
    ]

    // Live paths from punard, newest wins. Empty until the first answer.
    property var livePaths: []

    readonly property var policyPaths: {
        var out = [];
        var seen = ({});
        for (var i = 0; i < root.policySeeds.length; i++) {
            out.push(root.policySeeds[i]);
            seen[root.policySeeds[i].path] = true;
        }
        for (var j = 0; j < root.livePaths.length; j++) {
            var p = String(root.livePaths[j]);
            if (seen[p] === true)
                continue;
            seen[p] = true;
            // A path punard reports but this file has never heard of still
            // gets a keyword set — its own segments — so it is reachable.
            out.push({
                "path": p,
                "keywords": p.split(".").join(" ").toLowerCase()
            });
        }
        return out;
    }

    // ---- surface availability -------------------------------------------

    // IPC targets this shell instance actually registered, from one
    // `qs ipc show` per session. `probed` stays false when the probe could
    // not run at all.
    property var availableTargets: []
    property bool probed: false

    // "shipped" · "absent" · "unknown".
    //
    // `unknown` is not a hedge, it is the honest third answer: before the
    // probe returns (or when it could not run — no `qs` on a dev machine),
    // this shell has no evidence either way, and inventing "absent" would
    // dash a row that may well work. A row in `unknown` renders solid but
    // its meta says the probe did not answer.
    function targetState(target: string): string {
        if (!root.probed)
            return "unknown";
        return root.availableTargets.indexOf(target) !== -1 ? "shipped" : "absent";
    }

    // The shell config path this instance was launched with — the same `-p`
    // every `qs ipc call` client in this repo needs (hyprland.conf's
    // $commandCenter / $overview / $aiPanel variables use the installed
    // path; shellDir is that path at runtime and also works from a checkout).
    readonly property string shellPath: Quickshell.shellDir

    // Open a sibling surface by IPC target name. Fixed argv, never a shell
    // string: `qs -p <shell> ipc call <target> open`.
    function openSurface(target: string): bool {
        try {
            Quickshell.execDetached(["qs", "-p", root.shellPath, "ipc", "call", target, "open"]);
        } catch (e) {
            console.warn("punar-shell: could not reach surface", target, e);
            return false;
        }
        return true;
    }

    function applyLayout(preset: string): bool {
        try {
            Quickshell.execDetached([root.layoutScript, preset]);
        } catch (e) {
            console.warn("punar-shell: layout preset failed", preset, e);
            return false;
        }
        return true;
    }

    // ---- project workspaces (spec §14.1/§14.3; spec §75 step 3) ----------

    // Project workspace names are lowercased identifiers: "Open Atlas"
    // opens the workspace named `atlas`. The row still shows the reader's
    // own words; the row's meta prints the identifier that will be used, so
    // what happens is visible before Enter (D-003 register 03).
    function normalizeProject(raw: string): string {
        var name = String(raw).trim().replace(/\s+/g, " ").toLowerCase();
        if (name === "")
            return "";
        return WorkspaceState.validName(name) ? name : "";
    }

    // Strip a leading intent verb: "open atlas" / "switch to atlas" /
    // "go to atlas" / "project atlas" all mean the workspace `atlas`.
    // This is the whole of "natural language resolves to a typed action":
    // the words select a verb and an argument, and the verb is one of the
    // six kinds above — never a command line.
    function projectArgument(query: string): string {
        var q = String(query).trim();
        var m = q.match(/^(?:open|go\s+to|goto|switch\s+to|switch|project|workspace)\s+(.+)$/i);
        return m ? m[1] : q;
    }

    function projectVerbUsed(query: string): bool {
        return /^(?:open|go\s+to|goto|switch\s+to|switch|project|workspace)\s+/i.test(String(query).trim());
    }

    // Every project workspace this device knows: the live ones the
    // compositor reports, plus the stored ones from workspaces.json that
    // have not been recreated this session (WorkspaceState.pendingNames —
    // the M2 contract, milestone-2.md §6).
    function knownProjects(): var {
        var out = [];
        var seen = ({});
        var wss = Hyprland.workspaces.values;
        for (var i = 0; i < wss.length; i++) {
            var ws = wss[i];
            if (ws.id < 1 || !WorkspaceState.isNamed(ws))
                continue;
            var name = String(ws.name).toLowerCase();
            if (seen[name] === true)
                continue;
            seen[name] = true;
            out.push({
                "name": name,
                "id": ws.id,
                "live": true
            });
        }
        var pending = WorkspaceState.pendingNames;
        for (var id in pending) {
            var stored = String(pending[id]).toLowerCase();
            if (seen[stored] === true)
                continue;
            seen[stored] = true;
            out.push({
                "name": stored,
                "id": Number(id),
                "live": false
            });
        }
        out.sort(function (a, b) {
            return a.id - b.id;
        });
        return out;
    }

    function findProject(name: string): var {
        var known = root.knownProjects();
        for (var i = 0; i < known.length; i++) {
            if (known[i].name === name)
                return known[i];
        }
        return null;
    }

    // Lowest workspace id not taken by a live workspace or a stored name.
    // Stays inside 1..9 while it can, because those are the ids SUPER+1..9
    // reach directly (punar-binds.conf).
    function freeWorkspaceId(): int {
        var taken = ({});
        var wss = Hyprland.workspaces.values;
        for (var i = 0; i < wss.length; i++) {
            if (wss[i].id >= 1)
                taken[wss[i].id] = true;
        }
        var pending = WorkspaceState.pendingNames;
        for (var id in pending)
            taken[Number(id)] = true;
        for (var n = 1; n <= 99; n++) {
            if (taken[n] !== true)
                return n;
        }
        return 1;
    }

    // The id `openProject(name)` would use — printed in the row's meta so
    // the destination is visible before Enter.
    function plannedWorkspaceId(name: string): int {
        var found = root.findProject(name);
        return found !== null ? found.id : root.freeWorkspaceId();
    }

    // Switch to, or create, the named project workspace.
    //
    // Two typed compositor dispatchers and nothing else. The rename is what
    // makes the workspace a PROJECT rather than a number, and it is also
    // what persists it: Hyprland emits `renameworkspace` on socket2,
    // WorkspaceState follows that event and writes
    // ~/.local/state/punar/workspaces.json (milestone-2.md §6 — the shell
    // is the only writer, debounced, never on a timer). This satisfies
    // spec §75 step 3 exactly as written: type `Open Atlas`, get a named
    // Atlas project workspace.
    function openProject(name: string): int {
        var target = root.normalizeProject(name);
        if (target === "")
            return -1;
        var found = root.findProject(target);
        var id = found !== null ? found.id : root.freeWorkspaceId();
        Hyprland.dispatch("workspace " + id);
        // A live workspace already carrying the name needs no rename; a
        // stored-but-not-yet-created one does (WorkspaceState also applies
        // it on createworkspacev2 — doing it here makes the verb
        // deterministic rather than dependent on event ordering).
        if (found === null || !found.live)
            Hyprland.dispatch("renameworkspace " + id + " " + target);
        return id;
    }

    // ---- policy questions (spec §40) -------------------------------------

    // A query is a QUESTION when it is shaped like one. Questions get the
    // explain surface; everything else gets rows.
    function isQuestion(query: string): bool {
        var q = String(query).trim().toLowerCase();
        if (q === "")
            return false;
        if (q.indexOf("?") !== -1)
            return true;
        return /^(why|what|who|when|how|can|could|is|are|does|do|am i|may i)\b/.test(q);
    }

    // Resolve a question to ONE typed policy path, or "" when nothing on
    // this device answers it. Scored so "why is my firewall blocking this?"
    // reaches `security.firewall` and not the first row in the table.
    function questionPath(query: string): string {
        var q = String(query).toLowerCase();
        var best = "";
        var bestScore = 0;
        var table = root.policyPaths;
        for (var i = 0; i < table.length; i++) {
            var row = table[i];
            var score = 0;
            if (q.indexOf(String(row.path).toLowerCase()) !== -1)
                score += 100;
            var words = String(row.keywords).split(" ");
            for (var j = 0; j < words.length; j++) {
                if (words[j].length >= 3 && q.indexOf(words[j]) !== -1)
                    score += 10;
            }
            if (score > bestScore) {
                bestScore = score;
                best = String(row.path);
            }
        }
        return best;
    }
}
