pragma Singleton
// HyprlandActions — the shell's one path to workspace and window dispatchers.
//
// Every call runs the `punarctl` verb a person would type: `punarctl workspace
// focus|rename` and `punarctl window focus --class`. punarctl builds the
// Hyprland 0.56 Lua dispatcher expression, quotes every value as a Lua string
// literal and checks workspace names against the one grammar, so the overview,
// the command center, the workspace store and a terminal all do each thing the
// same way (terminal parity: docs/api/ipc.md section 7).
//
// Calls run one at a time, in the order they were made: opening a project is
// "focus, then rename", and a rename that raced its focus would name the
// wrong workspace. A refusal is logged and kept in `lastError`, never dropped.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    // The last refusal, verbatim from punarctl; empty after a success.
    property string lastError: ""
    property var queue: []

    function run(argv: var): void {
        var next = root.queue.slice();
        next.push(argv);
        root.queue = next;
        root.pump();
    }

    function pump(): void {
        if (runner.running || root.queue.length === 0)
            return;
        var next = root.queue.slice();
        var argv = next.shift();
        root.queue = next;
        runner.command = argv;
        try {
            runner.running = true;
        } catch (e) {
            root.lastError = "punarctl could not be started: " + e;
            console.warn("punar-shell:", root.lastError);
            Qt.callLater(root.pump);
        }
    }

    Process {
        id: runner

        stderr: StdioCollector {
            id: runnerErr
            waitForEnd: true
        }

        // Connected, not declared: Quickshell does not register the exit
        // status type, so a declarative onExited cannot be compiled.
        Component.onCompleted: runner.exited.connect(function (exitCode) {
            if (exitCode === 0) {
                root.lastError = "";
            } else {
                root.lastError = String(runnerErr.text).trim();
                console.warn("punar-shell:", runner.command.join(" "), "was refused:", root.lastError);
            }
            Qt.callLater(root.pump);
        })
    }

    function focusWorkspace(selector: var): void {
        root.run(["punarctl", "workspace", "focus", String(selector)]);
    }

    // Raise an application's window by its class; punarctl escapes the class
    // into an exact-match selector.
    function focusWindowClass(appClass: string): void {
        root.run(["punarctl", "window", "focus", "--class", appClass]);
    }

    // Raise one exact window by its address (the Alt+Tab switcher); punarctl
    // checks the address is 0x-hex before it builds the selector.
    function focusWindowAddress(address: string): void {
        root.run(["punarctl", "window", "focus", "--address", address]);
    }

    // A layout preset: `punarctl layout`, which runs punar-layout.sh, the
    // presets' one implementation, and refuses first when no compositor is
    // reachable.
    function applyLayout(preset: string): void {
        root.run(["punarctl", "layout", preset, "--workspace", "active"]);
    }

    // An empty name clears the workspace's name.
    function renameWorkspace(selector: var, name: string): void {
        var argv = ["punarctl", "workspace", "rename", String(selector)];
        if (name !== "")
            argv.push(name);
        root.run(argv);
    }
}
