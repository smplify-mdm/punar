// PasswordRun — run one punarctl verb that needs the person's password, and
// hand the password to it over a private socket, never a pipe (F0-S4;
// docs/api/ipc.md §23.5).
//
// WHY NOT STDIN. A pipe can be reopened by any program running as the same
// person, through /proc/<pid>/fd, and read before punarctl reads it; a socket
// reopened that way gives ENXIO. Quickshell's Process can only hand a child a
// stdin pipe, so the direction is reversed: the verb runs with
// `--password-from-parent`, opens a listening socket in a private directory,
// prints `password-socket <path>` as its first line, and accepts exactly one
// connection — from this process, its parent, which the kernel attests
// (SO_PEERCRED). This component connects, writes the one line, and forgets it.
//
// The command is the one a terminal runs; only the flag differs, so the
// surface and the CLI stay one capability layer (terminal parity).
//
// The secret lives in `secret` from start() until it has been written, and is
// cleared on every path out: written, refused, failed to start, exited.

import QtQuick
import Quickshell
import Quickshell.Io

Scope {
    id: run

    /// Once per start(): how punarctl exited, and its own words on stderr.
    signal finished(int exitCode, string said)

    readonly property bool running: proc.running

    // Held only until it is written to the socket punarctl opened.
    property string secret: ""

    /// Start `argv` — which must carry `--password-from-parent` — and give it
    /// `password` when it asks. False when nothing could be started, in which
    /// case the secret is already gone.
    function start(argv: list<string>, password: string): bool {
        if (proc.running)
            return false;
        run.secret = password;
        handoff.path = "";
        proc.command = argv;
        try {
            proc.running = true;
        } catch (e) {
            run.secret = "";
            return false;
        }
        return true;
    }

    Process {
        id: proc

        stdout: SplitParser {
            onRead: function (line) {
                var text = String(line);
                var prefix = "password-socket ";
                // Only the first announcement is answered; anything else on
                // stdout is the verb's own output.
                if (handoff.path !== "" || text.indexOf(prefix) !== 0)
                    return;
                handoff.path = text.substring(prefix.length);
                handoff.connected = true;
            }
        }
        stderr: StdioCollector {
            id: errText
            waitForEnd: true
        }

        // Connected, not declared: see Probe in SystemControl/ControlData.qml.
        Component.onCompleted: proc.exited.connect(function (exitCode) {
            run.secret = "";
            handoff.connected = false;
            handoff.path = "";
            run.finished(exitCode, String(errText.text).trim());
        })
    }

    Socket {
        id: handoff

        onConnectedChanged: {
            if (!handoff.connected)
                return;
            handoff.write(run.secret + "\n");
            handoff.flush();
            run.secret = "";
            handoff.connected = false;
        }
        // Quickshell exposes the C++ QLocalSocket error enum in this signal,
        // but does not register that enum as a QML type for qmllint. The
        // handler deliberately ignores the unrepresentable argument.
        // qmllint disable signal-handler-parameters
        onError: run.secret = ""
        // qmllint enable signal-handler-parameters
    }
}
