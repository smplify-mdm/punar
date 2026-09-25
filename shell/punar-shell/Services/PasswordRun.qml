// PasswordRun — run one punarctl verb that needs the person's password. The
// password goes from this surface to punar-authd directly, over punar-authd's
// own socket; punarctl receives only punar-authd's answer (F0-S4, F0 review;
// docs/api/ipc.md §23.5).
//
// WHY THE PASSWORD NEVER GOES TO PUNARCTL. A pipe can be reopened by any
// program running as the same person, through /proc/<pid>/fd, and read before
// punarctl reads it; a socket reopened that way gives ENXIO — so the old path
// used a private socket punarctl opened and announced on its stdout. But
// punarctl's stdout is itself a pipe this process reads, and another program
// of the same person can open its write end and announce a socket of its own
// first; and a socket name in the person's own directory can be swapped. So
// the password now goes only where no program of this person can stand in:
// punar-authd's root-owned socket, which this surface connects to itself.
//
// WHAT PUNARCTL GETS INSTEAD. punar-authd mints a ticket bound to the one call
// the person typed their password for (`action`, the IPC method) and to the
// one process that may spend it — the punarctl this component started, named
// by pid (`for_pid`); punard refuses it from any other process or for any
// other call. That ticket (`ok <ticket>`), or `denied`, or `unavailable`, is
// relayed to punarctl over the private socket it announces with
// `ticket-socket <path>`. If another program intercepts the relay, what it
// holds is a ticket only this punarctl could spend, and punarctl then fails
// closed with nothing changed.
//
// ORDER. punarctl checks that the person may make the change at all before it
// announces the socket; only then does this component send the password. A
// person without the device-administrator role never has it checked against
// the lock screen's shared faillock tally.
//
// The command is the one a terminal runs; only the flag differs, so the
// surface and the CLI stay one capability layer (terminal parity). It is
// started by its absolute path: a `punarctl` earlier on PATH (a person's
// ~/.local/bin) would be the process a ticket is bound to.
//
// The secret lives in `secret` from start() until it has been written to
// punar-authd, and is cleared on every path out: written, refused, failed to
// start, exited.

import QtQuick
import Quickshell
import Quickshell.Io

Scope {
    id: run

    /// Once per start(): how punarctl exited, and its own words on stderr.
    signal finished(int exitCode, string said)

    readonly property bool running: proc.running

    /// punarctl's own standard output: every line but the `ticket-socket`
    /// announcement (a `--json` verb's answer is its last line).
    property string output: ""

    /// punar-authd's socket, the one place the password is sent.
    readonly property string authdSocket: "/run/punar-authd/auth.sock"

    // Held only until it is written to punar-authd.
    property string secret: ""
    // The IPC method the ticket is for (`policy.set`, `approvals.resolve`).
    property string action: ""
    // Where punarctl waits for the answer, once it has said so.
    property string rendezvous: ""
    // The answer to relay (`ok <ticket>`, `denied`, `unavailable`), held
    // only until it is written to punarctl.
    property string answer: ""
    // Whether punarctl has been given its answer for this run.
    property bool relayed: false

    /// Start `argv` — /usr/bin/punarctl with `--ticket-from-parent` — for the
    /// IPC method `action`, and confirm it with `password` if punarctl asks.
    /// False when nothing could be started, in which case the secret is
    /// already gone.
    function start(argv: list<string>, password: string, action: string): bool {
        if (proc.running)
            return false;
        run.secret = password;
        run.action = action;
        run.rendezvous = "";
        run.answer = "";
        run.relayed = false;
        run.output = "";
        proc.command = argv;
        try {
            proc.running = true;
        } catch (e) {
            run.secret = "";
            return false;
        }
        return true;
    }

    /// Give punarctl punar-authd's answer, once.
    function relay(word: string): void {
        run.secret = "";
        if (run.relayed || run.rendezvous === "")
            return;
        run.relayed = true;
        run.answer = word;
        handoff.path = run.rendezvous;
        handoff.connected = true;
    }

    /// punar-authd's JSON line, as the one word punarctl reads.
    function answerOf(line: string): string {
        try {
            var said = JSON.parse(line);
            if (said !== null && typeof said === "object") {
                if (said.verdict === "ok" && typeof said.ticket === "string"
                        && /^[0-9a-f]{64}$/.test(said.ticket))
                    return "ok " + said.ticket;
                if (said.verdict === "denied")
                    return "denied";
            }
        } catch (e) {}
        return "unavailable";
    }

    Process {
        id: proc

        stdout: SplitParser {
            onRead: function (line) {
                var text = String(line);
                var prefix = "ticket-socket ";
                // Only the first announcement is answered; anything else on
                // stdout is the verb's own output.
                if (run.rendezvous !== "" || text.indexOf(prefix) !== 0) {
                    run.output += text + "\n";
                    return;
                }
                run.rendezvous = text.substring(prefix.length);
                var pid = proc.processId;
                if (run.secret === "" || run.action === "" || pid === null || pid === undefined) {
                    run.relay("unavailable");
                    return;
                }
                authd.path = run.authdSocket;
                authd.connected = true;
            }
        }
        stderr: StdioCollector {
            id: errText
            waitForEnd: true
        }

        // Connected, not declared: see Probe in SystemControl/ControlData.qml.
        Component.onCompleted: proc.exited.connect(function (exitCode) {
            run.secret = "";
            run.answer = "";
            authd.connected = false;
            handoff.connected = false;
            run.rendezvous = "";
            run.finished(exitCode, String(errText.text).trim());
        })
    }

    // punar-authd: one line out (the request), one line back (the verdict).
    Socket {
        id: authd

        parser: SplitParser {
            onRead: function (line) {
                authd.connected = false;
                run.relay(run.answerOf(String(line)));
            }
        }

        onConnectedChanged: {
            if (!authd.connected) {
                // Closed before it answered: the device could not check.
                // Deferred one turn so an answer that arrived with the close
                // is read first.
                Qt.callLater(function () {
                    run.relay("unavailable");
                });
                return;
            }
            authd.write(JSON.stringify({
                v: 1,
                password: run.secret,
                purpose: "admin",
                action: run.action,
                for_pid: Number(proc.processId)
            }) + "\n");
            authd.flush();
            run.secret = "";
        }
        // Quickshell exposes the C++ QLocalSocket error enum in this signal,
        // but does not register that enum as a QML type for qmllint. The
        // handler deliberately ignores the unrepresentable argument.
        // qmllint disable signal-handler-parameters
        onError: run.relay("unavailable")
        // qmllint enable signal-handler-parameters
    }

    // punarctl's private socket: the answer, then close.
    Socket {
        id: handoff

        onConnectedChanged: {
            if (!handoff.connected)
                return;
            handoff.write(run.answer + "\n");
            handoff.flush();
            run.answer = "";
            handoff.connected = false;
        }
        // qmllint disable signal-handler-parameters
        onError: run.answer = ""
        // qmllint enable signal-handler-parameters
    }
}
