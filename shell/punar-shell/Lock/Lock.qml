pragma ComponentBehavior: Bound
// Lock — the session lock. Plate D-002's grammar, D-012 Sect III's surface,
// and a REAL lock underneath both.
//
// ── IT ACTUALLY LOCKS ────────────────────────────────────────────────────
// This is not a full-screen overlay pretending to be a lock. It drives the
// Wayland `ext-session-lock-v1` protocol through Quickshell 0.3.0's
// `WlSessionLock` (verified present in the pinned snapshot: `WlSessionLock`
// and `WlSessionLockSurface` are exported by
// /usr/lib/qt6/qml/Quickshell/Wayland/quickshell-wayland.qmltypes in
// quickshell 0.3.0-3). The compositor — not the shell — hides every other
// surface, redirects all input to the lock surfaces, and refuses to unlock
// until the client says so. If this process dies while locked, a conforming
// compositor keeps the session locked rather than exposing the desktop.
//
// `WlSessionLock.secure` is the compositor's own acknowledgement that the
// lock took effect on every output; the surface prints its absence rather
// than assuming success (spec §1.22).
//
// ── AUTHENTICATION IS PAM, NOT A COMPARISON ──────────────────────────────
// Unlocking runs a real PAM conversation through `Quickshell.Services.Pam`
// (`PamContext`, also verified present in the pinned snapshot). The shell
// never reads a hash, never compares a string, and holds the typed
// passphrase only for the moments between Enter and `respond()` — see
// `pending` below, which is cleared on every terminal outcome.
//
// PAM stack: `punar-lock` when the image installs `/etc/pam.d/punar-lock`,
// otherwise `login`, which Arch's `pam` package always ships. The probe is
// a FileView, so the day the image workstream drops that file in, this
// picks it up with no code change. `pam_unix` authenticates an unprivileged
// process through the setuid `unix_chkpwd` helper, so the shell needs no
// privilege of its own.
//
// ── THERE IS NO IPC UNLOCK, DELIBERATELY ─────────────────────────────────
// The IpcHandler below exposes `lock` and `state` and nothing else. An
// `unlock` verb would make the session's own IPC socket a complete bypass
// of the passphrase — the lock would be theatre. Locking is the only thing
// another process may ask for; unlocking is the human's, through PAM.
//
// ── WIRING (owned by the integrator, not by this file) ───────────────────
//   shell.qml:            Lock { }
//   punar-binds.conf:     bindd = $mod, escape, Lock session, exec, $lock
//   hyprland.conf:        $lock = qs -p /usr/share/punar/shell ipc call lock lock
// The chord is PUNAR+Escape, NOT the PUNAR+SHIFT+L this file first
// recommended: all three L chords are load-bearing in the §13.3
// directional grammar (focus-right / move-right / move-into-group-right)
// and Hyprland fires both binds when two share a chord. Escape is free at
// the top level and carries its own meaning — it is the key that leaves.
// The shortcut surface prints whatever the config actually holds, so this
// cannot drift back into a lie.
// Nothing here assumes that wiring exists; without it the surface is simply
// never raised.
//
// ── BUDGET ───────────────────────────────────────────────────────────────
// One timer, and it runs ONLY while the screen is locked: a one-shot that
// re-arms itself on the next minute boundary so the clock is correct
// without a 1 Hz tick. Unlocked, this file costs one idle FileView watch on
// two small files and nothing else (PERFORMANCE_BUDGETS.md; spec §6.3).

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Services.Pam

Scope {
    id: root

    // Drives the protocol. Never set from IPC except through lock().
    property bool locked: false

    // A PAM conversation is in flight.
    property bool busy: false

    // Failed attempts in this lock session. The third one earns the red
    // voice (Plate D-002's own words for the state it did not draw).
    property int attempts: 0
    property string failure: ""

    // The typed passphrase, alive only between Enter and PAM's prompt.
    // Cleared on success, failure, error, and every lock.
    property string pending: ""

    property date now: new Date()

    // ---- identity ---------------------------------------------------------

    readonly property string accountName: {
        var u = Quickshell.env("USER");
        if (u)
            return String(u);
        var l = Quickshell.env("LOGNAME");
        return l ? String(l) : "";
    }

    // A display name is the account name with its first letter raised —
    // the shell does not read /etc/passwd's GECOS field for this, because
    // one capitalised word is enough and a parser is not.
    readonly property string displayName: {
        var n = root.accountName;
        if (n === "")
            return "User";
        return n.charAt(0).toUpperCase() + n.slice(1);
    }

    property string hostName: ""

    FileView {
        id: hostFile
        path: "/etc/hostname"
        onLoaded: root.hostName = hostFile.text().trim().split("\n")[0]
        onLoadFailed: root.hostName = ""
    }

    // ---- PAM stack selection ---------------------------------------------

    property string pamConfig: "login"

    FileView {
        id: pamProbe
        path: "/etc/pam.d/punar-lock"
        onLoaded: root.pamConfig = "punar-lock"
        onLoadFailed: root.pamConfig = "login"
    }

    // ---- clock ------------------------------------------------------------

    readonly property var dayNames: ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
    readonly property var monthNames: ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]

    function pad2(n: int): string {
        return (n < 10 ? "0" : "") + n;
    }

    readonly property string timeText: root.pad2(root.now.getHours()) + ":" + root.pad2(root.now.getMinutes())
    readonly property string dateText: root.dayNames[root.now.getDay()] + " · " + root.now.getDate() + " " + root.monthNames[root.now.getMonth()] + " " + root.now.getFullYear()
    readonly property string monthYear: root.pad2(root.now.getMonth() + 1) + " · " + root.now.getFullYear()

    // Re-arms on the next minute boundary instead of ticking every second:
    // a minute-resolution clock has no business waking the CPU 60 times a
    // minute, and this one only exists while the surface is on screen.
    Timer {
        id: clockTimer
        repeat: false
        interval: 60000
        onTriggered: root.tickClock()
    }

    function tickClock(): void {
        root.now = new Date();
        if (!root.locked) {
            clockTimer.stop();
            return;
        }
        clockTimer.interval = Math.max(1000, 60000 - (root.now.getSeconds() * 1000 + root.now.getMilliseconds()));
        clockTimer.restart();
    }

    onLockedChanged: {
        if (root.locked)
            root.tickClock();
        else
            clockTimer.stop();
    }

    // ---- entry points -----------------------------------------------------

    function lock(): void {
        if (root.locked)
            return;
        root.attempts = 0;
        root.failure = "";
        root.pending = "";
        root.busy = false;
        root.now = new Date();
        root.locked = true;
    }

    // NOTE: no `unlock` verb. See the header — an IPC unlock is a bypass.
    IpcHandler {
        target: "lock"

        function lock(): void {
            root.lock();
        }
        function state(): string {
            if (!root.locked)
                return "unlocked";
            return sessionLock.secure ? "locked" : "locking";
        }
    }

    // ---- authentication ---------------------------------------------------

    function submit(passphrase: string): void {
        if (root.busy || passphrase === "")
            return;
        root.pending = passphrase;
        root.failure = "";
        root.busy = true;
        if (!pam.start()) {
            root.busy = false;
            root.pending = "";
            root.failure = "Authentication is unavailable on this device";
        }
    }

    PamContext {
        id: pam

        config: root.pamConfig
        user: root.accountName

        // PAM asks; the shell answers with what the human typed, once.
        onPamMessage: {
            if (pam.responseRequired)
                pam.respond(root.pending);
        }

        onCompleted: function (result) {
            root.busy = false;
            root.pending = "";
            if (result === PamResult.Success) {
                root.attempts = 0;
                root.failure = "";
                // Setting this false is what releases the protocol lock;
                // the compositor brings the session back exactly as it was.
                root.locked = false;
                return;
            }
            root.attempts = root.attempts + 1;
            root.failure = result === PamResult.MaxTries ? "Too many attempts · wait and try again" : "Try again";
        }

        onError: function (error) {
            root.busy = false;
            root.pending = "";
            root.attempts = root.attempts + 1;
            console.warn("punar-shell: PAM error on config", root.pamConfig, error);
            root.failure = "Authentication is unavailable on this device";
        }
    }

    // ---- the protocol -----------------------------------------------------

    WlSessionLock {
        id: sessionLock

        locked: root.locked

        LockSurface {
            displayName: root.displayName
            accountName: root.accountName
            hostName: root.hostName
            timeText: root.timeText
            dateText: root.dateText
            monthYear: root.monthYear
            attempts: root.attempts
            busy: root.busy
            failure: root.failure
            secure: sessionLock.secure

            onSubmitted: function (passphrase) {
                root.submit(passphrase);
            }
        }
    }
}
