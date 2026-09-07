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
// ── AUTHENTICATION IS PAM, RUN BY A PRIVILEGED VERIFIER ──────────────────
// Unlocking still runs a real PAM conversation against the `punar-lock`
// stack — the shell never reads a hash and never compares a string — but it
// no longer runs that conversation itself. It relays the typed passphrase
// to `punar-authd` over a socket and reads back one of three words.
//
// IT CANNOT RUN PAM ITSELF, and this file used to claim the opposite. The
// old text here said `pam_unix` authenticates an unprivileged process
// through the setuid `unix_chkpwd` helper "so the shell needs no privilege
// of its own". That is false for the accounts Punar actually creates:
// systemd serves a userdb record's privileged section, where the hash
// lives, only to a uid-0 caller. An in-process PamContext therefore
// rejected every correct password on a real machine while greetd — which
// is root — accepted the same one, and the lock screen could not be opened
// by anyone. Both substrates refuse, for different reasons; the
// measurements are in crates/punar-auth/src/lib.rs.
//
// The stack is no longer selected here either. punar-authd names
// `punar-lock` and nothing else, so there is no probe and no fallback to
// `login` — a fallback that silently changed which stack authenticated a
// screen unlock was a way to be wrong quietly.
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

    // ---- the lockout policy, read rather than assumed ---------------------
    //
    // `etc/pam.d/punar-lock` includes pam_faillock, so after enough failures
    // the account is locked and the CORRECT passphrase is refused too. PAM
    // reports that refusal as PAM_AUTH_ERR — the same code as a wrong
    // passphrase — so this surface cannot tell the two apart from the result
    // alone and used to print "Try again" for both. A person who has just been
    // locked out for minutes is then told, in the same words as a typo, that
    // their passphrase is wrong; on a LUKS machine that is how someone talks
    // themselves into wiping a working disk.
    //
    // The numbers come from the shipped policy file rather than being repeated
    // here, so /etc/security/faillock.conf and the sentence on the lock screen
    // cannot drift apart. A file that is missing or unparsable yields 0, which
    // this surface reads as "policy unknown" and then says nothing about
    // lockouts at all — an invented threshold would be worse than silence.
    property int denyAfter: 0
    property int unlockSeconds: 0

    readonly property string lockoutPath: "/etc/security/faillock.conf"

    FileView {
        id: faillockPolicy
        path: root.lockoutPath
        printErrors: false
        onLoaded: {
            var deny = 0;
            var unlock = 0;
            var lines = String(faillockPolicy.text()).split("\n");
            for (var i = 0; i < lines.length; i++) {
                var line = lines[i].trim();
                if (line === "" || line.charAt(0) === "#")
                    continue;
                var eq = line.indexOf("=");
                if (eq < 0)
                    continue;
                var key = line.substring(0, eq).trim();
                var value = parseInt(line.substring(eq + 1).trim(), 10);
                if (isNaN(value) || value <= 0)
                    continue;
                if (key === "deny")
                    deny = value;
                else if (key === "unlock_time")
                    unlock = value;
            }
            root.denyAfter = deny;
            root.unlockSeconds = unlock;
        }
        onLoadFailed: {
            root.denyAfter = 0;
            root.unlockSeconds = 0;
        }
    }

    // "5 minutes" / "90 seconds" — whole units only; a lock screen does not
    // need a countdown, it needs an order of magnitude the reader can wait out.
    function lockoutWindow(): string {
        if (root.unlockSeconds <= 0)
            return "";
        if (root.unlockSeconds % 60 === 0) {
            var mins = root.unlockSeconds / 60;
            return mins === 1 ? "1 minute" : mins + " minutes";
        }
        return root.unlockSeconds + " seconds";
    }

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


    // ---- the exercise seam, and why it is not a bypass ---------------------
    //
    // The header above refuses an `unlock` verb, and still does: nothing here
    // unlocks anything. `submit` hands a candidate passphrase to the SAME PAM
    // conversation the keyboard uses, so a wrong secret fails exactly as it
    // would at the field, faillock counts it exactly the same, and the session
    // opens only if PAM says yes. It is the keyboard's path, driven by a test.
    //
    // WHY IT NEEDS A GATE ANYWAY. Even without a bypass, a submit verb lets any
    // process that can reach this session's IPC socket guess at machine speed.
    // That process already runs as the session user — it could read the same
    // files — but a locked screen is a promise about someone at the keyboard,
    // and quietly widening it in a shipped image is not this file's decision.
    //
    // So the verb exists ONLY where /usr/lib/punar/lock-exercise.allow does,
    // which is the dev image and nowhere else. check-release-image.sh assertion
    // A15 fails the build if that marker ever appears in a release tree, so the
    // absence is a mechanism rather than a convention.
    //
    // WHY IT EXISTS AT ALL. surfaces-check could only assert that a PAM stack
    // FILE existed — its own comment said "not a lock/unlock round trip:
    // submit() is unreachable over IPC" — so nothing had ever proven that a
    // correct passphrase unlocks a Punar session. The owner found that hole by
    // being unable to unlock a machine whose password was right.
    property bool exerciseAllowed: false

    // The last thing the lock's frosted field reported about itself. Held
    // across an unlock so a check script can read it after the round trip
    // rather than having to interleave with a locked session.
    property string fieldDiag: ""

    FileView {
        id: exerciseProbe
        path: "/usr/lib/punar/lock-exercise.allow"
        printErrors: false
        onLoaded: root.exerciseAllowed = true
        onLoadFailed: root.exerciseAllowed = false
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

        /// Submit a candidate passphrase through the ordinary PAM path.
        /// Returns "refused" on any image without the exercise marker, which is
        /// every release image. Never returns whether the secret was right —
        /// the caller reads `state` afterwards, so this cannot become an oracle
        /// that answers faster than PAM does.
        function submit(passphrase: string): string {
            if (!root.exerciseAllowed)
                return "refused";
            if (!root.locked)
                return "unlocked";
            root.submit(passphrase);
            return "submitted";
        }

        /// What the frosted field resolved the last time this surface was
        /// built: whether the photo branch was taken, the URL, and whether the
        /// Image reached Ready. Dev images only, behind the same marker
        /// `submit` uses, so a release image answers "refused" and A15 keeps
        /// the marker out of one. It reveals a wallpaper filename and a load
        /// status and nothing else — never a secret, never an auth verdict.
        function field(): string {
            if (!root.exerciseAllowed)
                return "refused";
            return root.fieldDiag === "" ? "unreported" : root.fieldDiag;
        }
    }

    // ---- authentication ---------------------------------------------------

    function submit(passphrase: string): void {
        if (root.busy || passphrase === "")
            return;
        root.pending = passphrase;
        root.failure = "";
        root.busy = true;
        // Re-armed on every attempt: onStarted disables stdin after writing, so
        // without this a second try would run the verifier with nothing on its
        // input and be told, correctly, that an empty secret is refused. A lock
        // screen is retried by definition, which is exactly why this matters
        // here and not in the greeter's one-shot account creation.
        verifier.stdinEnabled = true;
        verifier.running = true;
    }

    /// The verifier, and why the shell no longer runs PAM itself.
    ///
    /// It cannot. systemd serves a userdb record's privileged section — where
    /// the password hash lives — only to a uid-0 caller, and this process is the
    /// session user. An in-process PamContext therefore rejected every correct
    /// password on an onboarding-created account while greetd, which is root,
    /// accepted the same one. See crates/punar-auth/src/lib.rs for the
    /// measurements on both substrates.
    ///
    /// The secret crosses one anonymous stdin pipe to a fixed argv, exactly as
    /// account creation does in the greeter, and `pending` is cleared on the
    /// next line. It is never an argument and never an environment variable.
    Process {
        id: verifier

        command: ["/usr/bin/punar-auth"]
        stdinEnabled: true
        stdout: StdioCollector {
            id: verifierOutput
            waitForEnd: true
            // The LAST line, not the whole buffer: the verifier prints exactly
            // one word, but a collector that accumulated across two attempts
            // would yield "denieddenied", which is not a word this surface knows
            // and would report a plain wrong password as a device fault.
            onStreamFinished: root.finishAuth(root.lastLine(verifierOutput.text))
        }

        onStarted: {
            verifier.write(root.pending + "\n");
            root.pending = "";
            verifier.stdinEnabled = false;
        }

        // A VERIFIER THAT NEVER STARTS MUST STILL SETTLE THE SURFACE. A missing
        // binary or a failed exec would otherwise leave `busy` true forever and
        // the lock screen accepting no further attempts — the same
        // unrecoverable shape as the bug this whole change fixes. Whether
        // Quickshell's StdioCollector emits onStreamFinished for a process that
        // never ran is not documented, so this does not rely on it: exit is a
        // terminal outcome too, and finishAuth is idempotent.
        //
        // Connected rather than declared as onExited because the signal's second
        // parameter is a QProcess::ExitStatus, which qmllint cannot resolve in a
        // declared handler — the Services/WallpaperState.qml idiom.
        Component.onCompleted: verifier.exited.connect(function (exitCode) {
            if (exitCode !== 0)
                console.warn("punar-shell: punar-auth exited " + exitCode);
            root.finishAuth("");
        })
    }

    function lastLine(text: string): string {
        var lines = String(text).split("\n");
        for (var i = lines.length - 1; i >= 0; i--) {
            var line = lines[i].trim();
            if (line !== "")
                return line;
        }
        return "";
    }

    /// One of three words, and anything else is treated as "could not ask".
    ///
    /// IDEMPOTENT ON PURPOSE. Both the collector finishing and the process
    /// exiting are terminal, they arrive in no guaranteed order, and either may
    /// be the only one that arrives. The first to land decides; the rest are
    /// dropped, so a verdict can never be overwritten by the exit that followed
    /// it.
    function finishAuth(verdict: string): void {
        if (!root.busy)
            return;
        root.busy = false;
        root.pending = "";

        if (verdict === "ok") {
            root.attempts = 0;
            root.failure = "";
            // Setting this false is what releases the protocol lock; the
            // compositor brings the session back exactly as it was.
            root.locked = false;
            return;
        }

        if (verdict !== "denied") {
            // THE DEVICE COULD NOT ASK, which is not a statement about the
            // secret, so it must not be rendered as one and must not spend an
            // attempt. Telling someone their correct password is wrong on a
            // machine they cannot get into is how a diagnosable fault becomes
            // an unrecoverable one.
            console.warn("punar-shell: lock auth unavailable · verdict='" + verdict
                + "' user=" + root.accountName);
            root.failure = "Authentication is unavailable on this device";
            return;
        }

        root.attempts = root.attempts + 1;
        // An ordinary rejection used to leave no trace anywhere, so a session
        // that could never be unlocked looked identical in the journal to one
        // nobody had tried to unlock. This records what separates "wrong
        // secret" from "this surface cannot authenticate at all". The
        // passphrase is never logged, and neither is its length.
        console.warn("punar-shell: lock auth rejected · user=" + root.accountName
            + " attempt=" + root.attempts);

        if (root.denyAfter > 0 && root.attempts >= root.denyAfter) {
            // This surface caused at least `deny` failures itself, so a lockout
            // is a fact rather than a guess, and it says the one thing the
            // reader needs: the passphrase may well be right, and waiting is
            // what fixes this.
            var window = root.lockoutWindow();
            root.failure = window === ""
                ? "Locked · too many attempts · wait before trying again"
                : "Locked · too many attempts · wait " + window + " and try again";
        } else if (root.denyAfter > 0) {
            // Stated as the POLICY, not as a remaining count: faillock's counter
            // outlives this lock session while `attempts` resets on every lock,
            // so "2 tries left" here could be a lie. The threshold is always true.
            root.failure = "Try again · " + root.denyAfter
                + " failures locks this account";
        } else {
            root.failure = "Try again";
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

            onFieldReport: function (report) {
                root.fieldDiag = report;
            }
        }
    }
}
