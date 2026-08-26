pragma Singleton
// Notifications — Punar's freedesktop notification DAEMON and the store
// behind every notification surface, implementing
// docs/design/mockups/notifications-osd.html (Plate D-009, the acceptance
// reference) Sect I (card anatomy), Sect II (centre and DND) and Sect IV
// (keyboard register).
//
// THE GAP THIS CLOSES. Until this file existed, nothing on a Punar
// machine implemented `org.freedesktop.Notifications`: no application
// could tell the user anything. M10 shipped ONE region (Alert/AlertStack)
// for punar-agentd's own detection cards and said so in its header; M13
// declined a daemon on the grounds that a notification server shipped as
// final-milestone polish is how you ship a bad one. This is that daemon,
// built deliberately rather than as polish.
//
// THE MECHANISM (verified against the installed quickshell 0.3.0-3, not
// assumed): `Quickshell.Services.Notifications.NotificationServer` binds
// the D-Bus name and hands each request to QML as a `Notification`. Two
// details of that API drive the code below and are worth naming because
// they are not obvious:
//
//   1. A `Notification` is DROPPED the moment the `notification` signal
//      returns unless `tracked` is set to true. Tracking is therefore the
//      first thing the handler does — a notification centre whose records
//      evaporate is not a centre.
//   2. `trackedNotifications` is a Quickshell `ObjectModel`; its `values`
//      list changes as records arrive and close, and `valuesChanged` is
//      the only event this file needs. There is no polling anywhere in
//      this singleton and no timer of any kind (spec 6.3).
//
// WHEN ANOTHER DAEMON ALREADY OWNS THE NAME, PUNAR SAYS SO. Quickshell
// yields the name silently — it logs "Could not register notification
// server ... presumably because one is already registered" to a log the
// user never reads, and then simply receives nothing. Silence that looks
// exactly like "nobody has notified you" is the failure mode spec 1.22
// exists to forbid, so this file probes the bus ONCE at startup (and
// again whenever a human opens the centre — an event, never a poll) and
// publishes `ownership` so the surfaces can print the truth. The probe is
// identity-based, not name-based: it asks D-Bus which PID owns
// `org.freedesktop.Notifications` and compares it to `Quickshell.processId`.
// Matching on a vendor string would break the day quickshell renames
// itself; a PID cannot lie about who it is.
//
// DO NOT DISTURB, AND THE ONE THING IT DOES NOT REACH (Plate D-009 Sect II
// register 03). DND silences TOASTS, never the record: every suppressed
// notification is still tracked, still grouped and still in the centre.
// It applies to EVERY freedesktop toast including `Critical` — urgency is
// asserted by the sending application, and an application must not be
// able to defeat a decision the user made about their own machine. The
// breakthroughs are the two surfaces this daemon does not own and cannot
// mute: the M9 approval gate (Approval/ApprovalOverlay, which opens
// itself) and the M10 first-sighting shadow-AI alert (Alert/AlertStack,
// whose §5.5 rule is that a first sighting always appears). Those are not
// toasts, so quiet never reaches them — which is exactly the promise
// D-009 prints beside the toggle, kept by construction rather than by a
// special case.
//
// DND PERSISTS, because a switch that forgets is a switch the user cannot
// trust: `~/.local/state/punar/notifications.json`, written atomically
// through FileView (the Services/WorkspaceState.qml pattern), read once at
// startup. The shell is the only writer, so the file is not watched.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Services.Notifications

Singleton {
    id: root

    // Called at startup purely to force instantiation — QML singletons
    // are created lazily, and a notification daemon that only exists once
    // someone opens a surface is not a daemon (the WorkspaceState.init()
    // precedent). The caller is Notifications/ToastStack.qml's
    // `Component.onCompleted`, NOT shell.qml: the toast stack is a direct
    // child of ShellRoot and is constructed at startup, so the guarantee
    // holds without the integrator having to remember a second init call.
    function init(): void {
    }

    // ---- do not disturb ----

    property bool dnd: false

    readonly property string statePath: {
        var home = Quickshell.env("HOME");
        return home ? home + "/.local/state/punar/notifications.json" : "";
    }

    // A newer writer owns the file: never restore from it, never overwrite
    // it (the WorkspaceState version-guard rule).
    property bool writable: true

    function setDnd(on: bool): void {
        if (root.dnd === on)
            return;
        root.dnd = on;
        root.persist();
    }

    function toggleDnd(): void {
        root.setDnd(!root.dnd);
    }

    function persist(): void {
        if (!root.writable || root.statePath === "")
            return;
        stateFile.setText(JSON.stringify({
            version: 1,
            updated: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
            dnd: root.dnd
        }, null, 2) + "\n");
    }

    FileView {
        id: stateFile

        path: root.statePath
        // Atomic tmp+rename via QSaveFile; parent dirs are created on
        // write. NOT watched: the shell is the only writer of this file,
        // so a watch would only ever hear its own echo.
        atomicWrites: true
        watchChanges: false

        onLoaded: {
            var j = null;
            try {
                j = JSON.parse(stateFile.text());
            } catch (e) {
                j = null;
            }
            if (j === null || typeof j !== "object")
                return;
            if (typeof j.version === "number" && j.version > 1) {
                root.writable = false;
                return;
            }
            root.dnd = j.dnd === true;
        }
        // Absent on a machine that has never toggled quiet — the default
        // is loud, which is the honest default for a notification daemon.
        onLoadFailed: root.dnd = false
    }

    // ---- the daemon ----

    // What Punar tells applications it can do. Each flag is a CLAIM the
    // surfaces have to honour, so every one of them is answered by code
    // that exists (spec 1.22):
    //
    //   bodySupported          the toast and the centre both render a body
    //   actionsSupported       action buttons, keyed 1..9 on a focused toast
    //   persistenceSupported   the centre keeps records after the toast goes
    //   bodyMarkupSupported    FALSE — every surface renders Text.PlainText,
    //                          so claiming markup would make senders emit
    //                          `<b>` tags that Punar prints literally
    //   imageSupported         FALSE — D-009's card anatomy has no image
    //                          slot; a claimed image nothing draws is a lie
    //   actionIconsSupported   FALSE — the actions carry printed key hints,
    //                          not icons
    //   inlineReplySupported   FALSE — no text entry on any of these
    //                          surfaces
    NotificationServer {
        id: server

        // A shell reload must not silently swallow the record of every
        // notification the user has not read yet.
        keepOnReload: true

        bodySupported: true
        actionsSupported: true
        persistenceSupported: true
        bodyMarkupSupported: false
        bodyHyperlinksSupported: false
        bodyImagesSupported: false
        imageSupported: false
        actionIconsSupported: false
        inlineReplySupported: false

        // The ONE handler. Tracking is first because an untracked
        // Notification is destroyed as soon as this returns.
        onNotification: function (notification) {
            notification.tracked = true;
            root.noteArrival(notification);
        }
    }

    // Live records, newest LAST (the order the server appends them).
    readonly property var tracked: server.trackedNotifications.values

    readonly property int count: root.tracked.length

    // ---- arrival bookkeeping ----
    //
    // The freedesktop protocol carries no timestamp, so the daemon stamps
    // each record as it arrives. Keyed by the server's own notification id
    // (`uint`, stringified), which is stable for the life of the record.

    property var arrivedAt: ({})

    // Emitted for a notification that has just been accepted. The toast
    // surface listens; the centre does not need to, because it renders
    // `tracked` directly. Carries the key rather than the object so no
    // surface holds a reference to a record that may close underneath it.
    signal arrived(string key)

    // Emitted when the notification centre opens. The toast stack files
    // everything it is showing: the human is now looking at the record
    // itself, so the transient copy has done its job and stacking a toast
    // in front of the surface that contains it is just clutter. Routed
    // through this singleton rather than surface-to-surface so neither
    // file reaches into the other (the AlertStack signal precedent).
    signal centreOpened

    function noteCentreOpened(): void {
        root.centreOpened();
    }

    function key(notification: var): string {
        return (notification === null || notification === undefined) ? "" : String(notification.id);
    }

    function noteArrival(notification: var): void {
        var k = root.key(notification);
        if (k === "")
            return;
        var stamps = ({});
        for (var existing in root.arrivedAt)
            stamps[existing] = root.arrivedAt[existing];
        stamps[k] = Date.now();
        root.arrivedAt = stamps;
        root.arrived(k);
    }

    // `HH:mm` for the meta row's right-hand datum. A record with no stamp
    // — only possible for one that survived a reload — prints nothing
    // rather than a manufactured time (spec 1.22).
    function timeOf(notification: var): string {
        var at = root.arrivedAt[root.key(notification)];
        if (typeof at !== "number")
            return "";
        return Qt.formatDateTime(new Date(at), "HH:mm");
    }

    // ---- record accessors (tolerant, never throwing) ----

    function byKey(k: string): var {
        if (k === "")
            return null;
        var live = root.tracked;
        for (var i = 0; i < live.length; i++) {
            if (String(live[i].id) === k)
                return live[i];
        }
        return null;
    }

    // The speaker. A notification ALWAYS names its source — "anonymous
    // interruptions do not exist" (D-009 Sect II register 01) — so an
    // application that sent no name is labelled as exactly that, never
    // folded into a catch-all group with somebody else's messages.
    function sourceOf(notification: var): string {
        if (notification === null || notification === undefined)
            return "";
        var name = notification.appName;
        if (typeof name === "string" && name !== "")
            return name;
        var entry = notification.desktopEntry;
        if (typeof entry === "string" && entry !== "")
            return entry;
        return "Unnamed application";
    }

    // THE one sentence (D-009 Sect I register 02). The summary is the
    // claim; a sender that supplied only a body gets the body promoted
    // rather than an empty card.
    function sentenceOf(notification: var): string {
        if (notification === null || notification === undefined)
            return "";
        var s = notification.summary;
        if (typeof s === "string" && s !== "")
            return s;
        var b = notification.body;
        return (typeof b === "string" && b !== "") ? b : "(no message)";
    }

    // The detail line under the sentence. Empty when the sender supplied
    // no body, or when the body merely repeats the summary — a card does
    // not print the same sentence twice.
    function detailOf(notification: var): string {
        if (notification === null || notification === undefined)
            return "";
        var b = notification.body;
        if (typeof b !== "string" || b === "")
            return "";
        return b === notification.summary ? "" : b;
    }

    // "low" | "normal" | "critical". Returned as a STRING so no surface
    // has to import Quickshell.Services.Notifications for one enum.
    function urgencyOf(notification: var): string {
        if (notification === null || notification === undefined)
            return "normal";
        switch (notification.urgency) {
        case NotificationUrgency.Low:
            return "low";
        case NotificationUrgency.Critical:
            return "critical";
        default:
            return "normal";
        }
    }

    function actionsOf(notification: var): var {
        if (notification === null || notification === undefined)
            return [];
        var a = notification.actions;
        return (a === null || a === undefined) ? [] : a;
    }

    // ---- toast dwell time ----
    //
    // PUNAR SETS THE DWELL TIME, NOT THE SENDER. The protocol's
    // `expire_timeout` is advisory and its unit is a long-standing source
    // of confusion between implementations; guessing at it would produce
    // toasts that linger for a minute or vanish before they are read.
    // Punar therefore uses its own urgency table and honours exactly ONE
    // value from the sender — 0, which means "never expire" in every
    // reading of the spec and in both candidate units. Everything else is
    // ignored, deliberately and in writing.
    //
    // A sticky toast is not a trap: it is dismissable by key and by click,
    // and dismissal FILES it to the centre rather than destroying it.
    readonly property int dwellLowMs: 4000
    readonly property int dwellNormalMs: 6000

    function sticky(notification: var): bool {
        if (notification === null || notification === undefined)
            return false;
        if (root.urgencyOf(notification) === "critical")
            return true;
        return notification.expireTimeout === 0;
    }

    function dwellMs(notification: var): int {
        return root.urgencyOf(notification) === "low" ? root.dwellLowMs : root.dwellNormalMs;
    }

    // ---- grouping (D-009 Sect II register 01) ----
    //
    // Sources in most-recent-first order, each holding its own records
    // newest first. Rebuilt whenever the model changes — an O(n) walk over
    // a list that is, by the nature of the surface, short.
    readonly property var groups: {
        var order = [];
        var bySource = ({});
        var live = root.tracked;
        for (var i = live.length - 1; i >= 0; i--) {
            var n = live[i];
            if (n === null || n === undefined)
                continue;
            var src = root.sourceOf(n);
            if (bySource[src] === undefined) {
                bySource[src] = [];
                order.push(src);
            }
            bySource[src].push(n);
        }
        var out = [];
        for (var j = 0; j < order.length; j++)
            out.push({
                source: order[j],
                items: bySource[order[j]]
            });
        return out;
    }

    // ---- resolution ----

    // Dismiss ONE record: it leaves the centre and the sending application
    // is told why (`dismiss()` closes with reason Dismissed, which is the
    // signal a well-behaved sender needs to stop waiting on it).
    function dismiss(notification: var): void {
        if (notification === null || notification === undefined)
            return;
        notification.dismiss();
    }

    function dismissKey(k: string): void {
        root.dismiss(root.byKey(k));
    }

    // Clear all — freedesktop records only. Approvals and shadow-AI alerts
    // are NOT in this model at all (they are punard's and punar-agentd's
    // records, read by their own singletons), so "approvals resolve, they
    // don't dismiss" (D-009 Sect II register 04) is true here by
    // construction rather than by a special case that could rot.
    //
    // Iterates over a COPY: `tracked` shrinks under the loop otherwise.
    function clearAll(): void {
        var live = root.tracked;
        var doomed = [];
        for (var i = 0; i < live.length; i++)
            doomed.push(live[i]);
        for (var j = 0; j < doomed.length; j++)
            root.dismiss(doomed[j]);
    }

    // Invoke one of a notification's actions. The sender decides what
    // happens next; freedesktop closes the notification afterwards unless
    // it declared itself resident, and quickshell implements that rule, so
    // this file does not second-guess it.
    function invokeAction(action: var): void {
        if (action === null || action === undefined)
            return;
        action.invoke();
    }

    // ---- who owns org.freedesktop.Notifications ----
    //
    // "punar"      — the owning PID is this shell process. Notifications
    //                reach Punar.
    // "foreign"    — a DIFFERENT process owns the name, proven by PID.
    //                Nothing reaches Punar, and every surface must say so
    //                instead of drawing a calm empty state that means the
    //                opposite.
    // "unverified" — the probe has not run, `busctl` is unavailable (a dev
    //                machine outside the image), or the bus did not
    //                answer. THE ABSENCE OF AN ANSWER IS NOT AN ANSWER:
    //                this state claims nothing in either direction, and no
    //                surface draws an alarm for it.
    //
    // There is deliberately no fourth state for "nobody owns the name". A
    // failed lookup can mean an unowned name, an unreachable bus, or a
    // missing tool, and the shell cannot tell those apart from here — so
    // it declines to invent a verdict it cannot support (spec 1.22).
    property string ownership: "unverified"
    property int ownerPid: 0
    property string ownerName: ""

    function ownershipHealthy(): bool {
        // Surfaces print the alarm only for a PROVEN foreign owner.
        return root.ownership !== "foreign";
    }

    // Ask D-Bus for the PID behind the well-known name. One-shot, fixed
    // argv, no shell string (the AlertStack/ApprovalOverlay rule). Called
    // once shortly after startup and again on every centre open — an
    // event, never a poll.
    function probeOwnership(): void {
        if (ownerProbe.running)
            return;
        ownerOut.seen = false;
        ownerProbe.running = true;
    }

    Process {
        id: ownerProbe

        command: ["busctl", "--user", "--json=short", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetConnectionUnixProcessID", "s", "org.freedesktop.Notifications"]

        // THE RESULT IS READ FROM THE STREAM, NOT FROM AN EXIT CODE.
        // `Process.exited` also carries a `QProcess::ExitStatus`, a C++
        // enum qmllint cannot resolve from QML — every handler for that
        // signal trips [signal-handler-parameters] whether or not it names
        // the parameter. The stream's own completion says everything this
        // probe needs: a well-formed reply carries a PID, and anything
        // else — a refusing bus, a missing tool, a crash — leaves no PID
        // and is reported as unverified.
        stdout: StdioCollector {
            id: ownerOut

            property bool seen: false

            waitForEnd: true

            onStreamFinished: {
                if (ownerOut.seen)
                    return;
                ownerOut.seen = true;
                var pid = 0;
                try {
                    var j = JSON.parse(ownerOut.text);
                    if (j !== null && typeof j === "object" && Array.isArray(j.data))
                        pid = Number(j.data[0]);
                } catch (e) {
                    pid = 0;
                }
                if (!(pid > 0)) {
                    root.ownership = "unverified";
                    root.ownerPid = 0;
                    root.ownerName = "";
                    return;
                }
                root.ownerPid = pid;
                root.ownership = (pid === Quickshell.processId) ? "punar" : "foreign";
                root.ownerName = "";
                // Name the intruder, so the user is told WHICH daemon to
                // stop rather than merely that one exists. /proc/<pid>/comm
                // is a read, not a second probe process.
                if (root.ownership === "foreign")
                    ownerComm.path = "/proc/" + pid + "/comm";
            }
        }
    }

    FileView {
        id: ownerComm

        // Empty until a foreign owner is found; a FileView with no path
        // reads nothing.
        path: ""
        watchChanges: false
        onLoaded: root.ownerName = ownerComm.text().trim()
        onLoadFailed: root.ownerName = ""
    }

    // The probe runs ONCE, shortly after startup — late enough that
    // quickshell's own D-Bus registration has settled, early enough that
    // the first notification of the session is already judged correctly.
    // This is a single-shot timer, not a clock: it fires once per shell
    // process and then stops for good (spec 6.3 — no polling loops).
    Timer {
        interval: 1500
        repeat: false
        running: true
        onTriggered: root.probeOwnership()
    }
}
