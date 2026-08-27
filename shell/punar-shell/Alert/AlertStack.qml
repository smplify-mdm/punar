pragma ComponentBehavior: Bound
// AlertStack — the Milestone 10 shadow-AI alert surface, implementing
// docs/design/mockups/notifications-osd.html Sect I (Plate D-009, the
// acceptance reference) and milestone-10.md §5: ONE layer-shell alert
// region at the D-009 toast position, rendering ONLY punar-agentd
// detection alerts, in the D-009 card anatomy —
//
//     meta row · hairline · one sentence · detail · why · policy ·
//     actions · footer
//
// THE SLIVER, AND ONLY THE SLIVER (milestone-10.md §5.6). There is no
// notification code in this shell: no toast stack for anything else, no
// notification centre, no freedesktop notification daemon, no persistent
// do-not-disturb toggle and no `Punar+N`. D-009 draws all three states;
// M13 owns them. This file builds the one region M10's deliverable names
// and nothing beside it.
//
// SUSPECTED, NEVER CERTAIN, AND NEVER ARMED (milestone-10.md law 4, spec
// 23, 1.22). The word "suspected" appears in the meta row AND in the
// sentence. The subject of every sentence is the PROCESS, never the
// person — this surface passes no verdict on a human. "Nothing was
// blocked" is printed because M10 detects, records and alerts and does
// not block, kill or quarantine anything; a user who believes they are
// protected when they are not is worse off than one who knows. There are
// therefore no BLOCK NETWORK / REGISTER AS MANAGED buttons: those need
// punar-netd (M12) and a policy verb, and this release ships no dead
// buttons.
//
// DELIBERATE DEVIATION FROM THE PLATE (milestone-10.md §5.1, written down
// because it must be): D-009's subline reads
// `~/Downloads/foo-agent → api.foo.ai`. THE SHIPPED CARD DROPS
// `→ api.foo.ai`. Nothing on this device observes a network destination
// before M12, and the plate is the acceptance reference for ANATOMY, not
// a licence to print a field no code produced. No destination — invented,
// inferred or fixture-borrowed — appears anywhere in this file.
//
// DATA (milestone-10.md §5.3, §13.4): the Alerts singleton follows
// `/run/punar-agentd/alerts.json` (`0640 root:punar`) with an inotify
// FileView — no socket client in the shell, no polling, no timers in this
// file at all. The file is NON-AUTHORITATIVE display data: `D` sends only
// the `alert_id` to `punarctl` and agentd re-derives everything from its
// own record. A missing or unparsable file renders NO card — fail closed,
// never a placeholder alert.
//
// ANTI-NAG IS THE DAEMON'S (milestone-10.md §5.2): agentd raises at most
// one alert per `signature_id` and re-raises nothing inside the 24 h quiet
// window. This surface keys every card by `alert_id` and remembers which
// ids it has already presented, so no file rewrite — and no restart of the
// detection pass — can produce a second card for the same alert.
//
// DO NOT DISTURB (milestone-10.md §5.5, decision 8): the FIRST sighting of
// a signature breaks through; nothing else does. The argument is spec 24.2,
// not taste — from M10 on, an authorized administrator can query this exact
// fact, so a quiet-mode toggle that could hide it would create a state in
// which the admin knows about a process on this machine and the user does
// not. Under DND the card renders WITHOUT SOUND (this shell plays none),
// WITHOUT FOCUS STEAL (the layer surface never takes the keyboard on a
// quiet raise) and WITHOUT AUTO-DISMISS. DND here is shell-local state
// with an IPC setter, no persistence, no capability and no UI toggle —
// the honest minimum that makes the rule testable (milestone-10.md §5.6);
// the real toggle, its persistence and its capability are M13.
//
// KEYBOARD-FIRST (spec 12.1 — notifications are a required keyboard-
// operable area; 12.3 — the binding is printed on the control):
//   I  Inspect  → the PUNAR+A AI panel, focused on this detection
//   D  Dismiss  → files the card to the record; it is never destroyed
//   ↑ ↓ / k j   → walk a multi-card stack
//   Esc         → hands the keyboard back. It ignores NOTHING silently:
//                 the card stays, the record stays, the alert stays in
//                 `punarctl agents alerts` (D-009 Sect I register 03).
//
// Driven from Hyprland / the m10-check probe via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call alerts open

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Theme"
import "../Services"

Scope {
    id: root

    property bool open: false
    property bool windowVisible: false

    // Do-not-disturb, shell-local (§5.6). No persistence, no capability,
    // no UI toggle, no punard round trip — M13 owns all four.
    property bool dnd: false

    // Whether this surface currently holds the keyboard. A raise takes it
    // so the printed keys work the instant the card appears; a QUIET raise
    // (DND) never does, and Esc hands it back without touching the card.
    property bool holdsKeyboard: false

    // The card under the cursor.
    property string focusedId: ""

    // Every `alert_id` this surface has already put on screen, and the
    // subset that was raised while DND was on. Presentation happens ONCE
    // per id, for the lifetime of the shell process: a rewrite of
    // alerts.json, a dismissal, a clear-and-return of the same process, or
    // a `close()` followed by a later change can never re-raise a card the
    // human has already been shown. Only a genuinely new alert — which
    // agentd raises only after the 24 h quiet window (§5.2) — is new here.
    property var presentedIds: ({})
    property var quietIds: ({})

    // The [I] Inspect action. Wired in shell.qml to the PUNAR+A panel so
    // this surface does not reach into another one directly (and so a
    // shell without an AI panel simply has nothing connected).
    signal inspectRequested(string detectionId)

    // D-009's stack is a short column, not a scroller. Three cards is the
    // plate's density; anything beyond that is counted honestly and read
    // in the register the footer already names.
    readonly property int maxCards: 3

    readonly property var cards: {
        var out = [];
        var live = Alerts.active;
        for (var i = 0; i < live.length && i < root.maxCards; i++)
            out.push(live[i]);
        return out;
    }

    readonly property int overflow: Math.max(0, Alerts.activeCount - root.cards.length)

    // ---- shared type grammar (DESIGN_LANGUAGE.md §1) ----

    // Meta / label register: Geist Mono, tracked, uppercase. The SYSTEM
    // voice, and the only voice allowed to look like one.
    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.13)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        textFormat: Text.PlainText
    }

    // The same mono register with its CASE PRESERVED, for lines that carry
    // evidence rather than labels: an executable path, a signature id, an
    // org policy id, a CLI command. The meta grammar uppercases labels,
    // never evidence — `~/Downloads/foo-agent`, `unmanaged-path-agentlike`
    // and `punarctl agents list` all mean something only as written.
    component Data: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 500
        font.letterSpacing: Theme.tracking(9, 0.1)
        color: Theme.shellInk3
        textFormat: Text.PlainText
    }

    // A bordered tag (mockup .pill): mono, tracked, uppercase, in its own
    // status color.
    component Pill: Rectangle {
        id: pill

        property string text: ""
        property color tone: Theme.shellInk3

        implicitWidth: pillLabel.implicitWidth + 16
        implicitHeight: pillLabel.implicitHeight + 7
        color: "transparent"
        border.width: Theme.hairline
        border.color: pill.tone
        radius: Theme.radiusTag

        Text {
            id: pillLabel

            anchors.centerIn: parent
            text: pill.text
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            font.letterSpacing: Theme.tracking(9, 0.13)
            font.capitalization: Font.AllUppercase
            color: pill.tone
            textFormat: Text.PlainText
        }
    }

    // An action button (mockup .approve / .ghost), each carrying its
    // visible key binding. The keyboard is the primary path; these are the
    // legend for it (spec 12.3).
    component ActionButton: Rectangle {
        id: button

        property string label: ""
        property string binding: ""
        property bool filled: false
        property color tone: Theme.shellFg

        signal activated

        implicitWidth: buttonRow.implicitWidth + 22
        implicitHeight: buttonRow.implicitHeight + 12
        radius: Theme.radiusTag
        color: button.filled ? button.tone : "transparent"
        border.width: Theme.hairline
        border.color: button.tone

        Row {
            id: buttonRow

            anchors.centerIn: parent
            spacing: 5

            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: button.label
                font.family: Theme.fontMono
                font.pixelSize: 9
                font.weight: 600
                font.letterSpacing: Theme.tracking(9, 0.1)
                font.capitalization: Font.AllUppercase
                color: button.filled ? Theme.shellActionFg : button.tone
                textFormat: Text.PlainText
            }
            Rectangle {
                anchors.verticalCenter: parent.verticalCenter
                width: keyCap.implicitWidth + 8
                height: keyCap.implicitHeight + 3
                radius: 3
                color: "transparent"
                border.width: Theme.hairline
                border.color: button.filled ? Theme.shellActionFg : button.tone
                opacity: 0.7

                Text {
                    id: keyCap

                    anchors.centerIn: parent
                    text: button.binding
                    font.family: Theme.fontMono
                    font.pixelSize: 8
                    font.weight: 600
                    color: button.filled ? Theme.shellActionFg : button.tone
                    textFormat: Text.PlainText
                }
            }
        }

        MouseArea {
            anchors.fill: parent
            cursorShape: Qt.PointingHandCursor
            onClicked: button.activated()
        }
    }

    // ---- the card's words (milestone-10.md §5.1, exact copy) ----

    // The process, named as the record names it. Never a person.
    function agentName(alert: var): string {
        var name = Alerts.str(alert, "agent");
        return name === "" ? "an unnamed process" : name;
    }

    // Meta row, left half. "SUSPECTED" is not decoration and not optional:
    // §5.1 requires the word here and in the sentence below.
    readonly property string metaLabel: "Unknown AI · Suspected"

    // Meta row, right half: the clock time of the most recent sighting —
    // D-009's `.tmeta .exp` slot. An unreadable stamp prints nothing.
    function metaTime(alert: var): string {
        var t = Alerts.hhmm(Alerts.str(alert, "last_seen"));
        return t !== "" ? t : Alerts.hhmm(Alerts.str(alert, "first_seen"));
    }

    // THE one sentence. If it needs two, it is not a card (D-009 Sect I
    // register 02).
    function sentence(alert: var): string {
        return "Unknown AI activity suspected · " + root.agentName(alert);
    }

    // `/home/punar/Downloads/foo-agent` → `~/Downloads/foo-agent`, and
    // only when the record's own `owner` makes the tilde unambiguous. This
    // is the spelling Plate D-009 and milestone-10.md §5.1 both print, and
    // it is a RENDERING of the path already on the card next to the owner
    // it belongs to — not an abbreviation that hides where the binary
    // lives. Any path that is not under that owner's home is printed
    // exactly as the record carries it. The untouched path is always in
    // `punarctl agents alerts`.
    function displayPath(executable: string, owner: string): string {
        if (executable === "" || owner === "")
            return executable;
        var home = owner === "root" ? "/root/" : "/home/" + owner + "/";
        if (executable.indexOf(home) === 0)
            return "~/" + executable.substring(home.length);
        return executable;
    }

    // The detail line: what is running, as whom, since when. Every clause
    // is dropped when the record does not carry it — an absent field is
    // absent, never a placeholder and never a guess (spec 1.22).
    function detailLine(alert: var): string {
        var exe = Alerts.str(alert, "executable");
        var owner = Alerts.str(alert, "owner");
        var live = Alerts.isLive(alert);
        var parts = [];
        if (exe !== "")
            parts.push(root.displayPath(exe, owner));
        var when = Alerts.hhmm(Alerts.str(alert, live ? "first_seen" : "last_seen"));
        var clause = live ? "running" : "no longer running";
        if (owner !== "")
            clause = live ? ("running as " + owner) : ("ran as " + owner);
        if (when !== "")
            clause += live ? (" since " + when) : (" · last seen " + when);
        parts.push(clause);
        return parts.join(" · ");
    }

    // Where an executable lives, in the words §3.5 uses for the zones the
    // shipped signature actually tests. This is a RENDERING of the path
    // the record already carries, not a second datum: an unrecognised path
    // yields the generic phrasing rather than a confident-sounding guess.
    function zonePhrase(executable: string): string {
        if (executable.indexOf("/Downloads/") >= 0)
            return "Downloads";
        if (executable.indexOf("/.local/bin/") >= 0)
            return "~/.local/bin";
        if (executable.indexOf("/tmp/") === 0 || executable.indexOf("/tmp/") >= 0)
            return "/tmp";
        return "an unmanaged path";
    }

    // The `why`, in words and by signature id — §73's "why", and the half
    // of it a human can act on. A `why` string supplied by agentd always
    // wins; otherwise the shell says, in its own words, what the ONE
    // shipped signature means (§3.5: an unmanaged path prefix AND an
    // agent-like name token, never either alone). An unrecognised
    // signature is named and not narrated.
    function whyLine(alert: var): string {
        var supplied = Alerts.str(alert, "why");
        var sig = Alerts.str(alert, "signature");
        var live = Alerts.isLive(alert);
        var base = "";
        if (supplied !== "") {
            base = supplied;
        } else if (sig === "unmanaged-path-agentlike") {
            base = "an agent-named executable " + (live ? "is" : "was")
                 + " running from " + root.zonePhrase(Alerts.str(alert, "executable"))
                 + ", outside any managed Punar session";
        } else {
            base = "this process " + (live ? "is" : "was")
                 + " running outside any managed Punar session";
        }
        return "Why · " + base + (sig === "" ? "" : " · signature " + sig);
    }

    // UNMANAGED-FIRST (DESIGN_LANGUAGE.md §8): whatever agentd cites is
    // what is drawn — a personal device cites personal defaults, an
    // enrolled one cites the organization by name. The shell never
    // upgrades a personal citation into an org one, and the card renders
    // FULLY on a personal device: a security feature is a user benefit
    // first, and the managed annotation is additive only.
    function policyLine(alert: var): string {
        var cited = Alerts.str(alert, "policy_citation");
        return "Policy · " + (cited === "" ? "Personal defaults" : cited);
    }

    // The footer. "Nothing was blocked" is mandatory (§5.1 / law 4), and
    // the CLI command is the next step for a reader who wants the whole
    // register rather than one card.
    readonly property string footerLeft: "Suspected, not certain · nothing was blocked · punarctl agents list"

    // §73's "who requested it": nobody. This is the device's own
    // observation, and D-009 Sect II register 01 gives it a source group.
    readonly property string footerRight: "Punar · punar-agentd"

    // ---- state ----

    function wasPresented(alertId: string): bool {
        return root.presentedIds[alertId] === true;
    }

    function raisedQuietly(alertId: string): bool {
        return root.quietIds[alertId] === true;
    }

    function cardIndex(alertId: string): int {
        for (var i = 0; i < root.cards.length; i++) {
            if (Alerts.id(root.cards[i]) === alertId)
                return i;
        }
        return -1;
    }

    // THE WHOLE CONTROL LOOP. No polling, no queue of its own: agentd's
    // file is the register and this reacts to changes in it.
    function syncStack(): void {
        if (root.cards.length === 0) {
            // Nothing suspected, or every card filed. Fail closed: the
            // region simply is not there.
            root.focusedId = "";
            root.hide();
            return;
        }

        // First sightings — ids this surface has never drawn. Everything
        // agentd puts in the file IS a first sighting by construction
        // (§5.2 raises once per signature), so this loop is the shell's
        // own guarantee that a rewrite cannot re-toast, not a second
        // anti-nag rule competing with the daemon's.
        var fresh = [];
        var seen = ({});
        for (var key in root.presentedIds)
            seen[key] = root.presentedIds[key];
        var quiet = ({});
        for (var qkey in root.quietIds)
            quiet[qkey] = root.quietIds[qkey];

        for (var i = 0; i < root.cards.length; i++) {
            var id = Alerts.id(root.cards[i]);
            if (id === "" || root.wasPresented(id))
                continue;
            fresh.push(id);
            seen[id] = true;
            if (root.dnd)
                quiet[id] = true;
        }
        root.presentedIds = seen;
        root.quietIds = quiet;

        // Keep the reader's place across a rewrite; take the cursor to a
        // new sighting when one arrives.
        if (fresh.length > 0)
            root.focusedId = fresh[0];
        else if (root.cardIndex(root.focusedId) < 0)
            root.focusedId = Alerts.id(root.cards[0]);

        if (fresh.length === 0)
            return; // an update to a card already on screen: no re-raise

        // The breakthrough (§5.5): the card appears either way. Under DND
        // it appears WITHOUT the keyboard — no focus steal, no sound, no
        // auto-dismiss — so the information arrives and the interruption
        // does not.
        root.show(!root.dnd);
    }

    function moveFocus(delta: int): void {
        if (root.cards.length === 0)
            return;
        var at = root.cardIndex(root.focusedId);
        at = (at < 0 ? 0 : at) + delta;
        at = Math.max(0, Math.min(root.cards.length - 1, at));
        root.focusedId = Alerts.id(root.cards[at]);
    }

    // ---- actions ----

    // [I] Inspect — the PUNAR+A surface (Plate D-005), focused on this
    // detection. `detection_id` is the running-process identity
    // (milestone-10.md §4.1) and is exactly the id the AI panel's rail
    // keys its detection rows by, so the panel opens ON the row rather
    // than merely near it.
    function inspect(): void {
        var a = Alerts.byId(root.focusedId);
        if (a === null)
            return;
        root.releaseKeyboard();
        root.inspectRequested(Alerts.str(a, "detection_id"));
    }

    // [D] Dismiss — DISMISS FILES, IT NEVER DESTROYS (§5.4, D-009 Sect I
    // register 03). Detached `punarctl` with fixed argv — never a shell
    // string, never an IPC client in the shell. The result is not read:
    // agentd rewrites alerts.json and the next FileView change is the
    // truth. The alert stays in `punarctl agents alerts` with its
    // dismissal time, and in the detection record.
    function dismiss(): void {
        var id = root.focusedId;
        if (id === "")
            return;
        try {
            Quickshell.execDetached(["punarctl", "agents", "alerts", "dismiss", id]);
        } catch (e) {
            // No punarctl on a dev machine: the card stays exactly as it
            // is and the record is untouched. Nothing is guessed.
            console.warn("punar-shell: alert dismissal unavailable:", e);
        }
    }

    // ---- surface ----

    function show(takeKeyboard: bool): void {
        hideTimer.stop();
        root.windowVisible = true;
        root.open = true;
        if (takeKeyboard) {
            root.holdsKeyboard = true;
            cardKeys.forceActiveFocus();
        }
    }

    // Esc: hand the keyboard back. IGNORES NOTHING SILENTLY — the card
    // stays on screen, the alert stays in the record, and nothing is
    // dismissed. Only [D] files a card.
    function releaseKeyboard(): void {
        root.holdsKeyboard = false;
    }

    // The surface's off switch (IPC `close`). It changes no record: the
    // alert is still in `punarctl agents alerts`, and `alerts open` draws
    // it again.
    function hide(): void {
        if (!root.open)
            return;
        root.open = false;
        root.holdsKeyboard = false;
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    Component.onCompleted: root.syncStack()

    Connections {
        target: Alerts

        // One handler, one control loop: agentd's file is the register.
        function onActiveChanged(): void {
            root.syncStack();
        }
    }

    // Hyprland binds and the m10-check probe:
    //   qs -p /usr/share/punar/shell ipc call alerts open
    IpcHandler {
        target: "alerts"

        // Draw whatever is outstanding and take the keyboard. An explicit
        // open is a human asking to see it, so it is never quiet.
        //
        // NOTHING SUSPECTED MEANS NOTHING ON SCREEN, even when asked
        // directly: an empty region that took the keyboard would swallow
        // every keystroke on the desktop behind a card that does not
        // exist. Fail closed here too.
        function open(): void {
            Alerts.refresh();
            if (root.cards.length === 0) {
                root.hide();
                return;
            }
            if (root.cardIndex(root.focusedId) < 0)
                root.focusedId = Alerts.id(root.cards[0]);
            root.show(true);
        }
        function close(): void {
            root.hide();
        }
        function state(): string {
            return root.open ? "open" : "closed";
        }

        // The DND setter (§5.6): shell-local, unpersisted, capability-less
        // — it exists so decision 8 is verifiable rather than merely
        // written. `on` | `off` | `toggle`; anything else reports the
        // current state without changing it. Returns the resulting state.
        function dnd(mode: string): string {
            if (mode === "on")
                root.dnd = true;
            else if (mode === "off")
                root.dnd = false;
            else if (mode === "toggle")
                root.dnd = !root.dnd;
            return root.dnd ? "on" : "off";
        }

        // ---- read-only probes ----
        //
        // The `approval` / `aipanel` / `overview` precedent: a check must
        // be able to assert what the human was actually shown without a
        // screenshot being the only evidence. These are needed here for a
        // second reason (milestone-10.md §16 group 5): whether a raise
        // broke through QUIETLY is shell-local state by §5.6 — agentd
        // cannot write it into its own root-owned file, because agentd
        // does not know this shell's DND state and must never be told to
        // trust it. So the shell answers for it.
        function cards(): string {
            var ids = [];
            for (var i = 0; i < root.cards.length; i++)
                ids.push(Alerts.id(root.cards[i]));
            return ids.join(",");
        }
        function quiet(): string {
            var ids = [];
            for (var j = 0; j < root.cards.length; j++) {
                var id = Alerts.id(root.cards[j]);
                if (root.raisedQuietly(id))
                    ids.push(id);
            }
            return ids.join(",");
        }
        function focused(): string {
            return root.focusedId;
        }
    }

    // The only timer in this file, and it is not a clock: it keeps the
    // window alive for the 300 ms exit animation and then stops. There is
    // no auto-dismiss timer anywhere on this surface. Under DND because
    // §5.5 forbids one; otherwise because a shadow-AI first sighting is a
    // decision, not an interruption, and decisions are not on a clock.
    // (The original reason — "M10 ships no notification centre" — has
    // EXPIRED: the centre now ships. It does not change the conclusion,
    // because the centre reads this same Alerts singleton and holds these
    // rows STICKY for exactly the same reason. It stays until [D].)
    Timer {
        id: hideTimer
        interval: Theme.durStandard
        onTriggered: root.windowVisible = false
    }

    PanelWindow {
        id: win

        visible: root.windowVisible

        anchors {
            top: true
            bottom: true
            left: true
            right: true
        }
        // THE INPUT REGION IS THE CARDS, AND NOTHING ELSE. The surface
        // spans the output so the stack can sit at the plate's percentage
        // position, but the mask confines every pointer event to the cards
        // themselves — the rest of the desktop keeps its clicks. (The M9
        // gate is a full-screen scrim because a GATE must be; an alert must
        // not be: nothing is waiting on this card, so nothing may be
        // blocked by it.)
        mask: Region {
            item: stack
        }
        exclusionMode: ExclusionMode.Ignore
        color: "transparent" // the cards own every visible pixel
        WlrLayershell.namespace: "punar-alerts"
        WlrLayershell.layer: WlrLayer.Overlay
        // A raise takes the keyboard so the printed keys work at once; a
        // QUIET raise (DND) never does, and Esc gives it back. OnDemand
        // keeps the card operable by click without ever stealing focus.
        WlrLayershell.keyboardFocus: root.holdsKeyboard ? WlrKeyboardFocus.Exclusive
                                                        : WlrKeyboardFocus.OnDemand

        onVisibleChanged: {
            if (win.visible && root.holdsKeyboard)
                cardKeys.forceActiveFocus();
        }

        Connections {
            target: root

            // Re-arm keyboard focus on every raise, not only on creation:
            // a raise inside the 300 ms hide animation keeps the same
            // window, so `onVisibleChanged` never fires and the stack
            // would come back focus-less, swallowing Esc (the M7 AI-panel
            // bug, re-learned in M9).
            function onHoldsKeyboardChanged(): void {
                if (root.holdsKeyboard)
                    cardKeys.forceActiveFocus();
            }
        }

        FocusScope {
            id: cardKeys

            anchors.fill: parent
            focus: true

            // Keyboard-first (spec 12.1): every action on this surface has
            // a key, and every key is printed on the control it drives.
            Keys.onPressed: function (event) {
                switch (event.key) {
                case Qt.Key_I:
                    root.inspect();
                    event.accepted = true;
                    break;
                case Qt.Key_D:
                    root.dismiss();
                    event.accepted = true;
                    break;
                case Qt.Key_Escape:
                    // Ignores nothing silently: the card and the record
                    // both stay; only the keyboard goes back.
                    root.releaseKeyboard();
                    event.accepted = true;
                    break;
                case Qt.Key_Down:
                case Qt.Key_J:
                    root.moveFocus(1);
                    event.accepted = true;
                    break;
                case Qt.Key_Up:
                case Qt.Key_K:
                    root.moveFocus(-1);
                    event.accepted = true;
                    break;
                }
            }

            // D-009 `.toaststack`: top 13%, right 3.4%, width min(46%,
            // 340px), 10 px gap. The top offset is floored at 44 px so the
            // stack always clears the 30 px bar and its gutter on a short
            // display, and the right inset at 20 px for the same reason.
            Column {
                id: stack

                anchors.right: parent.right
                anchors.rightMargin: Math.max(20, Math.round(cardKeys.width * 0.034))
                y: Math.max(44, Math.round(cardKeys.height * 0.13))
                width: Math.min(340, Math.round(cardKeys.width * 0.46))
                spacing: 10
                opacity: root.open ? 1 : 0

                Behavior on opacity {
                    NumberAnimation {
                        duration: Theme.durStandard
                        easing.type: Easing.BezierSpline
                        easing.bezierCurve: Theme.easingCurve
                    }
                }

                Repeater {
                    model: root.cards

                    // ---- the alert card (Plate D-009 `.toast`) ----
                    Rectangle {
                        id: card

                        required property var modelData

                        readonly property string alertId: Alerts.id(card.modelData)
                        readonly property bool hasFocus: card.alertId === root.focusedId

                        width: stack.width
                        implicitHeight: body.implicitHeight + 24
                        height: card.implicitHeight
                        color: Theme.shellSurface
                        radius: Theme.radius
                        // The red voice — the only red on this surface, as
                        // in D-005's unknown row. A focused card wears the
                        // 2 px border; the plate's soft drop shadow is
                        // omitted deliberately (llvmpipe budget, the
                        // standing M1/M2 deviation).
                        border.width: card.hasFocus ? 2 : Theme.hairline
                        border.color: Theme.shellStatusBad

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                root.focusedId = card.alertId;
                                root.holdsKeyboard = true;
                            }
                        }

                        Column {
                            id: body

                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.top: parent.top
                            anchors.leftMargin: 14
                            anchors.rightMargin: 14
                            anchors.topMargin: 12
                            spacing: 0

                            // ---- meta row (D-009 `.tmeta`) ----
                            Item {
                                width: parent.width
                                height: Math.max(13, metaRight.implicitHeight)

                                Meta {
                                    anchors.left: parent.left
                                    anchors.verticalCenter: parent.verticalCenter
                                    color: Theme.shellStatusBad
                                    text: root.metaLabel
                                }
                                Row {
                                    id: metaRight

                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: 8

                                    // Managed annotation is ADDITIVE ONLY
                                    // (DESIGN_LANGUAGE.md §8): the pill
                                    // joins the card when enrolled, and the
                                    // card renders fully without it. D-009
                                    // hangs this pill off the action row;
                                    // at the shipped 340 px width the
                                    // action row is already full, so it
                                    // rides the meta row instead — the
                                    // annotation is the same, and nothing
                                    // else moves.
                                    Pill {
                                        anchors.verticalCenter: parent.verticalCenter
                                        visible: Status.enrolled
                                        text: "Managed"
                                        tone: Theme.shellInk3
                                    }
                                    Meta {
                                        anchors.verticalCenter: parent.verticalCenter
                                        color: Theme.shellStatusBad
                                        text: root.metaTime(card.modelData)
                                    }
                                }
                            }

                            Item {
                                width: parent.width
                                height: 8
                            }

                            // ---- hairline (D-009 `.trule`) ----
                            Rectangle {
                                width: parent.width
                                height: Theme.hairline
                                color: Theme.shellFg
                            }

                            Item {
                                width: parent.width
                                height: 9
                            }

                            // ---- THE one sentence (D-009 `.tsent`) ----
                            Text {
                                width: parent.width
                                text: root.sentence(card.modelData)
                                font.family: Theme.fontSans
                                font.pixelSize: 13
                                font.weight: 500
                                lineHeight: 1.45
                                color: Theme.shellFg
                                wrapMode: Text.WordWrap
                                textFormat: Text.PlainText
                            }

                            Item {
                                width: parent.width
                                height: 7
                            }

                            // ---- detail: what, as whom, since when ----
                            Data {
                                width: parent.width
                                text: root.detailLine(card.modelData)
                                // WRAPPED, NEVER ELIDED: this line is the
                                // evidence, and a truncated path is worse
                                // than a taller card. `Text.Wrap` breaks
                                // inside a long path when it has to.
                                wrapMode: Text.Wrap
                            }

                            Item {
                                width: parent.width
                                height: 4
                            }

                            // ---- why (§73), in words and by signature ----
                            Data {
                                width: parent.width
                                text: root.whyLine(card.modelData)
                                wrapMode: Text.WordWrap
                            }

                            Item {
                                width: parent.width
                                height: 4
                            }

                            // ---- policy (D-009 `.tpolicy`) ----
                            Data {
                                width: parent.width
                                text: root.policyLine(card.modelData)
                                elide: Text.ElideRight
                            }

                            Item {
                                width: parent.width
                                height: 10
                            }

                            // ---- actions (D-009 `.tacts`) ----
                            Item {
                                width: parent.width
                                height: actions.implicitHeight

                                Row {
                                    id: actions

                                    anchors.left: parent.left
                                    spacing: 8

                                    ActionButton {
                                        label: "Inspect"
                                        binding: "I"
                                        filled: true
                                        tone: Theme.shellFg
                                        onActivated: {
                                            root.focusedId = card.alertId;
                                            root.inspect();
                                        }
                                    }
                                    // The PUNAR+A surface is where Inspect
                                    // lands; naming the global binding
                                    // means the reader can get back to it
                                    // without this card (§5.1).
                                    Meta {
                                        anchors.verticalCenter: parent.verticalCenter
                                        font.pixelSize: 8
                                        font.weight: 500
                                        color: Theme.shellInputBorder
                                        text: "Punar+A"
                                    }
                                    ActionButton {
                                        label: "Dismiss to record"
                                        binding: "D"
                                        tone: Theme.shellInk3
                                        onActivated: {
                                            root.focusedId = card.alertId;
                                            root.dismiss();
                                        }
                                    }
                                }
                            }

                            Item {
                                width: parent.width
                                height: 10
                            }

                            // ---- footer ----
                            Rectangle {
                                width: parent.width
                                height: Theme.hairline
                                color: Theme.shellBorder
                            }

                            Item {
                                width: parent.width
                                height: footerText.implicitHeight + 14

                                Data {
                                    id: footerText

                                    anchors.left: parent.left
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    font.pixelSize: 8
                                    text: root.footerLeft
                                    wrapMode: Text.WordWrap
                                }
                            }

                            Item {
                                width: parent.width
                                height: 12

                                Data {
                                    anchors.left: parent.left
                                    anchors.verticalCenter: parent.verticalCenter
                                    font.pixelSize: 8
                                    color: Theme.shellInputBorder
                                    text: root.footerRight
                                }
                                // The keyboard legend, printed beside the
                                // source group: Esc is offered and it is
                                // explicitly non-destructive.
                                Data {
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    font.pixelSize: 8
                                    color: Theme.shellInputBorder
                                    visible: root.cards.length > 1 && card.hasFocus
                                    text: "↑↓ next · Esc keeps the card"
                                }
                            }
                        }
                    }
                }

                // More alerts than the stack draws. Counted honestly and
                // pointed at the register that holds all of them — never
                // silently truncated.
                Item {
                    width: parent.width
                    height: root.overflow > 0 ? 16 : 0
                    visible: root.overflow > 0

                    Data {
                        anchors.left: parent.left
                        anchors.verticalCenter: parent.verticalCenter
                        color: Theme.shellInputBorder
                        text: root.overflow + " more suspected · punarctl agents alerts"
                    }
                }
            }
        }
    }
}
