pragma ComponentBehavior: Bound
// ToastStack — the transient notification surface, implementing
// docs/design/mockups/notifications-osd.html Sect I (Plate D-009, the
// acceptance reference): a stacked column at top-right whose every card
// is the same drawing —
//
//     meta row · hairline · one sentence · detail · actions
//
// and whose calm variant carries no colour at all, because "a screen with
// no status to report contains no colour" (DESIGN_LANGUAGE.md §2).
//
// THIS SURFACE DRAWS FREEDESKTOP NOTIFICATIONS AND NOTHING ELSE. The M10
// shadow-AI alert region (Alert/AlertStack) and the M9 approval gate
// (Approval/ApprovalOverlay) are separate surfaces owned by separate
// records; this file never re-draws either of them. That is not tidiness,
// it is the mute rule: do-not-disturb silences what THIS surface shows,
// and the two surfaces it does not own are the breakthroughs D-009
// promises (Sect II register 03).
//
// IT NEVER STEALS THE KEYBOARD, AND SO IT NEVER PRINTS A KEY IT CANNOT
// HONOUR. A gate may take the keyboard because something is waiting on
// the human; an alert may, because the machine has found something. An
// ordinary application toast may not — a toast that swallows the next
// keystroke while someone is typing is a defect, not a feature. The layer
// surface therefore uses `WlrKeyboardFocus.OnDemand`: it can be focused
// by clicking it, and it never grabs. Consequently the printed key hints
// (`X`, `Esc`, `1`..`9`) appear ONLY while the stack actually holds the
// keyboard — spec 1.22 applied to a keycap: an unfocused toast shows the
// same actions as real, clickable buttons, without claiming a key that
// would not fire. The guaranteed keyboard path is the centre
// (`PUNAR+SHIFT+N`), whose footer prints every key it owns.
//
// DISMISS FILES, IT NEVER DESTROYS (D-009 Sect I register 03). Dismissing
// a toast — by key, by click, or by its dwell timer running out — removes
// it from THIS surface only. The record stays tracked and stays in the
// centre until the human clears it there or the sending application
// closes it. Nothing said to the user is ever discarded by a timeout.
//
// TIMERS (spec 6.3, PERFORMANCE_BUDGETS.md): one dwell timer per VISIBLE
// toast, running only while that toast is on screen, plus one shared
// exit-animation timer. With an empty stack this file holds no running
// timer at all, so the idle cost of having a notification daemon is zero.
//
// Expected memory: the surface allocates one small paper card per visible
// toast (at most `maxToasts` = 3) over a fully transparent, click-through
// layer window; there is no image decoding path (the daemon declares
// `imageSupported: false`) and no scrollable model. It is the cheapest of
// the three notification surfaces and adds no measurable resident cost to
// the shell beyond the records themselves.
//
// Driven from Hyprland or a check script via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call toasts state

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import "../Theme"
import "../Services"

Scope {
    id: root

    // FORCE THE DAEMON UP AT STARTUP. QML singletons are lazy, and
    // Services/Notifications.qml is not merely a store — it BINDS
    // org.freedesktop.Notifications. A notification server that comes
    // into existence the first time a surface happens to read a property
    // is a server that missed the session's first notifications, and the
    // failure is silent, which is the one thing spec §1.22 forbids.
    //
    // The `Connections { target: Notifications }` below does instantiate
    // it as a side effect, but a side effect is not a guarantee: delete
    // that block and the daemon quietly stops existing. This line states
    // the requirement in code. It is idempotent and costs one no-op call.
    Component.onCompleted: Notifications.init()

    // Keys of the notifications currently drawn, newest first.
    property var shownKeys: []

    property bool windowVisible: false
    readonly property bool open: root.shownKeys.length > 0

    // Whether this surface currently holds the keyboard. Only a click can
    // set it; nothing else may (see the header).
    property bool holdsKeyboard: false

    property string focusedKey: ""

    // D-009's stack is a short column, not a scroller. Three is the
    // plate's density; everything beyond it is already in the centre, and
    // the overflow line says so rather than silently truncating.
    readonly property int maxToasts: 3

    // Asks the notification centre to open — wired in shell.qml, the
    // AlertStack.onInspectRequested precedent, so this surface never
    // reaches into another one directly.
    signal centerRequested

    readonly property var toasts: {
        var out = [];
        for (var i = 0; i < root.shownKeys.length; i++) {
            var n = Notifications.byKey(root.shownKeys[i]);
            if (n !== null)
                out.push(n);
        }
        return out;
    }

    // ---- shared type grammar (DESIGN_LANGUAGE.md §1) ----

    // Meta / label register: mono, tracked, uppercase. The system voice.
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
    // evidence rather than labels — a path, a filename, an id. The meta
    // grammar uppercases labels, never evidence.
    component Data: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 500
        font.letterSpacing: Theme.tracking(9, 0.1)
        color: Theme.shellInk3
        textFormat: Text.PlainText
    }

    // An action button carrying its key hint. The keycap renders only when
    // the stack holds the keyboard, because a printed key that does not
    // fire is a lie (spec 1.22).
    component ActionButton: Rectangle {
        id: button

        property string label: ""
        property string binding: ""
        property bool filled: false
        property bool showBinding: false
        property color tone: Theme.shellFg

        signal activated

        implicitWidth: buttonRow.implicitWidth + 20
        implicitHeight: buttonRow.implicitHeight + 11
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
                visible: button.showBinding && button.binding !== ""
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

    // ---- stack state ----

    function indexOfKey(k: string): int {
        for (var i = 0; i < root.shownKeys.length; i++) {
            if (root.shownKeys[i] === k)
                return i;
        }
        return -1;
    }

    // Raise a toast. Called only from Notifications.arrived — never from a
    // rebuild of the model, so a record that closes and re-enters the list
    // for any reason cannot re-toast itself.
    function raise(k: string): void {
        if (k === "" || root.indexOfKey(k) >= 0)
            return;
        // QUIET IS QUIET, FOR EVERY URGENCY. `Critical` is asserted by the
        // sending application; letting it defeat the user's own switch
        // would make do-not-disturb advisory. The record is already in the
        // centre — nothing is lost, only the interruption.
        if (Notifications.dnd)
            return;
        var next = [k];
        for (var i = 0; i < root.shownKeys.length && next.length < root.maxToasts; i++)
            next.push(root.shownKeys[i]);
        root.shownKeys = next;
        root.focusedKey = k;
        root.windowVisible = true;
        hideTimer.stop();
    }

    // Remove one toast from THIS surface. The record is untouched: it is
    // still tracked, still grouped, still in the centre.
    function file(k: string): void {
        var at = root.indexOfKey(k);
        if (at < 0)
            return;
        var next = [];
        for (var i = 0; i < root.shownKeys.length; i++) {
            if (i !== at)
                next.push(root.shownKeys[i]);
        }
        root.shownKeys = next;
        if (root.focusedKey === k)
            root.focusedKey = next.length > 0 ? next[0] : "";
        if (next.length === 0) {
            root.holdsKeyboard = false;
            hideTimer.restart(); // keep the window alive for the exit animation
        }
    }

    function fileAll(): void {
        root.shownKeys = [];
        root.focusedKey = "";
        root.holdsKeyboard = false;
        hideTimer.restart();
    }

    function moveFocus(delta: int): void {
        if (root.shownKeys.length === 0)
            return;
        var at = root.indexOfKey(root.focusedKey);
        at = (at < 0 ? 0 : at) + delta;
        at = Math.max(0, Math.min(root.shownKeys.length - 1, at));
        root.focusedKey = root.shownKeys[at];
    }

    // Invoke the nth action (1-based) of the focused toast, then file it —
    // the human has answered, so the interruption is over either way.
    function invokeNth(n: int): void {
        var record = Notifications.byKey(root.focusedKey);
        if (record === null)
            return;
        var acts = Notifications.actionsOf(record);
        if (n < 1 || n > acts.length)
            return;
        var k = root.focusedKey;
        Notifications.invokeAction(acts[n - 1]);
        root.file(k);
    }

    // Drop toasts whose record has closed underneath us (the application
    // withdrew it, or the human cleared it in the centre). Event-driven:
    // this runs on the model's own change signal, never on a tick.
    function prune(): void {
        var next = [];
        for (var i = 0; i < root.shownKeys.length; i++) {
            if (Notifications.byKey(root.shownKeys[i]) !== null)
                next.push(root.shownKeys[i]);
        }
        if (next.length === root.shownKeys.length)
            return;
        root.shownKeys = next;
        if (root.indexOfKey(root.focusedKey) < 0)
            root.focusedKey = next.length > 0 ? next[0] : "";
        if (next.length === 0) {
            root.holdsKeyboard = false;
            hideTimer.restart();
        }
    }

    Connections {
        target: Notifications

        function onArrived(key: string): void {
            root.raise(key);
        }

        function onTrackedChanged(): void {
            root.prune();
        }

        // Turning quiet ON clears the screen immediately: the switch is
        // about interruptions, and an interruption already on screen is
        // still an interruption. Nothing is discarded — every cleared card
        // is in the centre.
        function onDndChanged(): void {
            if (Notifications.dnd)
                root.fileAll();
        }

        // The centre is open: the human is reading the record, so the
        // transient copies step aside rather than stacking in front of it.
        function onCentreOpened(): void {
            root.fileAll();
        }
    }

    // Read-only probes plus the two verbs a check script needs. The
    // `alerts` / `approval` / `aipanel` precedent: a check must be able to
    // assert what the human was shown without a screenshot being the only
    // evidence.
    //
    //   qs -p /usr/share/punar/shell ipc call toasts state
    IpcHandler {
        target: "toasts"

        function state(): string {
            return root.open ? "open" : "closed";
        }

        // The keys currently on screen, newest first.
        function list(): string {
            return root.shownKeys.join(",");
        }

        function focused(): string {
            return root.focusedKey;
        }

        // Files the focused toast to the centre. Destroys nothing.
        function dismiss(): string {
            var k = root.focusedKey;
            root.file(k);
            return k;
        }

        // Files every toast to the centre.
        function dismissAll(): string {
            var n = root.shownKeys.length;
            root.fileAll();
            return String(n);
        }
    }

    // The only shared timer, and it is not a clock: it keeps the window
    // alive for the 300 ms exit animation and then stops.
    Timer {
        id: hideTimer

        interval: Theme.durStandard
        repeat: false
        onTriggered: {
            if (root.shownKeys.length === 0)
                root.windowVisible = false;
        }
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
        // — the rest of the desktop keeps its clicks. A toast blocks
        // nothing, because nothing is waiting on it.
        mask: Region {
            item: stack
        }
        exclusionMode: ExclusionMode.Ignore
        color: "transparent" // the cards own every visible pixel
        WlrLayershell.namespace: "punar-toasts"
        WlrLayershell.layer: WlrLayer.Overlay
        // NEVER Exclusive. OnDemand lets a click focus the stack so the
        // printed keys become real; without a click the keyboard belongs
        // to whatever the human is actually using.
        WlrLayershell.keyboardFocus: WlrKeyboardFocus.OnDemand

        Connections {
            target: root

            function onHoldsKeyboardChanged(): void {
                if (root.holdsKeyboard)
                    toastKeys.forceActiveFocus();
            }
        }

        FocusScope {
            id: toastKeys

            anchors.fill: parent
            focus: true

            Keys.onPressed: function (event) {
                if (!root.holdsKeyboard)
                    return;
                if (event.key >= Qt.Key_1 && event.key <= Qt.Key_9) {
                    root.invokeNth(event.key - Qt.Key_0);
                    event.accepted = true;
                    return;
                }
                switch (event.key) {
                case Qt.Key_X:
                    root.file(root.focusedKey);
                    event.accepted = true;
                    break;
                case Qt.Key_N:
                    root.centerRequested();
                    root.fileAll();
                    event.accepted = true;
                    break;
                case Qt.Key_Escape:
                    // Hands the keyboard back WITHOUT touching the cards.
                    // Esc ignores nothing silently: the toasts stay, their
                    // dwell timers keep running, the records stay.
                    root.holdsKeyboard = false;
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
            // stack clears the 30 px bar and its gutter on a short display,
            // and the right inset at 20 px for the same reason. Identical
            // geometry to Alert/AlertStack, so the two surfaces never
            // disagree about where an interruption lives.
            Column {
                id: stack

                anchors.right: parent.right
                anchors.rightMargin: Math.max(20, Math.round(toastKeys.width * 0.034))
                y: Math.max(44, Math.round(toastKeys.height * 0.13))
                width: Math.min(340, Math.round(toastKeys.width * 0.46))
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
                    model: root.toasts

                    // ---- the toast card (D-009 `.toast`) ----
                    Rectangle {
                        id: card

                        required property var modelData

                        readonly property string cardKey: Notifications.key(card.modelData)
                        readonly property bool hasFocus: root.holdsKeyboard && card.cardKey === root.focusedKey
                        readonly property string urgency: Notifications.urgencyOf(card.modelData)
                        readonly property var acts: Notifications.actionsOf(card.modelData)
                        readonly property string detail: Notifications.detailOf(card.modelData)

                        // NO COLOUR ON THIS CARD, IN EITHER VOICE. §2
                        // binds red/amber/green 1:1 to policy decisions and
                        // compliance states; an application's `Critical`
                        // urgency is a delivery hint it asserts about
                        // itself, not a judgment Punar has made, and
                        // spending the bad tone on it would teach the user
                        // that red sometimes means "an app was insistent".
                        // The loud variant is drawn LOUDER instead — ink
                        // meta row, ink rule, no auto-dismiss — and says
                        // the word CRITICAL, exactly as the OSD says MUTED:
                        // a state word, not a colour.
                        readonly property color tone: Theme.shellInk3

                        width: stack.width
                        implicitHeight: body.implicitHeight + 24
                        height: card.implicitHeight
                        color: Theme.shellSurface
                        radius: Theme.radius
                        // The focused card wears the 2 px ring (§9.4,
                        // colour-independent). The plate's soft drop
                        // shadow is omitted deliberately — the standing
                        // M1/M2 llvmpipe deviation.
                        border.width: card.hasFocus ? 2 : Theme.hairline
                        border.color: card.hasFocus ? Theme.shellFg : Theme.shellBorder

                        // The dwell timer. Runs ONLY while this card is on
                        // screen; a sticky card never starts one at all.
                        // When it fires the card is FILED to the centre —
                        // never closed, never destroyed.
                        Timer {
                            interval: Notifications.dwellMs(card.modelData)
                            repeat: false
                            running: root.open && !Notifications.sticky(card.modelData) && !card.hasFocus
                            onTriggered: root.file(card.cardKey)
                        }

                        MouseArea {
                            anchors.fill: parent
                            onClicked: {
                                root.focusedKey = card.cardKey;
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
                                height: Math.max(13, metaLeft.implicitHeight)

                                Meta {
                                    id: metaLeft

                                    anchors.left: parent.left
                                    anchors.right: metaRight.left
                                    anchors.rightMargin: 10
                                    anchors.verticalCenter: parent.verticalCenter
                                    color: Theme.shellFg
                                    elide: Text.ElideRight
                                    text: Notifications.sourceOf(card.modelData)
                                          + (card.urgency === "critical" ? " · Critical" : "")
                                }

                                Meta {
                                    id: metaRight

                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    color: card.tone
                                    // No stamp, no printed time — never a
                                    // manufactured one (spec 1.22).
                                    text: Notifications.timeOf(card.modelData)
                                }
                            }

                            Item {
                                width: parent.width
                                height: 8
                            }

                            // ---- hairline (D-009 `.trule`) ----
                            //
                            // Ink for a card that carries a status claim,
                            // border-hairline for the calm variant: "a
                            // hairline rule instead of ink" is the plate's
                            // own distinction between the two voices.
                            Rectangle {
                                width: parent.width
                                height: Theme.hairline
                                color: card.urgency === "critical" ? Theme.shellFg : Theme.shellBorder
                            }

                            Item {
                                width: parent.width
                                height: 9
                            }

                            // ---- THE one sentence (D-009 `.tsent`) ----
                            Text {
                                width: parent.width
                                text: Notifications.sentenceOf(card.modelData)
                                font.family: Theme.fontSans
                                font.pixelSize: 13
                                font.weight: 500
                                lineHeight: 1.45
                                color: Theme.shellFg
                                wrapMode: Text.WordWrap
                                maximumLineCount: 2
                                elide: Text.ElideRight
                                textFormat: Text.PlainText
                            }

                            Item {
                                width: parent.width
                                height: card.detail === "" ? 0 : 6
                                visible: card.detail !== ""
                            }

                            // ---- detail (the sender's body) ----
                            //
                            // Two lines at most: "if it needs two
                            // sentences it isn't a toast — it opens a
                            // surface", and the surface it opens is the
                            // centre, which wraps the body in full.
                            Data {
                                width: parent.width
                                visible: card.detail !== ""
                                text: card.detail
                                color: Theme.shellInk2
                                wrapMode: Text.WordWrap
                                maximumLineCount: 2
                                elide: Text.ElideRight
                            }

                            Item {
                                width: parent.width
                                height: card.acts.length > 0 ? 11 : 0
                                visible: card.acts.length > 0
                            }

                            // ---- actions (D-009 `.tacts`) ----
                            Flow {
                                width: parent.width
                                visible: card.acts.length > 0
                                spacing: 8

                                Repeater {
                                    model: card.acts

                                    ActionButton {
                                        id: actionButton

                                        required property var modelData
                                        required property int index

                                        label: {
                                            var t = actionButton.modelData.text;
                                            return (typeof t === "string" && t !== "") ? t : actionButton.modelData.identifier;
                                        }
                                        binding: String(actionButton.index + 1)
                                        showBinding: card.hasFocus
                                        // At most ONE filled button per
                                        // surface (§2 action colour): the
                                        // first action is the affirmative
                                        // one, every other goes ghost.
                                        filled: actionButton.index === 0
                                        tone: actionButton.index === 0 ? Theme.shellFg : Theme.shellInk3
                                        onActivated: {
                                            root.focusedKey = card.cardKey;
                                            root.invokeNth(actionButton.index + 1);
                                        }
                                    }
                                }
                            }

                            Item {
                                width: parent.width
                                height: 10
                            }

                            // ---- footer: the way out ----
                            Item {
                                width: parent.width
                                height: 12

                                Data {
                                    anchors.left: parent.left
                                    anchors.verticalCenter: parent.verticalCenter
                                    font.pixelSize: 8
                                    color: Theme.shellInputBorder
                                    // The keys are printed only while they
                                    // fire. Unfocused, the card states the
                                    // one thing that is always true: this
                                    // is filed, not lost.
                                    text: card.hasFocus
                                        ? "X files to centre · N opens centre · Esc keeps the card"
                                        : "Kept in the notification centre"
                                }

                                Data {
                                    anchors.right: parent.right
                                    anchors.verticalCenter: parent.verticalCenter
                                    font.pixelSize: 8
                                    color: Theme.shellInputBorder
                                    visible: !card.hasFocus
                                    text: "Punar+Shift+N"
                                }
                            }
                        }
                    }
                }

                // More waiting than the stack draws. Counted honestly and
                // pointed at the surface that holds all of it — never
                // silently truncated. (D-009's `.waitchip`.)
                Item {
                    width: parent.width
                    height: stackOverflow.visible ? 16 : 0

                    Data {
                        id: stackOverflow

                        anchors.right: parent.right
                        anchors.verticalCenter: parent.verticalCenter
                        color: Theme.shellInputBorder
                        visible: Notifications.count > root.shownKeys.length
                        text: (Notifications.count - root.shownKeys.length)
                              + " waiting in the centre · Punar+Shift+N"
                    }
                }
            }
        }
    }
}
