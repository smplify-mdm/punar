pragma ComponentBehavior: Bound
// Osd — the on-screen display for volume and brightness, implementing
// docs/design/mockups/notifications-osd.html Sect III (Plate D-009, the
// acceptance reference):
//
//     "Volume is a reading on a dial, not a fluid in a tube — twenty
//      discrete ticks, five percent each."
//
// TWENTY TICKS, FIVE PERCENT EACH, NO PARTIAL TICK. Lit ticks are
// `panel-fg`, unlit are `panel-edge`. There is no gradient, no rounded
// fill and no interpolation: the meter quantises to the same 5% step the
// volume keys move, so what the user sees is exactly the value the sink
// holds. The percentage beside it is Geist Mono, tabular, right-aligned,
// so it does not jitter while a key repeats.
//
// PANEL SURFACE (DESIGN_LANGUAGE.md §6 surface assignment). The OSD is one
// of the two surfaces that live on the dark system — it floats over
// anything, full-screen video included, and the near-black card holds
// contrast everywhere. NO STATUS COLOUR APPEARS: a level is a reading, not
// a judgment, and §2's rule is that a screen with no status to report
// contains no colour. At zero (or muted) the label reads MUTED in
// `panel-ink-3` — a state word, not a colour, because silence is not an
// error.
//
// IT APPEARS ONLY ON CHANGE, AND IT DOES NOT POLL TO FIND OUT. Volume is
// read from `Quickshell.Services.Pipewire`'s default sink, whose `volume`
// and `muted` properties are pushed by the pipewire event loop; the OSD
// raises on the property's own change signal. There is no timer sampling
// anything. The one timer in this file is the dwell timer, and it runs
// only while the OSD is on screen (spec 6.3 — idle CPU effectively zero).
//
// IT RENDERS WHAT THE SINK HOLDS, NOT WHAT SOMEBODY ASKED FOR. The volume
// keys in punar-binds.conf call wireplumber, and the OSD then draws the
// value pipewire actually settled on. A meter that echoed the request
// would keep reading 60% on a sink that refused to move; this one cannot
// lie, and it raises for a change made by any source — a key, a mixer, an
// application — because a change is a change.
//
// THE BRIGHTNESS ROW IS DASHED, AND THAT IS THE HONEST DRAWING
// (DESIGN_LANGUAGE.md §7 — a dashed stroke marks a mechanism outside the
// current production claim; spec 1.22). Punar ships no backlight
// capability: there is no typed `system.brightness`, no `punarctl` verb
// and, in the VM target, no physical backlight to move. So the row exists
// in the plate's anatomy, carries the plate's own `SIM · VM` tag on a
// dashed rule, and is reachable only by an explicit IPC call — it is never
// bound to a key, because a key that changes nothing is exactly the dead
// control spec 1.22 forbids. When a brightness capability ships, this row
// loses its dash and gains its binding; until then it says so out loud.
//
// Expected memory: two small panel cards on one transparent, click-through
// layer window, plus the pipewire client Quickshell already links. No
// image path, no model, no state file. It is the smallest of the three
// notification surfaces.
//
// Driven from a check script via Quickshell IPC:
//   qs -p /usr/share/punar/shell ipc call osd state
//   qs -p /usr/share/punar/shell ipc call osd brightness 60

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Services.Pipewire
import "../Theme"

Scope {
    id: root

    // "volume" | "brightness" | "" (nothing showing).
    property string showing: ""
    property bool windowVisible: false
    readonly property bool open: root.showing !== ""

    // D-009 Sect III register 01: twenty ticks, five percent each.
    readonly property int tickCount: 20

    // How long the reading stays up after the last change. Short, because
    // an OSD is an acknowledgement, not a notification — the record of
    // what the volume is lives in the volume itself.
    readonly property int dwellMs: 1400

    // ---- volume, from pipewire ----

    readonly property var sink: Pipewire.defaultAudioSink

    // Quickshell only streams property updates for objects a tracker binds.
    // Without this the sink's volume would be a snapshot from whenever the
    // node appeared, and the OSD would faithfully draw a stale number.
    PwObjectTracker {
        objects: (root.sink === null || root.sink === undefined) ? [] : [root.sink]
    }

    readonly property var sinkAudio: (root.sink === null || root.sink === undefined) ? null : root.sink.audio

    // True only when there is a real sink to read. With no audio server
    // there is no volume row at all — an OSD for a device that does not
    // exist is a control that does nothing.
    readonly property bool volumeAvailable: root.sinkAudio !== null && root.sinkAudio !== undefined

    readonly property bool muted: root.volumeAvailable && root.sinkAudio.muted === true

    // 0.0 – 1.0 as pipewire holds it, clamped: a sink configured to allow
    // over-amplification must not draw a twenty-first tick.
    readonly property real volume: root.volumeAvailable
        ? Math.max(0, Math.min(1, root.sinkAudio.volume)) : 0

    // ---- brightness (dashed · not shipped) ----

    // -1 until something sets it. Nothing in the image does, so on a stock
    // machine this row is never drawn at all.
    property real brightness: -1
    readonly property bool brightnessKnown: root.brightness >= 0

    // ---- raising ----
    //
    // ARMED AFTER FIRST READING. Binding to a live property fires once as
    // soon as the sink appears; raising the OSD then would flash a meter at
    // login for a change nobody made. The surface arms itself one shot
    // after the sink is first readable and only then treats a change as a
    // change.
    property bool armed: false

    function raise(which: string): void {
        root.showing = which;
        root.windowVisible = true;
        hideTimer.stop();
        dwellTimer.restart();
    }

    function hide(): void {
        if (root.showing === "")
            return;
        root.showing = "";
        dwellTimer.stop();
        hideTimer.restart(); // keep the window alive for the exit animation
    }

    function litTicks(value: real): int {
        return Math.round(Math.max(0, Math.min(1, value)) * root.tickCount);
    }

    function percentText(value: real): string {
        return String(Math.round(Math.max(0, Math.min(1, value)) * 100)) + "%";
    }

    onVolumeAvailableChanged: {
        if (!root.volumeAvailable) {
            root.armed = false;
            if (root.showing === "volume")
                root.hide();
            return;
        }
        armTimer.restart();
    }

    onVolumeChanged: {
        if (root.armed)
            root.raise("volume");
    }

    onMutedChanged: {
        if (root.armed)
            root.raise("volume");
    }

    // One shot, once per sink appearance: long enough for the initial
    // property sync to settle, then the surface starts believing changes.
    // Not a clock — it fires once and stops.
    Timer {
        id: armTimer

        interval: 900
        repeat: false
        onTriggered: root.armed = root.volumeAvailable
    }

    // The dwell timer. Runs ONLY while the OSD is on screen.
    Timer {
        id: dwellTimer

        interval: root.dwellMs
        repeat: false
        onTriggered: root.hide()
    }

    Timer {
        id: hideTimer

        interval: Theme.durStandard
        repeat: false
        onTriggered: {
            if (root.showing === "")
                root.windowVisible = false;
        }
    }

    //   qs -p /usr/share/punar/shell ipc call osd state
    IpcHandler {
        target: "osd"

        function state(): string {
            return root.showing === "" ? "closed" : root.showing;
        }

        // The value the SINK holds, as a whole percent, or "unavailable"
        // when there is no audio server to ask. Never a remembered value.
        function volume(): string {
            if (!root.volumeAvailable)
                return "unavailable";
            return root.muted ? "muted" : String(Math.round(root.volume * 100));
        }

        // Lit tick count — what the human can actually count on screen,
        // which is the thing a check script should assert.
        function ticks(): string {
            if (root.showing === "brightness")
                return String(root.litTicks(root.brightness));
            return String(root.muted ? 0 : root.litTicks(root.volume));
        }

        // Raise the volume reading without changing it (a check hook, and
        // the honest way to "show me the volume" without moving it).
        function show(): string {
            if (!root.volumeAvailable)
                return "unavailable";
            root.raise("volume");
            return "volume";
        }

        // The brightness row's ONLY driver. Punar ships no backlight
        // capability, so this sets a display value and nothing else — the
        // row draws itself dashed and says so.
        function brightness(percent: string): string {
            var v = Number(percent);
            if (isNaN(v))
                return "invalid";
            root.brightness = Math.max(0, Math.min(1, v / 100));
            root.raise("brightness");
            return String(Math.round(root.brightness * 100));
        }

        function close(): void {
            root.hide();
        }
    }

    // ---- panel type grammar (DESIGN_LANGUAGE.md §1 / §6) ----

    component PanelLabel: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.13)
        font.capitalization: Font.AllUppercase
        color: Theme.panelInk3
        textFormat: Text.PlainText
    }

    // A dashed hairline — the M7/M8 vocabulary, on the panel surface.
    component DashedRule: Canvas {
        id: dashedRule

        height: 2

        onPaint: {
            var ctx = getContext("2d");
            ctx.clearRect(0, 0, width, height);
            ctx.strokeStyle = String(Theme.panelInk3);
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.moveTo(0, 0.5);
            ctx.lineTo(width, 0.5);
            ctx.stroke();
        }
        onVisibleChanged: if (visible)
            dashedRule.requestPaint()
        onWidthChanged: dashedRule.requestPaint()
    }

    // The instrument itself (D-009 `.ticks`): discrete segments, never a
    // bar. `lit` is a count, not a fraction, so no tick is ever partly on.
    component TickMeter: Row {
        id: meter

        property int lit: 0
        property color onColor: Theme.panelFg
        property color offColor: Theme.panelEdge

        spacing: 3

        Repeater {
            model: root.tickCount

            Rectangle {
                id: tick

                required property int index

                width: 6
                height: 14
                radius: 1
                color: tick.index < meter.lit ? meter.onColor : meter.offColor

                // Motion explains the state change and nothing else: a
                // tick lights in the micro duration on the token curve.
                Behavior on color {
                    ColorAnimation {
                        duration: Theme.durMicro
                        easing.type: Easing.BezierSpline
                        easing.bezierCurve: Theme.easingCurve
                    }
                }
            }
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

        // The OSD never takes a click and never takes the keyboard: it is
        // an acknowledgement of something the human already did. An empty
        // mask makes the whole surface click-through.
        mask: Region {
        }
        exclusionMode: ExclusionMode.Ignore
        color: "transparent"
        WlrLayershell.namespace: "punar-osd"
        WlrLayershell.layer: WlrLayer.Overlay
        WlrLayershell.keyboardFocus: WlrKeyboardFocus.None

        Column {
            id: osdStack

            anchors.horizontalCenter: parent.horizontalCenter
            // D-009 floats the OSD low on the output, clear of the toast
            // stack in the opposite corner.
            y: parent.height - height - Math.max(48, Math.round(parent.height * 0.12))
            spacing: 10
            opacity: root.open ? 1 : 0

            Behavior on opacity {
                NumberAnimation {
                    duration: Theme.durStandard
                    easing.type: Easing.BezierSpline
                    easing.bezierCurve: Theme.easingCurve
                }
            }

            // ---- volume (D-009 `.osd`) ----
            Rectangle {
                id: volumeCard

                visible: root.showing === "volume"
                width: volumeRow.implicitWidth + 36
                height: 56
                radius: Theme.radius
                color: Theme.panelSurface
                border.width: Theme.hairline
                border.color: Theme.panelEdge

                Row {
                    id: volumeRow

                    anchors.centerIn: parent
                    spacing: 14

                    PanelLabel {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 74
                        // MUTED is a state word in panel-ink-3, never a
                        // colour: silence is not an error.
                        color: root.muted ? Theme.panelInk3 : Theme.panelFg
                        text: root.muted ? "Muted" : "Volume"
                    }

                    TickMeter {
                        anchors.verticalCenter: parent.verticalCenter
                        lit: root.muted ? 0 : root.litTicks(root.volume)
                    }

                    // Tabular mono, right-aligned so the digits do not
                    // jitter while a key repeats.
                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 44
                        horizontalAlignment: Text.AlignRight
                        font.family: Theme.fontMono
                        font.pixelSize: 12
                        font.weight: 500
                        // Geist Mono is inherently tabular (the Bar/
                        // ApprovalOverlay precedent) — the digits hold
                        // their column without a feature override.
                        color: root.muted ? Theme.panelInk3 : Theme.panelFg
                        text: root.percentText(root.volume)
                        textFormat: Text.PlainText
                    }
                }
            }

            // ---- brightness · DASHED, not shipped (§7) ----
            Rectangle {
                id: brightnessCard

                visible: root.showing === "brightness" && root.brightnessKnown
                width: brightnessRow.implicitWidth + 36
                height: 68
                radius: Theme.radius
                color: Theme.panelSurface
                // The card's own edge stays a hairline; the dashed rule
                // beneath the label carries the claim, exactly as the AI
                // panel's unobserved ledger rows do.
                border.width: Theme.hairline
                border.color: Theme.panelEdge

                Row {
                    id: brightnessRow

                    anchors.centerIn: parent
                    spacing: 14

                    Column {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 74
                        spacing: 4

                        PanelLabel {
                            color: Theme.panelInk3
                            text: "Brightness"
                        }

                        DashedRule {
                            width: 74
                        }

                        PanelLabel {
                            font.pixelSize: 8
                            color: Theme.panelInk3
                            // The plate's own tag, and the reason for it.
                            text: "Sim · VM"
                        }
                    }

                    TickMeter {
                        anchors.verticalCenter: parent.verticalCenter
                        lit: root.litTicks(root.brightness)
                        onColor: Theme.panelInk3 // dashed voice: never the full-strength reading
                    }

                    Text {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 44
                        horizontalAlignment: Text.AlignRight
                        font.family: Theme.fontMono
                        font.pixelSize: 12
                        font.weight: 500
                        // Geist Mono is inherently tabular (the Bar/
                        // ApprovalOverlay precedent) — the digits hold
                        // their column without a feature override.
                        color: Theme.panelInk3
                        text: root.percentText(root.brightness)
                        textFormat: Text.PlainText
                    }
                }
            }

            // The claim register, in one line, under whichever card is up:
            // what this instrument is, and what it is not.
            Item {
                width: osdStack.width
                height: 14

                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    font.family: Theme.fontMono
                    font.pixelSize: 8
                    font.weight: 500
                    font.letterSpacing: Theme.tracking(8, 0.1)
                    color: Theme.panelInk3
                    textFormat: Text.PlainText
                    text: root.showing === "brightness"
                        ? "No backlight capability ships · this reading is simulated"
                        : "20 ticks · 5% each · the value the sink holds"
                }
            }
        }
    }
}
