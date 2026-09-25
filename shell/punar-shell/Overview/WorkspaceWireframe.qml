pragma ComponentBehavior: Bound
// WorkspaceWireframe — one workspace's real window layout as a mini plate,
// scaled from each client's own at/size (Plate D-007's `.mini`). The project
// overview (PUNAR+Tab) draws one per workspace card; the window switcher
// (Alt+Tab, SMP-1405 WP-02) draws the chosen window's workspace with that
// window ruled in ink, so both surfaces show the same live geometry and
// neither keeps a second model of it.
//
// Live: it binds to the Quickshell.Hyprland workspace's toplevels, which
// socket2 events keep current, and draws nothing it did not read. An empty
// workspace is a dashed outline (the honesty grammar: dashed = not real yet).

import QtQuick
import "../Theme"

Item {
    id: mini

    // A Quickshell.Hyprland workspace, or null.
    property var workspace: null
    // "0x…" of a window to rule in ink; "" rules none.
    property string highlightAddress: ""

    readonly property var toplevels: mini.workspace === null || mini.workspace === undefined
        ? [] : mini.workspace.toplevels.values
    readonly property bool empty: mini.toplevels.length === 0
    // Wireframe inset (mockup .mini padding 5).
    readonly property real pad: 5

    // Normalize a client's global at/size to 0..1 of its monitor's logical
    // space.
    function normGeo(ipc: var): var {
        if (!ipc || ipc.at === undefined || ipc.size === undefined)
            return null;
        var mon = mini.workspace === null || mini.workspace === undefined ? null : mini.workspace.monitor;
        var s = mon && mon.scale > 0 ? mon.scale : 1;
        var mx = mon ? mon.x : 0;
        var my = mon ? mon.y : 0;
        var mw = mon && mon.width > 0 ? mon.width / s : 1920;
        var mh = mon && mon.height > 0 ? mon.height / s : 1080;
        var x = (ipc.at[0] - mx) / mw;
        var y = (ipc.at[1] - my) / mh;
        var w = ipc.size[0] / mw;
        var h = ipc.size[1] / mh;
        return {
            x: Math.max(0, Math.min(1, x)),
            y: Math.max(0, Math.min(1, y)),
            w: Math.max(0.04, Math.min(1, w)),
            h: Math.max(0.04, Math.min(1, h))
        };
    }

    // Occupied: solid mini with the real layout.
    Rectangle {
        anchors.fill: parent
        visible: !mini.empty
        color: Theme.shellMuted
        border.width: Theme.hairline
        border.color: Theme.shellBorder
        radius: Theme.radiusTag
        clip: true

        Repeater {
            model: mini.empty ? [] : mini.toplevels

            delegate: Rectangle {
                id: mw

                required property var modelData

                readonly property var ipc: mw.modelData.lastIpcObject
                readonly property var geo: mini.normGeo(mw.ipc)
                readonly property bool floats: mw.ipc && mw.ipc.floating === true
                readonly property bool inGroup: mw.ipc && Array.isArray(mw.ipc.grouped)
                                                && mw.ipc.grouped.length > 1
                readonly property bool chosen: mini.highlightAddress !== ""
                                               && mw.ipc && mw.ipc.address === mini.highlightAddress

                visible: mw.geo !== null
                x: mini.pad + (mw.geo ? mw.geo.x : 0) * (mini.width - 2 * mini.pad)
                y: mini.pad + (mw.geo ? mw.geo.y : 0) * (mini.height - 2 * mini.pad)
                width: (mw.geo ? mw.geo.w : 0) * (mini.width - 2 * mini.pad)
                height: (mw.geo ? mw.geo.h : 0) * (mini.height - 2 * mini.pad)
                radius: 3
                color: mw.chosen ? Theme.raise2 : Theme.shellSurface
                border.width: mw.chosen ? 2 : Theme.hairline
                // A float must read as a float even in wireframe; the chosen
                // window reads as chosen above everything.
                border.color: mw.chosen ? Theme.shellFg : (mw.floats ? Theme.shellInputBorder : Theme.shellBorder)
                z: mw.chosen ? 3 : (mw.floats ? 2 : 1)

                // Group slab tab notch (stacked windows share geometry; the
                // notch says so).
                Rectangle {
                    visible: mw.inGroup
                    anchors.top: parent.top
                    anchors.left: parent.left
                    anchors.topMargin: 2
                    anchors.leftMargin: 2
                    width: Math.min(12, parent.width / 3)
                    height: 3
                    radius: 1
                    color: Theme.shellInputBorder
                }
            }
        }
    }

    // Empty: dashed outline — the honesty grammar (dashed = not real yet).
    Canvas {
        anchors.fill: parent
        visible: mini.empty
        onPaint: {
            var ctx = getContext("2d");
            ctx.clearRect(0, 0, width, height);
            ctx.strokeStyle = String(Theme.shellInputBorder);
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.beginPath();
            ctx.roundedRect(0.5, 0.5, width - 1, height - 1, Theme.radiusTag, Theme.radiusTag);
            ctx.stroke();
        }
        onVisibleChanged: if (visible)
            requestPaint()
        onWidthChanged: requestPaint()
        onHeightChanged: requestPaint()
    }

    Text {
        anchors.centerIn: parent
        visible: mini.empty
        font.family: Theme.fontMono
        font.pixelSize: 8
        font.weight: 500
        font.letterSpacing: Theme.tracking(8, 0.14)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        text: "No windows"
    }
}
