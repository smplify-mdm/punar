pragma ComponentBehavior: Bound
// AppInstallCard — one catalog identity after punard has inspected its exact
// architecture source. Security words come only from verified daemon output;
// the image catalog supplies identity and disclosure copy, never containment.

import QtQuick
import "../Theme"

Item {
    id: root

    // "loading" · "ready" · "installing" · "opening" · "failed"
    property string phase: "loading"
    property var record: null
    property string failure: ""
    signal actionRequested()

    readonly property bool ready: root.phase === "ready"
    readonly property bool nativeSource: root.record !== null && root.record.source === "flatpak"
    readonly property bool webSource: root.record !== null && root.record.source === "web"
    readonly property bool installed: root.record !== null && root.record.installed === true
    readonly property var inspection: root.record !== null && root.record.inspection ? root.record.inspection : null
    readonly property bool verified: root.inspection !== null && root.inspection.verified === true
    readonly property string containment: root.verified ? String(root.inspection.containment || "unknown") : ""
    readonly property var permissions: root.verified && Array.isArray(root.inspection.permissions) ? root.inspection.permissions : []
    readonly property var disclosures: root.record !== null && Array.isArray(root.record.disclosures) ? root.record.disclosures : []

    implicitHeight: Math.min(320, content.implicitHeight + 28)

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.12)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
        wrapMode: Text.WordWrap
    }

    Flickable {
        anchors.fill: parent
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        anchors.topMargin: 14
        anchors.bottomMargin: 14
        contentHeight: content.implicitHeight
        clip: true
        interactive: contentHeight > height
        boundsBehavior: Flickable.StopAtBounds

        Column {
            id: content
            width: parent.width
            spacing: 7

            Text {
                width: parent.width
                wrapMode: Text.WordWrap
                font.family: Theme.fontSans
                font.pixelSize: 17
                font.weight: 550
                color: Theme.shellFg
                text: {
                    if (root.phase === "loading")
                        return "Checking the exact package and permissions…";
                    if (root.phase === "failed")
                        return "This application could not be prepared.";
                    if (root.record === null)
                        return "Application";
                    return String(root.record.name);
                }
            }

            Text {
                width: parent.width
                visible: text !== ""
                wrapMode: Text.WordWrap
                font.family: Theme.fontSans
                font.pixelSize: 13
                font.weight: 400
                lineHeight: 1.25
                lineHeightMode: Text.ProportionalHeight
                color: Theme.shellInk2
                text: root.phase === "failed" ? root.failure : (root.record !== null ? String(root.record.summary || "") : "")
            }

            Row {
                spacing: 6
                visible: root.record !== null

                Rectangle {
                    width: sourceMeta.implicitWidth + 16
                    height: sourceMeta.implicitHeight + 8
                    radius: Theme.radiusTag
                    color: Theme.shellSurface
                    border.width: Theme.hairline
                    border.color: Theme.shellBorder
                    Meta {
                        id: sourceMeta
                        anchors.centerIn: parent
                        text: root.webSource ? "Web app · browser" : "Flatpak · native"
                    }
                }

                Rectangle {
                    width: trustMeta.implicitWidth + 16
                    height: trustMeta.implicitHeight + 8
                    radius: Theme.radiusTag
                    color: Theme.shellSurface
                    border.width: Theme.hairline
                    border.color: root.record !== null && root.record.trust_tier === "community" ? Theme.shellStatusWarn : Theme.shellBorder
                    Meta {
                        id: trustMeta
                        anchors.centerIn: parent
                        color: root.record !== null && root.record.trust_tier === "community" ? Theme.shellStatusWarn : Theme.shellInk3
                        text: root.record !== null ? String(root.record.trust_tier || "unknown") : ""
                    }
                }

                Rectangle {
                    visible: root.nativeSource && root.verified
                    width: containmentMeta.implicitWidth + 16
                    height: containmentMeta.implicitHeight + 8
                    radius: Theme.radiusTag
                    color: Theme.shellSurface
                    border.width: Theme.hairline
                    border.color: root.containment === "sandboxed" ? Theme.shellBorder : Theme.shellStatusBad
                    Meta {
                        id: containmentMeta
                        anchors.centerIn: parent
                        color: root.containment === "sandboxed" ? Theme.shellInk3 : Theme.shellStatusBad
                        text: root.containment
                    }
                }
            }

            Meta {
                width: parent.width
                visible: root.nativeSource && root.verified
                text: "Permissions · verified metadata"
                topPadding: 2
            }

            Repeater {
                model: root.permissions
                delegate: Text {
                    required property var modelData
                    width: content.width
                    font.family: Theme.fontSans
                    font.pixelSize: 12
                    font.weight: 400
                    color: Theme.shellInk2
                    text: "· " + String(modelData)
                }
            }

            Repeater {
                model: root.disclosures
                delegate: Meta {
                    required property var modelData
                    width: content.width
                    color: Theme.shellStatusWarn
                    text: modelData && modelData.text ? String(modelData.text) : ""
                }
            }

            Rectangle {
                width: actionLabel.implicitWidth + 24
                height: actionLabel.implicitHeight + 13
                radius: Theme.radiusTag
                color: root.ready ? Theme.shellFg : Theme.shellSurface
                border.width: Theme.hairline
                border.color: root.phase === "failed" ? Theme.shellStatusBad : Theme.shellFg
                Meta {
                    id: actionLabel
                    anchors.centerIn: parent
                    color: root.ready ? Theme.shellSurface : (root.phase === "failed" ? Theme.shellStatusBad : Theme.shellInk3)
                    text: {
                        if (root.phase === "loading")
                            return "Checking…";
                        if (root.phase === "installing")
                            return "Installing…";
                        if (root.phase === "opening")
                            return "Opening…";
                        if (root.phase === "failed")
                            return "Try again ↵";
                        if (root.webSource)
                            return "Open web app ↵";
                        if (root.installed)
                            return "Open ↵";
                        return "Install ↵";
                    }
                }

                MouseArea {
                    anchors.fill: parent
                    enabled: root.ready || root.phase === "failed"
                    cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                    onClicked: root.actionRequested()
                }
            }
        }
    }
}
