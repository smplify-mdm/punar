pragma ComponentBehavior: Bound
// AppInstallCard — one catalog identity after punard has inspected its exact
// architecture source. Security words come only from verified daemon output;
// the image catalog supplies identity and disclosure copy, never containment.

import QtQuick
import "../Theme"

Item {
    id: root

    // "loading" · "ready" · "installing" · "removing" · "opening" · "failed"
    property string phase: "loading"
    property var record: null
    property string iconSource: ""
    property string failure: ""
    property bool removalArmed: false
    signal actionRequested()
    signal removeRequested()
    signal cancelRemoveRequested()

    readonly property bool ready: root.phase === "ready"
    readonly property bool nativeSource: root.record !== null && (root.record.source === "flatpak" || root.record.source === "vendor_deb")
    readonly property bool vendorSource: root.record !== null && root.record.source === "vendor_deb"
    readonly property bool webSource: root.record !== null && root.record.source === "web"
    readonly property bool installed: root.record !== null && root.record.installed === true
    readonly property var inspection: root.record !== null && root.record.inspection ? root.record.inspection : null
    readonly property bool verified: root.inspection !== null && (root.inspection.verified === true || (root.inspection.pinned === true && root.inspection.verified_on_install === true))
    readonly property string containment: root.verified ? String(root.inspection.containment || "unknown") : ""
    readonly property var permissions: root.verified && Array.isArray(root.inspection.permissions) ? root.inspection.permissions : []
    readonly property var disclosures: root.record !== null && Array.isArray(root.record.disclosures) ? root.record.disclosures : []

    // The action is deliberately outside the scrolling permission body. A
    // long native permission set must never push Install/Open below the
    // panel edge or leave Enter acting on an invisible control.
    implicitHeight: Math.min(380, content.implicitHeight + 28 + actionBar.height)

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
        id: detailsScroll
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: actionBar.top
        anchors.leftMargin: 16
        anchors.rightMargin: 16
        anchors.topMargin: 14
        anchors.bottomMargin: 6
        contentHeight: content.implicitHeight
        clip: true
        interactive: contentHeight > height
        boundsBehavior: Flickable.StopAtBounds

        Column {
            id: content
            width: parent.width
            spacing: 7

            Row {
                width: parent.width
                spacing: 12

                Rectangle {
                    width: 58
                    height: 58
                    radius: Theme.radius
                    color: Theme.shellSurface
                    border.width: Theme.hairline
                    border.color: Theme.shellBorder

                    Image {
                        id: detailIcon
                        anchors.fill: parent
                        anchors.margins: 10
                        source: root.iconSource
                        fillMode: Image.PreserveAspectFit
                        smooth: true
                    }
                    Meta {
                        anchors.centerIn: parent
                        visible: detailIcon.source.toString() === "" || detailIcon.status !== Image.Ready
                        text: "App"
                    }
                }

                Column {
                    width: parent.width - 70
                    spacing: 5

                    Text {
                        width: parent.width
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 18
                        font.weight: 600
                        color: Theme.shellFg
                        text: {
                            if (root.phase === "loading")
                                return "Checking source and access…";
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
                }
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
                        text: root.webSource ? "Web app · browser" : (root.vendorSource ? "Vendor package · native" : "Flatpak · native")
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
                    border.color: (root.containment === "sandboxed" || root.containment === "hardened_native") ? Theme.shellBorder : Theme.shellStatusBad
                    Meta {
                        id: containmentMeta
                        anchors.centerIn: parent
                        color: (root.containment === "sandboxed" || root.containment === "hardened_native") ? Theme.shellInk3 : Theme.shellStatusBad
                        text: root.containment
                    }
                }
            }

            Meta {
                width: parent.width
                visible: root.nativeSource && root.verified
                text: root.vendorSource ? "Access · Punar install policy" : "Permissions · verified metadata"
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

        }
    }

    Item {
        id: actionBar
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        height: 54

        Rectangle {
            anchors.top: parent.top
            anchors.left: parent.left
            anchors.right: parent.right
            height: Theme.hairline
            color: Theme.shellBorder
        }

        Meta {
            anchors.left: actionButton.right
            anchors.leftMargin: 12
            anchors.right: removeButton.visible ? removeButton.left : parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            visible: detailsScroll.contentHeight > detailsScroll.height
            text: "Scroll to review all access"
            elide: Text.ElideRight
        }

        Rectangle {
            id: actionButton
            anchors.left: parent.left
            anchors.leftMargin: 16
            anchors.verticalCenter: parent.verticalCenter
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
                    if (root.phase === "removing")
                        return "Removing…";
                    if (root.phase === "opening")
                        return "Opening…";
                    if (root.phase === "failed")
                        return "Try again ↵";
                    if (root.removalArmed)
                        return "Keep app";
                    if (root.webSource)
                        return "Open web app ↵";
                    if (root.installed)
                        return "Open ↵";
                    if (root.vendorSource)
                        return "Download & install ↵";
                    return "Install ↵";
                }
            }

            MouseArea {
                anchors.fill: parent
                enabled: root.ready || root.phase === "failed"
                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: {
                    if (root.removalArmed)
                        root.cancelRemoveRequested();
                    else
                        root.actionRequested();
                }
            }
        }

        // Removal stays in the same card as installation and launch. The
        // first action only arms a plainly worded confirmation; no package is
        // changed until the second click (or Enter), and Escape can always
        // return to the ordinary Open state.
        Rectangle {
            id: removeButton
            anchors.right: parent.right
            anchors.rightMargin: 16
            anchors.verticalCenter: parent.verticalCenter
            visible: root.nativeSource && root.installed && (root.ready || root.phase === "removing")
            width: removeLabel.implicitWidth + 24
            height: removeLabel.implicitHeight + 13
            radius: Theme.radiusTag
            color: root.removalArmed ? Theme.shellDestructive : Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellDestructive

            Meta {
                id: removeLabel
                anchors.centerIn: parent
                color: root.removalArmed ? Theme.shellSurface : Theme.shellDestructive
                text: {
                    if (root.phase === "removing")
                        return "Removing…";
                    if (root.removalArmed)
                        return "Confirm uninstall ↵";
                    return "Uninstall";
                }
            }

            MouseArea {
                anchors.fill: parent
                enabled: root.ready
                cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                onClicked: root.removeRequested()
            }
        }
    }
}
