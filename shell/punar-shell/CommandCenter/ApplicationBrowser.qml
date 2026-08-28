pragma ComponentBehavior: Bound
// ApplicationBrowser — the visual browse mode inside Command Center.
//
// THESIS: Applications are products people recognize, not package processes;
// installed software and vetted additions share one searchable library.
// OWN-WORLD: Punar paper/panel tokens, hairline structure, upstream app marks
// as content, and one compact action label per tile.
// STORY: See what is present, scan recommended tools, inspect one source, then
// open or install through the typed backend.
// FIRST VIEWPORT: Search remains in the Command Center masthead; installed apps
// lead, followed by a responsive three/two/one-column recommended field.
// FORM: Existing Command Center extension; no new resident surface.

import QtQuick
import "../Theme"
import "../Services"

Item {
    id: root

    property string query: ""
    property int currentIndex: 0
    signal launchRequested(var entry)
    signal catalogRequested(string id)

    readonly property var installedEntries: Apps.search(root.query, 0)
    readonly property var availableEntries: root.availableCatalog(root.query)
    readonly property var items: root.buildItems()
    readonly property int tileWidth: {
        var usable = Math.max(0, root.width - 32);
        if (usable >= 720)
            return Math.floor((usable - 24) / 3);
        if (usable >= 460)
            return Math.floor((usable - 12) / 2);
        return usable;
    }

    implicitHeight: 480

    function availableCatalog(query: string): var {
        var source = Catalog.search(query, 0);
        var out = [];
        for (var i = 0; i < source.length; i++) {
            if (!Apps.catalogAppInstalled(source[i]))
                out.push(source[i]);
        }
        return out;
    }

    function buildItems(): var {
        var out = [];
        for (var i = 0; i < root.installedEntries.length; i++)
            out.push({ "kind": "installed", "entry": root.installedEntries[i] });
        for (var k = 0; k < root.availableEntries.length; k++)
            out.push({ "kind": "catalog", "app": root.availableEntries[k] });
        return out;
    }

    function move(delta: int): void {
        if (root.items.length === 0) {
            root.currentIndex = -1;
            return;
        }
        root.currentIndex = Math.max(0, Math.min(root.items.length - 1, root.currentIndex + delta));
    }

    function activateCurrent(): void {
        if (root.currentIndex < 0 || root.currentIndex >= root.items.length)
            return;
        var item = root.items[root.currentIndex];
        if (item.kind === "installed")
            root.launchRequested(item.entry);
        else
            root.catalogRequested(String(item.app.id));
    }

    onItemsChanged: root.currentIndex = root.items.length > 0 ? 0 : -1

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: 9
        font.weight: 600
        font.letterSpacing: Theme.tracking(9, 0.12)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    component AppTile: Rectangle {
        id: tile

        required property var appData
        required property bool catalogApp
        required property bool selected
        property bool hovered: tileMouse.containsMouse
        signal activated()

        width: root.tileWidth
        height: 92
        radius: Theme.radius
        color: tile.selected || tile.hovered ? Theme.shellMuted : Theme.shellSurface
        border.width: Theme.hairline
        border.color: tile.selected || tile.hovered ? Theme.shellFg : Theme.shellBorder

        Rectangle {
            id: iconPlate
            anchors.left: parent.left
            anchors.leftMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            width: 52
            height: 52
            radius: Theme.radius
            color: Theme.shellSurface
            border.width: Theme.hairline
            border.color: Theme.shellBorder

            Image {
                id: appIcon
                anchors.fill: parent
                anchors.margins: 9
                source: tile.catalogApp ? Catalog.iconSource(tile.appData) : Apps.iconSource(tile.appData)
                fillMode: Image.PreserveAspectFit
                asynchronous: false
                smooth: true
            }

            Meta {
                anchors.centerIn: parent
                visible: appIcon.source.toString() === "" || appIcon.status === Image.Error
                color: Theme.shellInk2
                text: Apps.glyphFor(tile.catalogApp ? String(tile.appData.name) : Apps.displayName(tile.appData))
            }
        }

        Column {
            anchors.left: iconPlate.right
            anchors.leftMargin: 12
            anchors.right: parent.right
            anchors.rightMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            spacing: 5

            Text {
                width: parent.width
                text: tile.catalogApp ? String(tile.appData.name) : Apps.displayName(tile.appData)
                font.family: Theme.fontSans
                font.pixelSize: 14
                font.weight: 550
                color: Theme.shellFg
                elide: Text.ElideRight
            }

            Meta {
                width: parent.width
                text: tile.catalogApp
                    ? (Catalog.webOnly(tile.appData)
                        ? String(tile.appData.category || "application") + " · official web app"
                        : String(tile.appData.category || "application") + " · inspect & install")
                    : "Installed · open"
                color: Theme.shellInk3
                elide: Text.ElideRight
            }

            Rectangle {
                width: actionText.implicitWidth + 14
                height: 19
                radius: Theme.radiusTag
                color: tile.selected || tile.hovered ? Theme.shellFg : Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellFg

                Meta {
                    id: actionText
                    anchors.centerIn: parent
                    font.pixelSize: 8
                    color: tile.selected || tile.hovered ? Theme.shellSurface : Theme.shellFg
                    text: tile.catalogApp && !Catalog.webOnly(tile.appData) ? "View" : "Open"
                }
            }
        }

        MouseArea {
            id: tileMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: tile.activated()
        }
    }

    Flickable {
        anchors.fill: parent
        contentHeight: browserColumn.implicitHeight + 28
        clip: true
        interactive: contentHeight > height
        boundsBehavior: Flickable.StopAtBounds

        Column {
            id: browserColumn
            x: 16
            y: 16
            width: parent.width - 32
            spacing: 12

            Row {
                width: parent.width
                height: 40

                Column {
                    width: parent.width - countMeta.width
                    spacing: 2

                    Text {
                        width: parent.width
                        text: root.query.trim() === "" ? "Applications" : "Search results"
                        font.family: Theme.fontSans
                        font.pixelSize: 21
                        font.weight: 600
                        color: Theme.shellFg
                        elide: Text.ElideRight
                    }
                    Text {
                        width: parent.width
                        text: "Open what is installed or inspect a verified source before adding it."
                        font.family: Theme.fontSans
                        font.pixelSize: 12
                        color: Theme.shellInk2
                        elide: Text.ElideRight
                    }
                }

                Meta {
                    id: countMeta
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.width < 540
                        ? root.installedEntries.length + " here · " + root.availableEntries.length + " more"
                        : root.installedEntries.length + " installed · " + root.availableEntries.length + " available"
                }
            }

            Meta {
                visible: root.installedEntries.length > 0
                text: root.query.trim() === "" ? "Installed on this device" : "Installed matches"
                topPadding: 8
            }

            Flow {
                width: parent.width
                spacing: 12
                visible: root.installedEntries.length > 0
                height: childrenRect.height

                Repeater {
                    model: root.installedEntries
                    delegate: AppTile {
                        required property int index
                        required property var modelData
                        appData: modelData
                        catalogApp: false
                        selected: index === root.currentIndex
                        onActivated: root.launchRequested(modelData)
                    }
                }
            }

            Meta {
                visible: root.availableEntries.length > 0
                text: root.query.trim() === "" ? "Recommended for Punar" : "Available matches"
                topPadding: root.installedEntries.length > 0 ? 12 : 8
            }

            Flow {
                width: parent.width
                spacing: 12
                visible: root.availableEntries.length > 0
                height: childrenRect.height

                Repeater {
                    model: root.availableEntries
                    delegate: AppTile {
                        required property int index
                        required property var modelData
                        appData: modelData
                        catalogApp: true
                        selected: root.installedEntries.length + index === root.currentIndex
                        onActivated: root.catalogRequested(String(modelData.id))
                    }
                }
            }

            Item {
                width: parent.width
                height: 72
                visible: root.items.length === 0

                Column {
                    anchors.centerIn: parent
                    spacing: 5
                    Text {
                        anchors.horizontalCenter: parent.horizontalCenter
                        text: "No application matches “" + root.query + "”."
                        font.family: Theme.fontSans
                        font.pixelSize: 14
                        font.weight: 550
                        color: Theme.shellFg
                    }
                    Text {
                        anchors.horizontalCenter: parent.horizontalCenter
                        text: "Try a name or category from Punar’s approved catalog."
                        font.family: Theme.fontSans
                        font.pixelSize: 12
                        color: Theme.shellInk2
                    }
                }
            }
        }
    }
}
