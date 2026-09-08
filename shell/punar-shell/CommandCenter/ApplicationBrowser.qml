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
    property string selectedCategory: "all"
    property string updatePhase: "idle"
    property int updatesAvailable: 0
    property string updateMessage: ""
    signal launchRequested(var entry)
    signal catalogRequested(string id)
    signal updateAllRequested()

    readonly property var installedEntries: root.query.trim() !== "" || root.selectedCategory === "all"
        ? Apps.search(root.query, 0) : []
    readonly property var availableEntries: root.availableCatalog(root.query)
    readonly property var categoryEntries: Catalog.categories()
    readonly property var items: root.buildItems()
    readonly property bool updateBusy: root.updatePhase === "checking" || root.updatePhase === "updating"
    readonly property bool updateActionable: !root.updateBusy
        && (root.updatesAvailable > 0 || root.updatePhase === "failed")
    readonly property int tileWidth: {
        var usable = Math.max(0, root.width - 32);
        if (usable >= 720)
            return Math.floor((usable - 24) / 3);
        if (usable >= 460)
            return Math.floor((usable - 12) / 2);
        return usable;
    }

    implicitHeight: 480

    // WEB APPS ARE A SOURCE, NOT A CATEGORY. A category says what an
    // application is FOR — Slack is communication whether it arrives as a
    // Flatpak or as a Chromium app-mode window — so folding "web app" into
    // the category axis would make the taxonomy answer two questions at
    // once and get both wrong. It is therefore a filter over `sources`,
    // sharing the chip row because that is where a reader looks for
    // narrowing, and keyed `source:` so it can never collide with a
    // category id (the schema's category enum is plain words, no colons).
    readonly property string webFilterId: "source:web"

    function hasWebSource(app: var): bool {
        if (app === null || app === undefined)
            return false;
        var srcs = app.sources;
        if (!Array.isArray(srcs))
            return false;
        for (var i = 0; i < srcs.length; i++) {
            if (srcs[i] !== null && typeof srcs[i] === "object"
                && String(srcs[i].kind) === "web")
                return true;
        }
        return false;
    }

    readonly property bool anyWebApp: {
        var all = Catalog.entries;
        if (!Array.isArray(all))
            return false;
        for (var i = 0; i < all.length; i++) {
            if (root.hasWebSource(all[i]))
                return true;
        }
        return false;
    }

    function availableCatalog(query: string): var {
        var source = Catalog.search(query, 0);
        var out = [];
        var webOnly = root.selectedCategory === root.webFilterId;
        for (var i = 0; i < source.length; i++) {
            var inCategory = String(query).trim() !== ""
                || root.selectedCategory === "all"
                || (webOnly ? root.hasWebSource(source[i])
                            : String(source[i].category) === root.selectedCategory);
            if (inCategory && !Apps.catalogAppInstalled(source[i]))
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
    onQueryChanged: {
        if (root.query.trim() !== "")
            root.selectedCategory = "all";
    }

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
            // A monogram needs a ground to read as an icon rather than as text
            // in an empty box; a real logo does not, and gets the plain surface
            // so nothing tints it.
            color: appIcon.source.toString() === "" || appIcon.status === Image.Error
                ? Theme.shellMuted : Theme.shellSurface
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

            // THE MONOGRAM, when no icon file ships for this app.
            //
            // Twenty-one icon files cover sixty-two catalogue entries, and the
            // rest fall here — so this is the common case, not the exception,
            // and it was drawn like an exception: a 10px meta glyph in a
            // secondary ink, which reads as an EMPTY PLATE beside a real logo.
            // The owner reported it as "many apps are missing icons", which is
            // exactly right about the effect and not quite right about the
            // cause.
            //
            // Shipping forty more vendor logos is the other answer and a worse
            // one: trademarks need clearing app by app, and the bytes ride in
            // every image forever. A monogram that looks deliberate costs
            // nothing, cannot be wrong about a brand, and stays correct when
            // the catalogue grows.
            Text {
                anchors.centerIn: parent
                visible: appIcon.source.toString() === "" || appIcon.status === Image.Error
                text: Apps.glyphFor(tile.catalogApp ? String(tile.appData.name) : Apps.displayName(tile.appData))
                font.family: Theme.fontSans
                font.pixelSize: 20
                font.weight: 600
                font.letterSpacing: Theme.tracking(20, 0.02)
                color: tile.selected || tile.hovered ? Theme.shellFg : Theme.shellInk2
                textFormat: Text.PlainText
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
                        ? Catalog.categoryLabel(String(tile.appData.category)) + " · official web app"
                        : Catalog.categoryLabel(String(tile.appData.category)) + " · inspect & install")
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

    component CategoryButton: Rectangle {
        id: categoryButton

        required property string categoryId
        required property string categoryLabel
        readonly property bool active: root.selectedCategory === categoryButton.categoryId
        readonly property bool hovered: categoryMouse.containsMouse

        width: categoryText.implicitWidth + 24
        height: 30
        radius: Theme.radiusTag
        color: categoryButton.active ? Theme.shellFg
            : (categoryButton.hovered ? Theme.shellMuted : Theme.shellSurface)
        border.width: Theme.hairline
        border.color: categoryButton.active || categoryButton.hovered ? Theme.shellFg : Theme.shellBorder

        Meta {
            id: categoryText
            anchors.centerIn: parent
            text: categoryButton.categoryLabel
            color: categoryButton.active ? Theme.shellSurface : Theme.shellFg
        }

        MouseArea {
            id: categoryMouse
            anchors.fill: parent
            hoverEnabled: true
            cursorShape: Qt.PointingHandCursor
            onClicked: {
                root.selectedCategory = categoryButton.categoryId;
                root.currentIndex = root.items.length > 0 ? 0 : -1;
            }
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
                height: 58
                spacing: 12

                Column {
                    width: parent.width - updateButton.width - parent.spacing
                    spacing: 2

                    Text {
                        width: parent.width
                        text: root.query.trim() !== "" ? "Search results"
                            : (root.selectedCategory === "all" ? "Applications"
                                : (root.selectedCategory === root.webFilterId ? "Web applications"
                                    : Catalog.categoryLabel(root.selectedCategory) + " applications"))
                        font.family: Theme.fontSans
                        font.pixelSize: 21
                        font.weight: 600
                        color: Theme.shellFg
                        elide: Text.ElideRight
                    }
                    Text {
                        width: parent.width
                        text: root.selectedCategory === "all"
                            ? "Open what is installed or inspect permissions before adding reviewed software."
                            : (root.selectedCategory === root.webFilterId
                                ? "Opened in a Chromium app-mode window. Nothing is installed natively."
                                : "Reviewed tools in this category. Type at any time to search the entire catalog.")
                        font.family: Theme.fontSans
                        font.pixelSize: 12
                        color: Theme.shellInk2
                        elide: Text.ElideRight
                    }

                    Meta {
                        width: parent.width
                        text: root.width < 540
                        ? root.installedEntries.length + " here · " + root.availableEntries.length + " more"
                        : root.installedEntries.length + " installed · " + root.availableEntries.length + " available"
                        elide: Text.ElideRight
                    }
                }

                Rectangle {
                    id: updateButton
                    anchors.verticalCenter: parent.verticalCenter
                    width: Math.max(88, updateLabel.implicitWidth + 22)
                    height: 32
                    radius: Theme.radiusTag
                    color: root.updateActionable ? Theme.shellFg
                        : (updateMouse.containsMouse && !root.updateBusy
                            ? Theme.shellMuted : Theme.shellSurface)
                    border.width: Theme.hairline
                    border.color: updateButton.activeFocus ? Theme.shellFg
                        : (root.updatePhase === "failed" ? Theme.shellStatusBad
                        : (root.updateActionable ? Theme.shellFg : Theme.shellBorder)
                        )
                    opacity: root.updateBusy ? 0.72 : 1
                    activeFocusOnTab: root.updateActionable
                    Accessible.role: Accessible.Button
                    Accessible.name: root.updatesAvailable > 0 ? "Update all applications" : "Application updates"
                    Accessible.description: root.updateMessage

                    Keys.onPressed: function(event) {
                        if (root.updateActionable
                                && (event.key === Qt.Key_Return || event.key === Qt.Key_Enter
                                    || event.key === Qt.Key_Space)) {
                            root.updateAllRequested();
                            event.accepted = true;
                        }
                    }

                    Meta {
                        id: updateLabel
                        anchors.centerIn: parent
                        color: root.updateActionable ? Theme.shellSurface : Theme.shellInk2
                        text: {
                            if (root.updatePhase === "checking")
                                return "Checking…";
                            if (root.updatePhase === "updating")
                                return "Updating…";
                            if (root.updatePhase === "failed")
                                return "Try again";
                            if (root.updatesAvailable > 0)
                                return root.width < 620 ? "Update · " + root.updatesAvailable
                                    : "Update all · " + root.updatesAvailable;
                            return "All current";
                        }
                    }

                    MouseArea {
                        id: updateMouse
                        anchors.fill: parent
                        enabled: root.updateActionable
                        hoverEnabled: enabled
                        cursorShape: enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
                        onClicked: {
                            updateButton.forceActiveFocus();
                            root.updateAllRequested();
                        }
                    }
                }
            }

            Item {
                width: parent.width
                height: root.updateMessage !== "" || root.updateBusy ? 26 : 0
                visible: height > 0

                Meta {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    text: root.updateMessage
                    color: root.updatePhase === "failed" ? Theme.shellStatusBad : Theme.shellInk3
                    elide: Text.ElideRight
                }

                Rectangle {
                    id: updateTrack
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: 3
                    visible: root.updateBusy
                    clip: true
                    color: Theme.shellBorder

                    Rectangle {
                        id: updateSegment
                        width: Math.max(72, updateTrack.width * 0.24)
                        height: parent.height
                        radius: parent.height / 2
                        color: Theme.shellFg

                        NumberAnimation on x {
                            from: -updateSegment.width
                            to: updateTrack.width
                            duration: Theme.durSpatial * 3
                            loops: Animation.Infinite
                            running: updateTrack.visible
                            easing.type: Easing.InOutSine
                        }
                    }
                }
            }

            Flow {
                width: parent.width
                spacing: 8
                visible: root.query.trim() === ""
                height: visible ? childrenRect.height : 0

                CategoryButton {
                    categoryId: "all"
                    categoryLabel: "All"
                }

                Repeater {
                    model: root.categoryEntries
                    delegate: CategoryButton {
                        required property var modelData
                        categoryId: String(modelData.id)
                        categoryLabel: String(modelData.label)
                    }
                }

                // Last in the row, and absent entirely when the catalog
                // ships no web app — a filter that can only ever return
                // nothing is a dead control.
                CategoryButton {
                    categoryId: root.webFilterId
                    categoryLabel: "Web apps"
                    visible: root.anyWebApp
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
                text: root.query.trim() !== "" ? "Available matches"
                    : (root.selectedCategory === "all" ? "Recommended for Punar"
                        : Catalog.categoryLabel(root.selectedCategory) + " · " + root.availableEntries.length)
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
