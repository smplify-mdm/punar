//@ pragma Env QML_IMPORT_PATH = /usr/share/punar/shell
//@ pragma AppId org.punar.MailAccounts

pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import Theme

ShellRoot {
    id: root

    readonly property string socketPath: Quickshell.env("PUNAR_MAIL_ACCOUNTS_SOCKET")
    property string state: "connecting"
    property string detail: "Opening your private account list…"
    property var accounts: []
    property var selected: null
    property int nextRequest: 1
    property var requests: ({})

    function request(method: string, params: var, context: var): void {
        if (!transport.connected) {
            root.state = "error";
            root.detail = "The protected account service is unavailable.";
            return;
        }
        var id = "mail-accounts-" + root.nextRequest++;
        root.requests[id] = { "method": method, "context": context };
        transport.write(JSON.stringify({
            "v": 1,
            "id": id,
            "method": method,
            "params": params
        }) + "\n");
        transport.flush();
    }

    function loadAccounts(): void {
        root.state = "loading";
        root.detail = "Reading connected accounts…";
        root.request("accounts.list", { "cursor": null, "limit": 100 }, null);
    }

    function removeSelected(): void {
        if (root.selected === null)
            return;
        root.state = "removing";
        root.detail = "Removing the account, encrypted credentials, and local mail…";
        root.request("accounts.remove", {
            "account_id": root.selected.account_id,
            "delete_local_data": true
        }, root.selected);
    }

    function handleFrame(frame: string): void {
        var response;
        try {
            response = JSON.parse(frame);
        } catch (error) {
            root.state = "error";
            root.detail = "Mail returned an unreadable response.";
            return;
        }
        var pending = root.requests[response.id];
        if (pending === undefined)
            return;
        delete root.requests[response.id];
        if (response.error !== undefined) {
            root.state = "error";
            root.detail = response.error.code === "conflict"
                ? "Mail is still syncing this account. Wait a moment, then try removing it again."
                : response.error.code === "storage_encryption_required"
                    ? "Drive encryption must be available before account data can be changed."
                    : "Mail could not complete that account change.";
            return;
        }
        if (pending.method === "accounts.list") {
            root.accounts = response.result.items || [];
            root.selected = null;
            root.state = root.accounts.length === 0 ? "empty" : "ready";
            root.detail = root.accounts.length === 0
                ? "No mail accounts are connected on this profile."
                : "";
        } else if (pending.method === "accounts.remove") {
            root.selected = null;
            root.state = "removed";
            root.detail = "Account removed. Its credentials and local mail were deleted from this device.";
            reloadTimer.start();
        }
    }

    Timer {
        id: reloadTimer
        interval: 1200
        repeat: false
        onTriggered: root.loadAccounts()
    }

    Socket {
        id: transport
        path: root.socketPath
        connected: root.socketPath !== ""
        onConnectedChanged: {
            if (connected)
                root.loadAccounts();
            else if (root.state !== "connecting") {
                root.state = "error";
                root.detail = "The protected account service disconnected.";
            }
        }
        // qmllint disable signal-handler-parameters
        onError: {
            root.state = "error";
            root.detail = "The protected account service could not be reached.";
        }
        // qmllint enable signal-handler-parameters
        parser: SplitParser {
            onRead: function(data) { root.handleFrame(data); }
        }
    }

    component AccountRow: Rectangle {
        id: row
        required property var account
        readonly property bool chosen: root.selected !== null
            && root.selected.account_id === row.account.account_id

        width: parent.width
        height: 82
        radius: Theme.radius
        color: row.chosen ? Theme.shellRaise2 : Theme.shellSurface
        border.width: row.chosen || row.activeFocus ? 2 : Theme.hairline
        border.color: row.chosen || row.activeFocus ? Theme.shellFocusRing : Theme.shellBorder
        activeFocusOnTab: true
        Accessible.role: Accessible.ListItem
        Accessible.name: row.account.display_name + ", "
            + (row.account.primary_address === null ? "mail account" : row.account.primary_address.address)

        Rectangle {
            id: avatar
            anchors.left: parent.left
            anchors.leftMargin: 14
            anchors.verticalCenter: parent.verticalCenter
            width: 42
            height: 42
            radius: 21
            color: Theme.shellMuted
            border.width: Theme.hairline
            border.color: Theme.shellBorder
            Text {
                anchors.centerIn: parent
                text: row.account.display_name === "" ? "@" : row.account.display_name.charAt(0).toUpperCase()
                font.family: Theme.fontSans
                font.pixelSize: 18
                font.weight: 600
                color: Theme.shellFg
            }
        }
        Column {
            anchors.left: avatar.right
            anchors.leftMargin: 13
            anchors.right: status.left
            anchors.rightMargin: 16
            anchors.verticalCenter: parent.verticalCenter
            spacing: 4
            Text {
                width: parent.width
                text: row.account.display_name
                elide: Text.ElideRight
                font.family: Theme.fontSans
                font.pixelSize: 15
                font.weight: 600
                color: Theme.shellFg
            }
            Text {
                width: parent.width
                text: row.account.primary_address === null
                    ? "Address unavailable" : row.account.primary_address.address
                elide: Text.ElideRight
                font.family: Theme.fontSans
                font.pixelSize: 12
                color: Theme.shellInk2
            }
        }
        Column {
            id: status
            anchors.right: parent.right
            anchors.rightMargin: 14
            anchors.verticalCenter: parent.verticalCenter
            spacing: 4
            Text {
                anchors.right: parent.right
                text: row.account.auth_state === "ready" ? "READY" : "NEEDS ATTENTION"
                font.family: Theme.fontMono
                font.pixelSize: 8
                font.weight: 700
                color: row.account.auth_state === "ready" ? Theme.shellStatusOk : Theme.shellStatusWarn
            }
            Text {
                anchors.right: parent.right
                text: row.account.provider_type === "open_protocols" ? "IMAP + SMTP"
                    : String(row.account.provider_type).toUpperCase()
                font.family: Theme.fontMono
                font.pixelSize: 8
                color: Theme.shellInk3
            }
        }
        MouseArea {
            anchors.fill: parent
            enabled: root.state === "ready"
            onClicked: root.selected = row.account
        }
        Keys.onSpacePressed: root.selected = row.account
        Keys.onReturnPressed: root.selected = row.account
    }

    FloatingWindow {
        id: window
        visible: true
        title: "Mail Account Settings"
        minimumSize: Qt.size(520, 440)
        implicitWidth: 760
        implicitHeight: 620
        color: Theme.shellSurface

        Item {
            anchors.fill: parent
            Keys.onEscapePressed: {
                if (root.selected !== null)
                    root.selected = null;
                else
                    Qt.quit();
            }

            Flickable {
                id: scroll
                anchors.fill: parent
                contentWidth: width
                contentHeight: page.height + 56
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                Column {
                    id: page
                    x: 28
                    y: 28
                    width: scroll.width - 56
                    spacing: 18

                    Row {
                        width: parent.width
                        height: 28
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "MAIL · ACCOUNTS"
                            font.family: Theme.fontMono
                            font.pixelSize: 10
                            font.weight: 700
                            font.letterSpacing: Theme.tracking(10, 0.16)
                            color: Theme.shellInk3
                        }
                        Item { width: parent.width - 285; height: 1 }
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "LOCAL PROFILE"
                            font.family: Theme.fontMono
                            font.pixelSize: 9
                            font.weight: 600
                            color: Theme.shellStatusOk
                        }
                    }

                    Text {
                        width: parent.width
                        text: "Your mail accounts"
                        font.family: Theme.fontSans
                        font.pixelSize: 34
                        font.weight: 600
                        color: Theme.shellFg
                    }
                    Text {
                        width: parent.width
                        text: "Removing an account deletes its encrypted credentials and downloaded mail from this device. It does not delete anything from your provider."
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 13
                        lineHeight: 1.2
                        color: Theme.shellInk2
                    }

                    Column {
                        width: parent.width
                        spacing: 10
                        visible: root.state === "ready"
                        Repeater {
                            model: root.accounts
                            delegate: AccountRow {
                                required property var modelData
                                account: modelData
                            }
                        }
                    }

                    Rectangle {
                        width: parent.width
                        height: 132
                        visible: root.state !== "ready"
                        radius: Theme.radius
                        color: Theme.shellMuted
                        border.width: Theme.hairline
                        border.color: Theme.shellBorder
                        Column {
                            anchors.centerIn: parent
                            width: parent.width - 48
                            spacing: 8
                            Text {
                                anchors.horizontalCenter: parent.horizontalCenter
                                text: root.state === "loading" || root.state === "connecting" ? "READING ACCOUNTS…"
                                    : root.state === "removing" ? "REMOVING ACCOUNT…"
                                    : root.state === "removed" ? "ACCOUNT REMOVED"
                                    : root.state === "empty" ? "NO ACCOUNTS CONNECTED"
                                    : "ACCOUNT SETTINGS UNAVAILABLE"
                                font.family: Theme.fontMono
                                font.pixelSize: 10
                                font.weight: 700
                                color: root.state === "error" ? Theme.shellStatusBad : Theme.shellFg
                            }
                            Text {
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                text: root.detail
                                wrapMode: Text.WordWrap
                                font.family: Theme.fontSans
                                font.pixelSize: 13
                                color: Theme.shellInk2
                            }
                        }
                    }

                    Rectangle {
                        width: parent.width
                        height: root.selected === null ? 0 : 152
                        visible: root.selected !== null
                        radius: Theme.radius
                        color: Theme.shellMuted
                        border.width: 2
                        border.color: Theme.shellDestructive
                        Column {
                            anchors.fill: parent
                            anchors.margins: 16
                            spacing: 10
                            Text {
                                width: parent.width
                                text: "Remove “" + (root.selected === null ? "" : root.selected.display_name) + "” from this device?"
                                wrapMode: Text.WordWrap
                                font.family: Theme.fontSans
                                font.pixelSize: 16
                                font.weight: 600
                                color: Theme.shellFg
                            }
                            Text {
                                width: parent.width
                                text: "Encrypted credentials and local mail will be deleted. Remote mail stays with your provider."
                                wrapMode: Text.WordWrap
                                font.family: Theme.fontSans
                                font.pixelSize: 12
                                color: Theme.shellInk2
                            }
                            Row {
                                anchors.right: parent.right
                                spacing: 10
                                Rectangle {
                                    width: 86
                                    height: 38
                                    radius: Theme.radius
                                    color: "transparent"
                                    border.width: Theme.hairline
                                    border.color: Theme.shellBorder
                                    Text {
                                        anchors.centerIn: parent
                                        text: "KEEP"
                                        font.family: Theme.fontMono
                                        font.pixelSize: 9
                                        font.weight: 700
                                        color: Theme.shellFg
                                    }
                                    MouseArea { anchors.fill: parent; onClicked: root.selected = null }
                                }
                                Rectangle {
                                    width: 148
                                    height: 38
                                    radius: Theme.radius
                                    color: Theme.shellDestructive
                                    Text {
                                        anchors.centerIn: parent
                                        text: "REMOVE LOCALLY"
                                        font.family: Theme.fontMono
                                        font.pixelSize: 9
                                        font.weight: 700
                                        color: Theme.shellSurface
                                    }
                                    MouseArea { anchors.fill: parent; onClicked: root.removeSelected() }
                                }
                            }
                        }
                    }

                    Row {
                        width: parent.width
                        height: 42
                        Text {
                            width: parent.width - closeButton.width
                            anchors.verticalCenter: parent.verticalCenter
                            text: "ADD ANOTHER ACCOUNT FROM THE ‘ADD MAIL ACCOUNT’ APP"
                            wrapMode: Text.WordWrap
                            font.family: Theme.fontMono
                            font.pixelSize: 8
                            font.weight: 600
                            color: Theme.shellInk3
                        }
                        Rectangle {
                            id: closeButton
                            width: 84
                            height: 40
                            radius: Theme.radius
                            color: Theme.shellFg
                            Text {
                                anchors.centerIn: parent
                                text: "DONE  ↵"
                                font.family: Theme.fontMono
                                font.pixelSize: 9
                                font.weight: 700
                                color: Theme.shellSurface
                            }
                            MouseArea { anchors.fill: parent; onClicked: Qt.quit() }
                        }
                    }
                }
            }
        }
    }
}
