//@ pragma Env QML_IMPORT_PATH = /usr/share/punar/shell
//@ pragma AppId org.punar.MailAccount

pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io
import Theme

ShellRoot {
    id: root

    property string provider: "gmail"
    property string state: "form"
    property string errorText: ""
    property string socketPath: Quickshell.env("PUNAR_MAIL_ACCOUNT_SOCKET")

    function validEmail(value: string): bool {
        var at = value.indexOf("@");
        return value.length <= 254 && at > 0 && at < value.length - 1
            && value.indexOf(" ") < 0 && value.indexOf("\n") < 0
            && value.indexOf("\r") < 0;
    }

    function validHost(value: string): bool {
        return value.length > 0 && value.length <= 253
            && value.indexOf(" ") < 0 && value.indexOf("/") < 0
            && value.indexOf(":") < 0 && value.indexOf("\n") < 0;
    }

    function validPort(value: string): bool {
        var port = Number(value);
        return value !== "" && Number.isInteger(port) && port > 0 && port <= 65535;
    }

    function chooseProvider(value: string): void {
        root.provider = value;
        if (value === "gmail") {
            imapHost.text = "imap.gmail.com";
            imapPort.text = "993";
            smtpHost.text = "smtp.gmail.com";
            smtpPort.text = "465";
            smtpSecurity.value = "tls";
        } else if (value === "icloud") {
            imapHost.text = "imap.mail.me.com";
            imapPort.text = "993";
            smtpHost.text = "smtp.mail.me.com";
            smtpPort.text = "587";
            smtpSecurity.value = "start_tls";
        } else {
            imapHost.text = "";
            imapPort.text = "993";
            smtpHost.text = "";
            smtpPort.text = "465";
            smtpSecurity.value = "tls";
        }
        imapSecurity.value = "tls";
        root.errorText = "";
    }

    function submit(): void {
        root.errorText = "";
        var email = emailField.text.trim();
        var displayName = nameField.text.trim();
        var username = usernameField.text.trim() === "" ? email : usernameField.text.trim();
        var password = passwordField.text;
        if (!root.validEmail(email)) {
            root.errorText = "Enter a complete email address.";
            emailField.focusField();
            return;
        }
        if (displayName === "" || displayName.length > 200) {
            root.errorText = "Enter the name recipients should see.";
            nameField.focusField();
            return;
        }
        if (username === "" || username.length > 512) {
            root.errorText = "Enter the username used by your mail provider.";
            usernameField.focusField();
            return;
        }
        if (password === "" || password.length > 65536
                || password.indexOf("\n") >= 0 || password.indexOf("\r") >= 0
                || password.indexOf("\u0000") >= 0) {
            root.errorText = "Enter a valid password or app password.";
            passwordField.focusField();
            return;
        }
        if (!root.validHost(imapHost.text.trim()) || !root.validPort(imapPort.text)
                || !root.validHost(smtpHost.text.trim()) || !root.validPort(smtpPort.text)) {
            root.errorText = "Check the incoming and outgoing server settings.";
            imapHost.focusField();
            return;
        }
        if (!transport.connected) {
            root.errorText = "The protected account service is unavailable. Close this window and try again.";
            return;
        }

        root.state = "verifying";
        transport.write(JSON.stringify({
            "v": 1,
            "setup": {
                "identity": {
                    "display_name": displayName,
                    "primary_address": { "name": displayName, "address": email }
                },
                "config": {
                    "username": username,
                    "imap": {
                        "host": imapHost.text.trim(),
                        "port": Number(imapPort.text),
                        "security": imapSecurity.value
                    },
                    "smtp": {
                        "host": smtpHost.text.trim(),
                        "port": Number(smtpPort.text),
                        "security": smtpSecurity.value
                    }
                }
            }
        }) + "\n");
        transport.write(password + "\n");
        transport.flush();
        passwordField.clear();
    }

    function acceptOutcome(frame: string): void {
        var outcome;
        try {
            outcome = JSON.parse(frame);
        } catch (error) {
            root.state = "failed";
            root.errorText = "Mail returned an unreadable result. Nothing was connected.";
            return;
        }
        if (outcome.ok === true && outcome.code === "connected") {
            root.state = "connected";
            closeTimer.start();
            return;
        }
        // Account-entry capabilities are intentionally one-use. A rejected
        // attempt must close before another protected setup can be started.
        root.state = "failed";
        if (outcome.code === "invalid_credentials")
            root.errorText = "Your provider rejected that username or password. Check whether it requires an app password.";
        else if (outcome.code === "provider_unreachable")
            root.errorText = "The mail servers could not be reached. Check the network and server names.";
        else if (outcome.code === "tls_validation_failed")
            root.errorText = "The server identity could not be verified securely. The account was not saved.";
        else if (outcome.code === "invalid_configuration")
            root.errorText = "Those server settings are not valid. Review the addresses, ports, and security modes.";
        else if (outcome.code === "storage_encryption_required")
            root.errorText = "Drive encryption must be enabled before Mail can save an account.";
        else
            root.errorText = "Mail could not connect this account. Nothing was saved.";
    }

    Timer {
        id: closeTimer
        interval: 900
        repeat: false
        onTriggered: Qt.quit()
    }

    Socket {
        id: transport
        path: root.socketPath
        connected: root.socketPath !== ""

        onConnectedChanged: {
            if (!connected && root.state === "verifying") {
                root.state = "failed";
                root.errorText = "The protected account service disconnected. Nothing was connected.";
            }
        }
        // qmllint disable signal-handler-parameters
        onError: {
            if (root.state !== "connected" && root.state !== "failed") {
                root.state = "failed";
                root.errorText = "The protected account service could not be reached. Close this window and try again.";
            }
        }
        // qmllint enable signal-handler-parameters
        parser: SplitParser {
            onRead: function(data) {
                root.acceptOutcome(data);
            }
        }
    }

    component Field: Column {
        id: field
        required property string label
        property string placeholder: ""
        property bool secret: false
        property alias text: input.text
        property bool revealed: false
        signal accepted

        spacing: 6

        function focusField(): void { input.forceActiveFocus(); }
        function clear(): void {
            input.text = "";
            field.revealed = false;
        }

        Text {
            text: field.label.toUpperCase()
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            font.letterSpacing: Theme.tracking(9, 0.14)
            color: Theme.shellInk3
        }

        Rectangle {
            width: parent.width
            height: 48
            radius: Theme.radius
            color: Theme.shellSurface
            border.width: input.activeFocus ? 2 : Theme.hairline
            border.color: input.activeFocus ? Theme.shellFocusRing : Theme.shellInputBorder

            Text {
                anchors.left: parent.left
                anchors.leftMargin: 14
                anchors.right: reveal.visible ? reveal.left : parent.right
                anchors.rightMargin: 14
                anchors.verticalCenter: parent.verticalCenter
                visible: input.text === ""
                text: field.placeholder
                elide: Text.ElideRight
                font.family: Theme.fontSans
                font.pixelSize: 14
                color: Theme.shellInk3
            }

            TextInput {
                id: input
                anchors.left: parent.left
                anchors.leftMargin: 14
                anchors.right: reveal.visible ? reveal.left : parent.right
                anchors.rightMargin: 14
                anchors.verticalCenter: parent.verticalCenter
                height: 25
                enabled: root.state === "form"
                echoMode: field.secret && !field.revealed ? TextInput.Password : TextInput.Normal
                passwordCharacter: "•"
                passwordMaskDelay: 0
                font.family: Theme.fontSans
                font.pixelSize: 15
                color: Theme.shellFg
                selectionColor: Theme.shellFg
                selectedTextColor: Theme.shellSurface
                clip: true
                selectByMouse: true
                activeFocusOnTab: true
                Accessible.role: Accessible.EditableText
                Accessible.name: field.label
                Accessible.passwordEdit: field.secret
                Keys.onReturnPressed: field.accepted()
                Keys.onEnterPressed: field.accepted()
            }

            Item {
                id: reveal
                anchors.right: parent.right
                anchors.rightMargin: 8
                anchors.verticalCenter: parent.verticalCenter
                width: visible ? 38 : 0
                height: 36
                visible: field.secret
                enabled: root.state === "form"
                activeFocusOnTab: visible
                Accessible.role: Accessible.Button
                Accessible.name: field.revealed ? "Hide password" : "Show password"

                Text {
                    anchors.centerIn: parent
                    text: field.revealed ? "HIDE" : "SHOW"
                    font.family: Theme.fontMono
                    font.pixelSize: 8
                    font.weight: 600
                    color: reveal.activeFocus ? Theme.shellFg : Theme.shellInk3
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: field.revealed = !field.revealed
                }
                Keys.onSpacePressed: field.revealed = !field.revealed
                Keys.onReturnPressed: field.revealed = !field.revealed
            }
        }
    }

    component Choice: Rectangle {
        id: choice
        required property string value
        required property string label
        required property string note
        readonly property bool selected: root.provider === choice.value

        width: parent.width
        height: 58
        radius: Theme.radius
        color: selected ? Theme.shellRaise2 : "transparent"
        border.width: selected || activeFocus ? 2 : Theme.hairline
        border.color: selected || activeFocus ? Theme.shellFocusRing : Theme.shellBorder
        activeFocusOnTab: true
        Accessible.role: Accessible.RadioButton
        Accessible.name: choice.label
        Accessible.description: choice.note
        Accessible.checked: choice.selected

        Column {
            anchors.left: parent.left
            anchors.leftMargin: 14
            anchors.right: mark.left
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            spacing: 2
            Text {
                text: choice.label
                font.family: Theme.fontSans
                font.pixelSize: 14
                font.weight: 600
                color: Theme.shellFg
            }
            Text {
                width: parent.width
                text: choice.note
                elide: Text.ElideRight
                font.family: Theme.fontSans
                font.pixelSize: 11
                color: Theme.shellInk3
            }
        }
        Text {
            id: mark
            anchors.right: parent.right
            anchors.rightMargin: 14
            anchors.verticalCenter: parent.verticalCenter
            text: choice.selected ? "●" : "○"
            font.pixelSize: 16
            color: choice.selected ? Theme.shellStatusOk : Theme.shellInk3
        }
        MouseArea {
            anchors.fill: parent
            onClicked: root.chooseProvider(choice.value)
        }
        Keys.onSpacePressed: root.chooseProvider(choice.value)
        Keys.onReturnPressed: root.chooseProvider(choice.value)
    }

    component SecurityChoice: Item {
        id: security
        required property string label
        property string value: "tls"

        height: 42
        Text {
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            text: security.label.toUpperCase()
            font.family: Theme.fontMono
            font.pixelSize: 9
            font.weight: 600
            font.letterSpacing: Theme.tracking(9, 0.12)
            color: Theme.shellInk3
        }
        Row {
            anchors.right: parent.right
            anchors.verticalCenter: parent.verticalCenter
            spacing: 6
            Repeater {
                model: [
                    { "value": "tls", "label": "TLS" },
                    { "value": "start_tls", "label": "STARTTLS" }
                ]
                delegate: Rectangle {
                    id: securityOption
                    required property var modelData
                    width: optionText.implicitWidth + 20
                    height: 30
                    radius: Theme.radiusTag
                    color: security.value === modelData.value ? Theme.shellFg : "transparent"
                    border.width: Theme.hairline
                    border.color: Theme.shellBorder
                    Text {
                        id: optionText
                        anchors.centerIn: parent
                        text: securityOption.modelData.label
                        font.family: Theme.fontMono
                        font.pixelSize: 8
                        font.weight: 600
                        color: security.value === securityOption.modelData.value ? Theme.shellSurface : Theme.shellFg
                    }
                    MouseArea {
                        anchors.fill: parent
                        enabled: root.state === "form"
                        onClicked: security.value = securityOption.modelData.value
                    }
                }
            }
        }
    }

    FloatingWindow {
        id: window
        visible: true
        title: "Connect a mail account"
        // CLOSING THE WINDOW EXITS THE APPLICATION. Quickshell only hides a
        // window the compositor closes; the process — and the transient unit
        // holding its capability — would stay resident with no window, which
        // is the residency punar-mail-account@/punar-mail-accounts@ forbid.
        onClosed: Qt.quit()
        minimumSize: Qt.size(560, 620)
        implicitWidth: 940
        implicitHeight: 720
        color: Theme.shellSurface

        Item {
            anchors.fill: parent
            Keys.onEscapePressed: {
                if (root.state === "form" || root.state === "failed")
                    Qt.quit();
            }
            Component.onCompleted: emailField.focusField()

            Rectangle {
                id: leftRail
                anchors.left: parent.left
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                width: parent.width >= 760 ? 286 : 0
                visible: width > 0
                color: Theme.shellMuted

                Column {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.top: parent.top
                    anchors.margins: 28
                    spacing: 12
                    Text {
                        text: "MAIL"
                        font.family: Theme.fontMono
                        font.pixelSize: 10
                        font.weight: 700
                        font.letterSpacing: Theme.tracking(10, 0.18)
                        color: Theme.shellInk3
                    }
                    Text {
                        width: parent.width
                        text: "Choose your provider"
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 28
                        font.weight: 600
                        color: Theme.shellFg
                    }
                    Text {
                        width: parent.width
                        text: "Mail uses open standards and keeps credentials in the encrypted device vault."
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 13
                        lineHeight: 1.25
                        color: Theme.shellInk2
                    }
                    Item { width: 1; height: 8 }
                    Choice { value: "gmail"; label: "Gmail"; note: "Use a Google app password" }
                    Choice { value: "icloud"; label: "iCloud Mail"; note: "Use an app-specific password" }
                    Choice { value: "custom"; label: "Other provider"; note: "IMAP + SMTP over TLS" }
                }
            }

            Flickable {
                id: scroll
                anchors.left: leftRail.visible ? leftRail.right : parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.bottom: parent.bottom
                contentWidth: width
                contentHeight: formColumn.height + 64
                clip: true
                boundsBehavior: Flickable.StopAtBounds

                Column {
                    id: formColumn
                    x: Math.max(28, (scroll.width - width) / 2)
                    y: 30
                    width: Math.min(590, scroll.width - 56)
                    spacing: 18

                    Row {
                        width: parent.width
                        height: 34
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "CONNECT ACCOUNT"
                            font.family: Theme.fontMono
                            font.pixelSize: 10
                            font.weight: 700
                            font.letterSpacing: Theme.tracking(10, 0.16)
                            color: Theme.shellInk3
                        }
                        Item { width: parent.width - 250; height: 1 }
                        Text {
                            anchors.verticalCenter: parent.verticalCenter
                            text: "PRIVATE BY DEFAULT"
                            font.family: Theme.fontMono
                            font.pixelSize: 9
                            font.weight: 600
                            color: Theme.shellStatusOk
                        }
                    }

                    Text {
                        width: parent.width
                        text: root.state === "connected" ? "Account connected."
                            : root.state === "verifying" ? "Verifying both mail servers…"
                            : "Bring your inbox here."
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 34
                        font.weight: 600
                        color: Theme.shellFg
                    }
                    Text {
                        width: parent.width
                        text: root.state === "connected"
                            ? "Your first inbox sync has started. Mail will open with real account data only."
                            : "Punar checks incoming and outgoing mail before saving anything."
                        wrapMode: Text.WordWrap
                        font.family: Theme.fontSans
                        font.pixelSize: 14
                        color: Theme.shellInk2
                    }

                    Column {
                        width: parent.width
                        spacing: 14
                        opacity: root.state === "connected" || root.state === "failed" ? 0.35 : 1
                        enabled: root.state === "form"

                        Row {
                            width: parent.width
                            spacing: 14
                            Field {
                                id: emailField
                                width: parent.width >= 520 ? (parent.width - 14) / 2 : parent.width
                                label: "Email address"
                                placeholder: "you@example.com"
                                onAccepted: nameField.focusField()
                                onTextChanged: {
                                    if (usernameField.text === "" || usernameField.text === usernameField.lastEmail)
                                        usernameField.text = text.trim();
                                    usernameField.lastEmail = text.trim();
                                }
                            }
                            Field {
                                id: nameField
                                visible: parent.width >= 520
                                width: visible ? (parent.width - 14) / 2 : 0
                                label: "Your name"
                                placeholder: "Name shown to recipients"
                                onAccepted: usernameField.focusField()
                            }
                        }
                        Field {
                            id: narrowNameField
                            visible: parent.width < 520
                            width: parent.width
                            label: "Your name"
                            placeholder: "Name shown to recipients"
                            text: nameField.text
                            onTextChanged: nameField.text = text
                            onAccepted: usernameField.focusField()
                        }
                        Field {
                            id: usernameField
                            property string lastEmail: ""
                            width: parent.width
                            label: "Provider username"
                            placeholder: "Usually your full email address"
                            onAccepted: passwordField.focusField()
                        }
                        Field {
                            id: passwordField
                            width: parent.width
                            label: root.provider === "custom" ? "Password or app password" : "App password"
                            placeholder: root.provider === "gmail" ? "16-character Google app password"
                                : root.provider === "icloud" ? "Apple app-specific password"
                                : "Password required by your provider"
                            secret: true
                            onAccepted: root.submit()
                        }

                        Text {
                            width: parent.width
                            visible: root.provider !== "custom"
                            text: root.provider === "gmail"
                                ? "Google accounts with two-step verification require an app password. Standard account passwords are not accepted."
                                : "Create an app-specific password from your Apple Account security settings."
                            wrapMode: Text.WordWrap
                            font.family: Theme.fontSans
                            font.pixelSize: 12
                            color: Theme.shellInk3
                        }

                        Rectangle {
                            width: parent.width
                            height: serverColumn.height + 28
                            radius: Theme.radius
                            color: Theme.shellMuted
                            border.width: Theme.hairline
                            border.color: Theme.shellBorder

                            Column {
                                id: serverColumn
                                anchors.left: parent.left
                                anchors.right: parent.right
                                anchors.top: parent.top
                                anchors.margins: 14
                                spacing: 12
                                Text {
                                    text: root.provider === "custom" ? "SERVER SETTINGS" : "SECURE SERVER SETTINGS"
                                    font.family: Theme.fontMono
                                    font.pixelSize: 9
                                    font.weight: 700
                                    font.letterSpacing: Theme.tracking(9, 0.14)
                                    color: Theme.shellInk3
                                }
                                Row {
                                    width: parent.width
                                    spacing: 10
                                    Field {
                                        id: imapHost
                                        width: parent.width - imapPort.width - 10
                                        label: "Incoming (IMAP)"
                                        placeholder: "imap.example.com"
                                    }
                                    Field {
                                        id: imapPort
                                        width: 96
                                        label: "Port"
                                        placeholder: "993"
                                    }
                                }
                                SecurityChoice { id: imapSecurity; width: parent.width; label: "Incoming security" }
                                Row {
                                    width: parent.width
                                    spacing: 10
                                    Field {
                                        id: smtpHost
                                        width: parent.width - smtpPort.width - 10
                                        label: "Outgoing (SMTP)"
                                        placeholder: "smtp.example.com"
                                    }
                                    Field {
                                        id: smtpPort
                                        width: 96
                                        label: "Port"
                                        placeholder: "465"
                                    }
                                }
                                SecurityChoice { id: smtpSecurity; width: parent.width; label: "Outgoing security" }
                            }
                        }
                    }

                    Rectangle {
                        width: parent.width
                        height: visible ? errorMessage.implicitHeight + 24 : 0
                        visible: root.errorText !== ""
                        radius: Theme.radius
                        color: "transparent"
                        border.width: 2
                        border.color: Theme.shellStatusBad
                        Text {
                            id: errorMessage
                            anchors.left: parent.left
                            anchors.right: parent.right
                            anchors.verticalCenter: parent.verticalCenter
                            anchors.margins: 12
                            text: root.errorText
                            wrapMode: Text.WordWrap
                            font.family: Theme.fontSans
                            font.pixelSize: 13
                            color: Theme.shellStatusBad
                        }
                    }

                    Row {
                        width: parent.width
                        height: 48
                        spacing: 12
                        Text {
                            width: parent.width - cancelButton.width - connectButton.width - 24
                            anchors.verticalCenter: parent.verticalCenter
                            text: root.state === "verifying" ? "CHECKING IMAP + SMTP · THIS MAY TAKE A MOMENT"
                                : root.state === "failed" ? "NOTHING WAS SAVED · CLOSE TO TRY AGAIN"
                                : "CREDENTIALS STAY IN THE ENCRYPTED DEVICE VAULT"
                            wrapMode: Text.WordWrap
                            font.family: Theme.fontMono
                            font.pixelSize: 8
                            font.weight: 600
                            color: root.state === "verifying" ? Theme.shellStatusWarn : Theme.shellInk3
                        }
                        Rectangle {
                            id: cancelButton
                            width: 82
                            height: 42
                            radius: Theme.radius
                            color: "transparent"
                            border.width: Theme.hairline
                            border.color: Theme.shellBorder
                            opacity: root.state === "verifying" || root.state === "connected" ? 0.45 : 1
                            Text {
                                anchors.centerIn: parent
                                text: root.state === "failed" ? "CLOSE" : "CANCEL"
                                font.family: Theme.fontMono
                                font.pixelSize: 9
                                font.weight: 700
                                color: Theme.shellFg
                            }
                            MouseArea {
                                anchors.fill: parent
                                enabled: root.state === "form" || root.state === "failed"
                                onClicked: Qt.quit()
                            }
                        }
                        Rectangle {
                            id: connectButton
                            width: 116
                            height: 42
                            radius: Theme.radius
                            color: root.state === "form" ? Theme.shellActionBg : Theme.shellMuted
                            border.width: root.state === "verifying" ? Theme.hairline : 0
                            border.color: Theme.shellBorder
                            Text {
                                anchors.centerIn: parent
                                text: root.state === "connected" ? "CONNECTED"
                                    : root.state === "verifying" ? "VERIFYING…"
                                    : root.state === "failed" ? "TRY AGAIN" : "CONNECT  ↵"
                                font.family: Theme.fontMono
                                font.pixelSize: 9
                                font.weight: 700
                                color: root.state === "form" ? Theme.shellActionFg : Theme.shellInk3
                            }
                            MouseArea {
                                anchors.fill: parent
                                enabled: root.state === "form" || root.state === "failed"
                                onClicked: {
                                    if (root.state === "failed")
                                        Qt.quit();
                                    else
                                        root.submit();
                                }
                            }
                        }
                    }
                }
            }
        }

        Component.onCompleted: root.chooseProvider("gmail")
    }
}
