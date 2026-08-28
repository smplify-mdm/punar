pragma ComponentBehavior: Bound
// Punar first-run and login surface.
//
// The product contract is intentionally small: one field-note card over the
// shipped Stillpoint artwork, exactly three first-run values, and the normal
// password greeter after that. No network, tour, account type, telemetry or
// update choice is smuggled into the path to a useful desktop.
//
// Secret boundary: neither Process command contains a password. The QML
// TextInput necessarily owns the characters while they are typed; on process
// start they are written once to an anonymous stdin pipe and both first-run
// password fields are cleared immediately. No property or log receives a
// second copy. punar-onboard / punar-greet zeroize their own buffers.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
// The greeter is its own Quickshell configuration root. Import the shared
// singleton as a real QML module; a parent-directory singleton import leaves
// its color properties unresolved in that independent engine.
import Theme

Scope {
    id: root

    property bool stateLoaded: false
    property bool firstRun: true
    property bool complete: false
    property string accountName: ""
    property string deviceName: "Punar"
    readonly property bool reducedMotion: Quickshell.env("PUNAR_REDUCED_MOTION") === "1"

    readonly property var keyboardLayouts: [
        {
            "code": "us",
            "label": "US"
        },
        {
            "code": "gb",
            "label": "UK"
        },
        {
            "code": "de",
            "label": "DE"
        },
        {
            "code": "fr",
            "label": "FR"
        },
        {
            "code": "es",
            "label": "ES"
        }
    ]

    function parseState(body: string): void {
        try {
            var state = JSON.parse(body);
            root.complete = state.v === 1 && state.complete === true;
            if (!root.stateLoaded) {
                root.firstRun = !root.complete;
                root.stateLoaded = true;
            }
            if (typeof state.username === "string" && state.username !== "")
                root.accountName = state.username;
        } catch (e) {
            console.warn("punar-greeter: invalid onboarding projection");
        }
    }

    function parseProjection(body: string): void {
        try {
            var state = JSON.parse(body);
            if (typeof state.deviceName === "string" && state.deviceName !== "")
                root.deviceName = state.deviceName;
            if (Array.isArray(state.accounts) && state.accounts.length > 0 && typeof state.accounts[0].username === "string")
                root.accountName = state.accounts[0].username;
        } catch (e) {
            console.warn("punar-greeter: invalid account projection");
        }
    }

    function hostnameFor(displayName: string): string {
        var normalized = String(displayName).trim();
        try {
            normalized = normalized.normalize("NFKD");
        } catch (e) {
            // Qt's JS engine on every pinned image supports normalize(). The
            // backend remains authoritative if a future engine does not.
        }
        normalized = normalized.replace(/[\u0300-\u036f]/g, "");
        normalized = normalized.replace(/[\u2019']/g, "");
        normalized = normalized.toLowerCase().replace(/[^a-z0-9]+/g, "-");
        normalized = normalized.replace(/^-+|-+$/g, "").substring(0, 63);
        return normalized.replace(/-+$/g, "");
    }

    component Meta: Text {
        font.family: Theme.fontMono
        font.pixelSize: Theme.metaSize
        font.weight: 500
        font.letterSpacing: Theme.tracking(Theme.metaSize, 0.14)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    component Action: Rectangle {
        id: action

        property string label: "Continue"
        property string hint: "↵"
        property bool busy: false
        property bool quiet: false
        signal invoked

        width: actionRow.implicitWidth + 40
        height: Math.max(44, actionRow.implicitHeight + 22)
        radius: Theme.radiusTag
        color: action.quiet ? Theme.shellSurface : Theme.shellActionBg
        border.width: action.quiet ? Theme.hairline : 0
        border.color: Theme.shellInputBorder
        opacity: action.enabled ? (action.busy ? 0.62 : 1) : 0.45
        activeFocusOnTab: action.enabled
        Accessible.role: Accessible.Button
        Accessible.name: action.label
        Accessible.description: action.busy ? "Working" : ""

        Row {
            id: actionRow
            anchors.centerIn: parent
            spacing: 8

            Text {
                anchors.verticalCenter: parent.verticalCenter
                text: action.busy ? "Working" : action.label
                font.family: Theme.fontMono
                font.pixelSize: 11
                font.weight: 600
                font.letterSpacing: Theme.tracking(11, 0.1)
                font.capitalization: Font.AllUppercase
                color: action.quiet ? Theme.shellFg : Theme.shellActionFg
            }
            Text {
                anchors.verticalCenter: parent.verticalCenter
                visible: !action.busy && action.hint !== ""
                text: action.hint
                font.family: Theme.fontMono
                font.pixelSize: 10
                color: action.quiet ? Theme.shellInk3 : Theme.shellActionFg
            }
        }

        Rectangle {
            anchors.fill: parent
            anchors.margins: -4
            visible: action.activeFocus
            color: "transparent"
            radius: Theme.radiusTag + 2
            border.width: 2
            border.color: Theme.shellFocusRing
        }

        Keys.onPressed: function (event) {
            if ((event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Space) && action.enabled && !action.busy) {
                action.invoked();
                event.accepted = true;
            }
        }

        MouseArea {
            anchors.fill: parent
            enabled: action.enabled && !action.busy
            onClicked: action.invoked()
        }
    }

    component Glyph: Item {
        id: glyph

        property string kind: "user"
        property color ink: Theme.shellInk3

        width: 20
        height: 20
        Accessible.ignored: true

        onKindChanged: drawing.requestPaint()
        onInkChanged: drawing.requestPaint()

        Canvas {
            id: drawing

            anchors.fill: parent
            antialiasing: true

            onPaint: {
                var ctx = getContext("2d");
                ctx.clearRect(0, 0, width, height);
                ctx.strokeStyle = glyph.ink;
                ctx.fillStyle = glyph.ink;
                ctx.lineWidth = 1.5;
                ctx.lineCap = "round";
                ctx.lineJoin = "round";

                if (glyph.kind === "user") {
                    ctx.beginPath();
                    ctx.arc(10, 6.2, 3.1, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.moveTo(3.2, 18);
                    ctx.bezierCurveTo(3.8, 12.6, 16.2, 12.6, 16.8, 18);
                    ctx.stroke();
                } else if (glyph.kind === "lock") {
                    ctx.beginPath();
                    ctx.arc(10, 8.2, 4.1, Math.PI, 0);
                    ctx.stroke();
                    ctx.strokeRect(4.8, 8.2, 10.4, 8.8);
                    ctx.beginPath();
                    ctx.arc(10, 12.2, 1, 0, Math.PI * 2);
                    ctx.fill();
                    ctx.moveTo(10, 13.1);
                    ctx.lineTo(10, 15);
                    ctx.stroke();
                } else if (glyph.kind === "device") {
                    ctx.strokeRect(2.4, 3.2, 15.2, 10.6);
                    ctx.beginPath();
                    ctx.moveTo(10, 13.8);
                    ctx.lineTo(10, 17);
                    ctx.moveTo(6.7, 17);
                    ctx.lineTo(13.3, 17);
                    ctx.stroke();
                } else if (glyph.kind === "eye" || glyph.kind === "eye_off") {
                    ctx.beginPath();
                    ctx.moveTo(1.8, 10);
                    ctx.bezierCurveTo(5.2, 4.7, 14.8, 4.7, 18.2, 10);
                    ctx.bezierCurveTo(14.8, 15.3, 5.2, 15.3, 1.8, 10);
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.arc(10, 10, 2.3, 0, Math.PI * 2);
                    ctx.stroke();
                    if (glyph.kind === "eye_off") {
                        ctx.beginPath();
                        ctx.moveTo(3, 3);
                        ctx.lineTo(17, 17);
                        ctx.stroke();
                    }
                } else if (glyph.kind === "cloud_off") {
                    ctx.beginPath();
                    ctx.moveTo(4, 14.5);
                    ctx.bezierCurveTo(0.7, 14, 1.1, 8.9, 4.5, 8.5);
                    ctx.bezierCurveTo(5.2, 4.1, 11.4, 3.5, 13.3, 7.4);
                    ctx.bezierCurveTo(18.2, 6.8, 20, 13.8, 15.2, 14.6);
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.moveTo(2.8, 2.8);
                    ctx.lineTo(17.2, 17.2);
                    ctx.stroke();
                } else if (glyph.kind === "shield") {
                    ctx.beginPath();
                    ctx.moveTo(10, 2.2);
                    ctx.lineTo(16.5, 4.8);
                    ctx.lineTo(16, 11.7);
                    ctx.bezierCurveTo(15.6, 15.2, 12.9, 17.3, 10, 18.2);
                    ctx.bezierCurveTo(7.1, 17.3, 4.4, 15.2, 4, 11.7);
                    ctx.lineTo(3.5, 4.8);
                    ctx.closePath();
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.moveTo(7, 10.1);
                    ctx.lineTo(9.1, 12.2);
                    ctx.lineTo(13.3, 7.8);
                    ctx.stroke();
                } else if (glyph.kind === "clock") {
                    ctx.beginPath();
                    ctx.arc(10, 10, 7.2, 0, Math.PI * 2);
                    ctx.stroke();
                    ctx.beginPath();
                    ctx.moveTo(10, 5.8);
                    ctx.lineTo(10, 10.2);
                    ctx.lineTo(13.2, 12.1);
                    ctx.stroke();
                }
            }
        }
    }

    component Entry: Column {
        id: entry

        property alias text: input.text
        property string label: ""
        property string placeholder: ""
        property string icon: "user"
        property string help: ""
        property string errorText: ""
        property bool secret: false
        property bool reveal: false
        signal blurred
        signal accepted

        spacing: 6

        function focusField(): void {
            input.forceActiveFocus();
        }

        function clear(): void {
            input.text = "";
            entry.reveal = false;
        }

        Meta {
            text: entry.label
            color: entry.errorText !== "" ? Theme.shellStatusBad : Theme.shellInk3
        }

        Item {
            width: parent.width
            height: 54

            Rectangle {
                id: fieldFrame

                anchors.fill: parent
                radius: Theme.radius
                color: Theme.shellSurface
                // QML draws Rectangle borders inside their bounds. Keeping
                // the 2 px focus state here prevents the Flickable viewport
                // from clipping an outward (-4 px) ring at the card edges.
                border.width: entry.errorText !== "" || input.activeFocus ? 2 : Theme.hairline
                border.color: entry.errorText !== ""
                    ? Theme.shellStatusBad
                    : (input.activeFocus ? Theme.shellFocusRing : Theme.shellInputBorder)
            }

            Glyph {
                id: leadingGlyph

                anchors.left: parent.left
                anchors.leftMargin: 16
                anchors.verticalCenter: parent.verticalCenter
                kind: entry.icon
                ink: input.activeFocus ? Theme.shellFg : Theme.shellInk3
            }

            Text {
                anchors.left: parent.left
                anchors.leftMargin: 48
                anchors.right: revealButton.visible ? revealButton.left : parent.right
                anchors.rightMargin: revealButton.visible ? 12 : 16
                anchors.verticalCenter: parent.verticalCenter
                visible: input.text === ""
                text: entry.placeholder
                elide: Text.ElideRight
                font.family: Theme.fontSans
                font.pixelSize: 15
                color: Theme.shellInk3
                Accessible.ignored: true
            }

            TextInput {
                id: input

                anchors.left: parent.left
                anchors.leftMargin: 48
                anchors.right: revealButton.visible ? revealButton.left : parent.right
                anchors.rightMargin: revealButton.visible ? 12 : 16
                anchors.verticalCenter: parent.verticalCenter
                height: 26
                enabled: entry.enabled
                echoMode: entry.secret && !entry.reveal ? TextInput.Password : TextInput.Normal
                passwordCharacter: "•"
                passwordMaskDelay: 0
                font.family: Theme.fontSans
                font.pixelSize: 16
                font.weight: 500
                color: Theme.shellFg
                selectionColor: Theme.shellFg
                selectedTextColor: Theme.shellSurface
                clip: true
                selectByMouse: true
                activeFocusOnTab: true
                Accessible.role: Accessible.EditableText
                Accessible.name: entry.label
                Accessible.description: entry.errorText !== "" ? entry.errorText : entry.help
                Accessible.passwordEdit: entry.secret && !entry.reveal

                onActiveFocusChanged: {
                    if (!activeFocus)
                        entry.blurred();
                }
                Keys.onPressed: function (event) {
                    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                        entry.accepted();
                        event.accepted = true;
                    } else if (event.key === Qt.Key_Escape && entry.secret) {
                        entry.clear();
                        event.accepted = true;
                    }
                }
            }

            Item {
                id: revealButton
                anchors.right: parent.right
                anchors.rightMargin: 10
                anchors.verticalCenter: input.verticalCenter
                width: visible ? 40 : 0
                height: 36
                visible: entry.secret
                activeFocusOnTab: visible
                Accessible.role: Accessible.Button
                Accessible.name: entry.reveal ? "Conceal password" : "Reveal password"

                Glyph {
                    id: revealText
                    anchors.centerIn: parent
                    kind: entry.reveal ? "eye_off" : "eye"
                    ink: revealButton.activeFocus ? Theme.shellFg : Theme.shellInk3
                }

                Rectangle {
                    anchors.fill: parent
                    anchors.margins: -2
                    visible: revealButton.activeFocus
                    color: "transparent"
                    radius: Theme.radius
                    border.width: 2
                    border.color: Theme.shellFocusRing
                }

                onActiveFocusChanged: if (!activeFocus)
                    entry.reveal = false
                Keys.onPressed: function (event) {
                    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Space) {
                        entry.reveal = !entry.reveal;
                        event.accepted = true;
                    }
                }
                MouseArea {
                    anchors.fill: parent
                    onClicked: entry.reveal = !entry.reveal
                }
            }

        }

        Text {
            width: parent.width
            text: entry.errorText !== "" ? entry.errorText : entry.help
            wrapMode: Text.Wrap
            font.family: Theme.fontSans
            font.pixelSize: 12
            lineHeight: 1.25
            color: entry.errorText !== "" ? Theme.shellStatusBad : Theme.shellInk3
            Accessible.ignored: true
        }
    }

    FileView {
        id: onboardingState
        path: "/run/punar/onboarding.json"
        blockLoading: true
        watchChanges: true
        onFileChanged: onboardingState.reload()
        onLoaded: root.parseState(onboardingState.text())
        onLoadFailed: {
            // The materializer normally writes this before greetd. Holding the
            // greeter on a quiet loading field is safer than guessing that an
            // account exists or opening a shell.
            root.stateLoaded = false;
        }
    }

    FileView {
        id: accountProjection
        path: "/run/punar/greeter.json"
        blockLoading: true
        watchChanges: true
        onFileChanged: accountProjection.reload()
        onLoaded: root.parseProjection(accountProjection.text())
    }

    Variants {
        model: Quickshell.screens

        PanelWindow {
            id: panel

            required property var modelData
            readonly property bool primary: Quickshell.screens.length > 0 && panel.modelData === Quickshell.screens[0]

            property bool receipt: false
            property bool accountBusy: false
            property bool loginBusy: false
            property bool accountHandled: false
            property bool loginHandled: false
            property string createdUsername: ""
            property string recoveryCode: ""
            property string formFailure: ""
            property string loginFailure: ""
            property string usernameBackendError: ""
            property string passwordBackendError: ""
            property string deviceBackendError: ""
            property int layoutIndex: 0
            property bool layoutsOpen: false
            property bool usernameTouched: false
            property bool passwordTouched: false
            property bool confirmTouched: false
            property bool deviceTouched: false

            screen: panel.modelData
            anchors {
                top: true
                bottom: true
                left: true
                right: true
            }
            exclusionMode: ExclusionMode.Ignore
            exclusiveZone: 0
            color: Theme.shellSurface
            WlrLayershell.layer: WlrLayer.Overlay
            WlrLayershell.namespace: "punar-greeter"
            WlrLayershell.keyboardFocus: panel.primary ? WlrKeyboardFocus.Exclusive : WlrKeyboardFocus.None

            function usernameError(): string {
                if (!panel.usernameTouched)
                    return "";
                var name = usernameField.text;
                if (!/^[a-z][a-z0-9_-]{0,31}$/.test(name) || name.endsWith("-"))
                    return "Start with a lowercase letter; use letters, numbers, _ or -.";
                if (["root", "nobody", "greeter", "punard", "punar"].indexOf(name) >= 0 || name.indexOf("punar-") === 0)
                    return "That name is reserved by the system. Choose another.";
                return "";
            }

            function passwordError(): string {
                if (panel.accountBusy || !panel.passwordTouched)
                    return "";
                if (passwordField.text.length < 10)
                    return "Use 10 or more characters. There are no symbol rules.";
                var folded = passwordField.text.toLowerCase();
                var compact = folded.replace(/[^a-z0-9]/g, "");
                var username = usernameField.text.toLowerCase();
                var device = deviceField.text.toLowerCase().replace(/[^a-z0-9]/g, "");
                if (folded.indexOf("punar") >= 0
                        || (username !== "" && compact.indexOf(username) >= 0)
                        || (device.length >= 4 && compact.indexOf(device) >= 0))
                    return "Avoid your username, device name, and Punar.";
                var common = ["1234567890", "123456789", "qwertyuiop", "qwerty12345",
                              "password", "password1", "password12", "password123",
                              "letmein123", "iloveyou123", "administrator", "welcome123",
                              "changeme123", "correcthorsebatterystaple"];
                if (common.indexOf(folded.trim()) >= 0)
                    return "That password is commonly guessed. Try three unrelated words.";
                return "";
            }

            function confirmError(): string {
                if (!panel.confirmTouched)
                    return "";
                if (confirmField.text !== passwordField.text)
                    return "Those passwords do not match.";
                return "";
            }

            function deviceError(): string {
                if (!panel.deviceTouched)
                    return "";
                if (deviceField.text.trim() === "")
                    return "Give this machine a name.";
                if (root.hostnameFor(deviceField.text) === "")
                    return "Use at least one Latin letter or number for its network name.";
                return "";
            }

            function validateAll(): bool {
                panel.usernameTouched = true;
                panel.passwordTouched = true;
                panel.confirmTouched = true;
                panel.deviceTouched = true;
                if (panel.usernameError() !== "") {
                    usernameField.focusField();
                    return false;
                }
                if (panel.passwordError() !== "") {
                    passwordField.focusField();
                    return false;
                }
                if (panel.confirmError() !== "") {
                    confirmField.focusField();
                    return false;
                }
                if (panel.deviceError() !== "") {
                    deviceField.focusField();
                    return false;
                }
                return true;
            }

            function createAccount(): void {
                panel.formFailure = "";
                panel.usernameBackendError = "";
                panel.passwordBackendError = "";
                panel.deviceBackendError = "";
                if (panel.accountBusy || !panel.validateAll())
                    return;
                panel.accountBusy = true;
                panel.accountHandled = false;
                accountProcess.stdinEnabled = true;
                accountProcess.running = true;
            }

            function finishAccount(body: string): void {
                if (panel.accountHandled)
                    return;
                panel.accountHandled = true;
                panel.accountBusy = false;
                var response = null;
                try {
                    response = JSON.parse(body);
                } catch (e) {
                    response = null;
                }
                if (response !== null && response.ok === true && typeof response.recoveryCode === "string") {
                    panel.createdUsername = response.username;
                    panel.recoveryCode = response.recoveryCode;
                    panel.receipt = true;
                    receiptPane.opacity = 1;
                    receiptPane.y = 0;
                    receiptHeading.forceActiveFocus();
                    return;
                }
                var message = response !== null && typeof response.message === "string" ? response.message : "Account creation is unavailable. Nothing was changed; restart and try again.";
                var field = response !== null ? response.field : null;
                if (field === "username") {
                    panel.formFailure = "";
                    panel.usernameBackendError = message;
                    usernameField.focusField();
                } else if (field === "password") {
                    panel.formFailure = "";
                    panel.passwordBackendError = message;
                    passwordField.focusField();
                } else if (field === "deviceName") {
                    panel.formFailure = "";
                    panel.deviceBackendError = message;
                    deviceField.focusField();
                } else {
                    panel.formFailure = message;
                    retryButton.forceActiveFocus();
                }
            }

            function login(): void {
                if (panel.loginBusy || loginPassword.text === "") {
                    if (loginPassword.text === "")
                        panel.loginFailure = "Enter your password.";
                    loginPassword.focusField();
                    return;
                }
                panel.loginFailure = "";
                panel.loginBusy = true;
                panel.loginHandled = false;
                loginProcess.stdinEnabled = true;
                loginProcess.running = true;
            }

            function finishLogin(body: string): void {
                if (panel.loginHandled)
                    return;
                panel.loginHandled = true;
                panel.loginBusy = false;
                var response = null;
                try {
                    response = JSON.parse(body);
                } catch (e) {
                    response = null;
                }
                if (response !== null && response.ok === true) {
                    exitGreeter.running = true;
                    return;
                }
                panel.loginFailure = response !== null && typeof response.message === "string" ? response.message : "The login service is unavailable. Restart and try again.";
                loginPassword.focusField();
            }

            Component.onCompleted: if (panel.primary && root.stateLoaded)
                Qt.callLater(function () {
                    if (root.firstRun)
                        usernameField.focusField();
                    else
                        loginPassword.focusField();
                })

            onPrimaryChanged: if (panel.primary && root.stateLoaded)
                Qt.callLater(function () {
                    if (root.firstRun)
                        usernameField.focusField();
                    else
                        loginPassword.focusField();
                })

            Connections {
                target: root
                function onStateLoadedChanged(): void {
                    if (!root.stateLoaded || !panel.primary)
                        return;
                    Qt.callLater(function () {
                        if (root.firstRun)
                            usernameField.focusField();
                        else
                            loginPassword.focusField();
                    });
                }
            }

            Process {
                id: layoutProcess
                command: ["hyprctl", "keyword", "input:kb_layout", root.keyboardLayouts[panel.layoutIndex].code]
            }

            Process {
                id: accountProcess
                command: ["/usr/bin/punar-onboard"]
                stdinEnabled: true
                stdout: StdioCollector {
                    id: accountOutput
                    waitForEnd: true
                    onStreamFinished: panel.finishAccount(accountOutput.text)
                }
                onStarted: {
                    accountProcess.write(JSON.stringify({
                        "v": 1,
                        "username": usernameField.text,
                        "password": passwordField.text,
                        "deviceName": deviceField.text,
                        "timezone": null
                    }) + "\n");
                    passwordField.clear();
                    confirmField.clear();
                    accountProcess.stdinEnabled = false;
                }
            }

            Process {
                id: loginProcess
                command: ["/usr/bin/punar-greet", "login"]
                stdinEnabled: true
                stdout: StdioCollector {
                    id: loginOutput
                    waitForEnd: true
                    onStreamFinished: panel.finishLogin(loginOutput.text)
                }
                onStarted: {
                    loginProcess.write(JSON.stringify({
                        "username": root.accountName,
                        "password": loginPassword.text
                    }) + "\n");
                    loginPassword.clear();
                    loginProcess.stdinEnabled = false;
                }
            }

            Process {
                id: firstSession
                stdout: StdioCollector {
                    id: firstOutput
                    waitForEnd: true
                    onStreamFinished: {
                        var response = null;
                        try {
                            response = JSON.parse(firstOutput.text);
                        } catch (e) {
                            response = null;
                        }
                        if (response !== null && response.ok === true)
                            exitGreeter.running = true;
                        else {
                            // The one-use PAM token may already have been
                            // consumed before session startup failed. Never
                            // loop on a token that cannot succeed twice: the
                            // account is complete, so fall through to the real
                            // password greeter and say exactly what changed.
                            root.accountName = panel.createdUsername;
                            root.firstRun = false;
                            panel.loginFailure = "Your account is ready, but the desktop did not start. Sign in with your password to try again.";
                            loginPassword.focusField();
                        }
                    }
                }
            }

            Process {
                id: copyProcess
                command: ["/usr/bin/wl-copy", "--paste-once"]
                stdinEnabled: true
                onStarted: {
                    copyProcess.write(panel.recoveryCode);
                    copyProcess.stdinEnabled = false;
                }
            }

            Process {
                id: exitGreeter
                command: ["hyprctl", "dispatch", "exit"]
            }

            Image {
                anchors.fill: parent
                // The greeter is a production-only session launched from the
                // installed tree. Keep its security-sensitive first frame on
                // one absolute, package-owned asset: Quickshell's entrypoint
                // URL differs between `qs -p …/shell` and `qs -p …/Greeter`,
                // and relative resolution silently rendered the fallback
                // surface in the real release VM.
                source: "file:///usr/share/punar/shell/Wallpaper/assets/stillpoint.jpg"
                fillMode: Image.PreserveAspectCrop
                asynchronous: false
                cache: true
                sourceSize: Qt.size(Math.round(panel.width), Math.round(panel.height))
            }

            Rectangle {
                anchors.fill: parent
                color: Theme.shellScrim
                opacity: Theme.moodPanel ? 0.42 : 0.16
            }

            Item {
                id: masthead
                // The keyboard menu drops into the card's vertical space.
                // Keep the whole masthead above the later card sibling so the
                // popover cannot be clipped behind the onboarding surface.
                z: 30
                visible: panel.primary
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: parent.top
                anchors.leftMargin: Math.max(28, parent.width * 0.045)
                anchors.rightMargin: Math.max(28, parent.width * 0.045)
                anchors.topMargin: Math.max(22, parent.height * 0.034)
                height: 48

                Meta {
                    anchors.left: parent.left
                    anchors.verticalCenter: parent.verticalCenter
                    text: root.firstRun ? "Welcome to Punar" : "Punar · " + root.deviceName
                    color: Theme.panelFg
                    font.weight: 600
                }

                Item {
                    id: keyboardControl
                    anchors.right: parent.right
                    anchors.verticalCenter: parent.verticalCenter
                    width: 120
                    height: 38
                    activeFocusOnTab: true
                    Accessible.role: Accessible.Button
                    Accessible.name: "Keyboard layout " + root.keyboardLayouts[panel.layoutIndex].label
                    Accessible.description: "Change the layout used to enter your password"

                    Meta {
                        anchors.centerIn: parent
                        text: "Keyboard · " + root.keyboardLayouts[panel.layoutIndex].label
                        color: Theme.ink
                        z: 1
                    }
                    Rectangle {
                        anchors.fill: parent
                        // This is a neutral setup control, not an alert. A
                        // paper button stays distinct from the dark wallpaper
                        // without borrowing the panel's black status-card look.
                        color: Theme.paperSurface
                        radius: Theme.radiusTag
                        border.width: Theme.hairline
                        border.color: Theme.inputBorder
                    }
                    Rectangle {
                        anchors.fill: parent
                        anchors.margins: -3
                        visible: keyboardControl.activeFocus
                        color: "transparent"
                        radius: Theme.radiusTag + 2
                        border.width: 2
                        border.color: Theme.panelFg
                    }
                    Keys.onPressed: function (event) {
                        if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Space) {
                            panel.layoutsOpen = !panel.layoutsOpen;
                            event.accepted = true;
                        } else if (event.key === Qt.Key_Escape) {
                            panel.layoutsOpen = false;
                            event.accepted = true;
                        }
                    }
                    MouseArea {
                        anchors.fill: parent
                        onClicked: panel.layoutsOpen = !panel.layoutsOpen
                    }
                }

                Rectangle {
                    id: layoutMenu
                    visible: panel.layoutsOpen
                    anchors.right: keyboardControl.right
                    anchors.top: keyboardControl.bottom
                    anchors.topMargin: 8
                    width: layoutChoices.implicitWidth + 20
                    height: layoutChoices.implicitHeight + 18
                    radius: Theme.radiusTag
                    color: Theme.paperSurface
                    border.width: Theme.hairline
                    border.color: Theme.inputBorder
                    z: 20

                    Row {
                        id: layoutChoices
                        anchors.centerIn: parent
                        spacing: 4

                        Repeater {
                            model: root.keyboardLayouts

                            Rectangle {
                                id: layoutChoice
                                required property int index
                                required property var modelData
                                width: 34
                                height: 28
                                radius: Theme.radiusTag
                                color: panel.layoutIndex === layoutChoice.index ? Theme.raise2 : Theme.paperSurface
                                border.width: panel.layoutIndex === layoutChoice.index ? Theme.hairline : 0
                                border.color: Theme.inputBorder
                                activeFocusOnTab: layoutMenu.visible
                                Accessible.role: Accessible.Button
                                Accessible.name: layoutChoice.modelData.label + " keyboard layout"

                                Meta {
                                    anchors.centerIn: parent
                                    text: layoutChoice.modelData.label
                                    color: Theme.ink
                                }
                                Rectangle {
                                    anchors.fill: parent
                                    anchors.margins: -2
                                    visible: layoutChoice.activeFocus
                                    color: "transparent"
                                    radius: Theme.radiusTag
                                    border.width: 2
                                    border.color: Theme.ink
                                }
                                function select(): void {
                                    panel.layoutIndex = layoutChoice.index;
                                    layoutProcess.command = ["hyprctl", "keyword", "input:kb_layout", layoutChoice.modelData.code];
                                    layoutProcess.running = true;
                                    panel.layoutsOpen = false;
                                }
                                Keys.onPressed: function (event) {
                                    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter || event.key === Qt.Key_Space) {
                                        layoutChoice.select();
                                        event.accepted = true;
                                    }
                                }
                                MouseArea {
                                    anchors.fill: parent
                                    onClicked: layoutChoice.select()
                                }
                            }
                        }
                    }
                }

                Rectangle {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    anchors.bottom: parent.bottom
                    height: Theme.hairline
                    color: Theme.panelInk3
                }
            }

            Rectangle {
                id: card
                visible: panel.primary && root.stateLoaded
                anchors.horizontalCenter: parent.horizontalCenter
                anchors.verticalCenter: parent.verticalCenter
                anchors.verticalCenterOffset: 18
                width: Math.min(root.firstRun ? 960 : 720, parent.width - 64)
                height: Math.min(root.firstRun ? 690 : 500, parent.height - 142)
                radius: Theme.radius + Theme.radiusTag
                color: Theme.shellSurface
                border.width: Theme.hairline
                border.color: Theme.shellInputBorder

                Flickable {
                    id: viewport

                    readonly property real horizontalPadding: Math.max(24, Math.min(52, card.width * 0.057))

                    anchors.fill: parent
                    anchors.leftMargin: viewport.horizontalPadding
                    anchors.rightMargin: viewport.horizontalPadding
                    anchors.topMargin: Math.max(24, Math.min(40, card.height * 0.06))
                    anchors.bottomMargin: Math.max(20, Math.min(28, card.height * 0.042))
                    contentWidth: width
                    contentHeight: content.implicitHeight
                    clip: true
                    boundsBehavior: Flickable.StopAtBounds
                    interactive: contentHeight > height

                    Column {
                        id: content
                        width: viewport.width
                        spacing: 0

                        Column {
                            id: onboardingForm
                            width: parent.width
                            visible: root.firstRun && !panel.receipt
                            spacing: 24

                            Column {
                                width: parent.width
                                spacing: 8
                                Text {
                                    width: parent.width
                                    text: card.width >= 820 ? "Make this\nmachine yours." : "Make this machine yours."
                                    wrapMode: Text.Wrap
                                    font.family: Theme.fontSans
                                    font.pixelSize: card.width >= 820 ? 48 : 36
                                    font.weight: 650
                                    font.letterSpacing: -0.025 * font.pixelSize
                                    lineHeight: 0.94
                                    color: Theme.shellFg
                                }
                                Text {
                                    width: parent.width
                                    text: "Three details, then the desktop is ready."
                                    wrapMode: Text.Wrap
                                    font.family: Theme.fontSans
                                    font.pixelSize: 15
                                    color: Theme.shellInk2
                                }
                            }

                            Entry {
                                id: usernameField
                                width: parent.width
                                label: "Username"
                                placeholder: "e.g. yourname"
                                icon: "user"
                                help: "Your home folder and terminal name. This cannot be changed later."
                                errorText: panel.usernameBackendError !== "" ? panel.usernameBackendError : panel.usernameError()
                                enabled: !panel.accountBusy
                                onTextChanged: panel.usernameBackendError = ""
                                onBlurred: panel.usernameTouched = true
                                onAccepted: passwordField.focusField()
                            }

                            Grid {
                                id: passwordGrid
                                width: parent.width
                                columns: width >= 520 ? 2 : 1
                                columnSpacing: 24
                                rowSpacing: 20

                                Entry {
                                    id: passwordField
                                    width: passwordGrid.columns === 2 ? (passwordGrid.width - passwordGrid.columnSpacing) / 2 : passwordGrid.width
                                    label: "Password"
                                    placeholder: "Enter password"
                                    icon: "lock"
                                    help: "Use 10 or more characters. No symbol rules or forced rotation."
                                    errorText: panel.passwordBackendError !== "" ? panel.passwordBackendError : panel.passwordError()
                                    secret: true
                                    enabled: !panel.accountBusy
                                    onTextChanged: panel.passwordBackendError = ""
                                    onBlurred: panel.passwordTouched = true
                                    onAccepted: confirmField.focusField()
                                }
                                Entry {
                                    id: confirmField
                                    width: passwordGrid.columns === 2 ? (passwordGrid.width - passwordGrid.columnSpacing) / 2 : passwordGrid.width
                                    label: "Confirm password"
                                    placeholder: "Confirm password"
                                    icon: "lock"
                                    help: "Type the same password again."
                                    errorText: panel.confirmError()
                                    secret: true
                                    enabled: !panel.accountBusy
                                    onBlurred: panel.confirmTouched = true
                                    onAccepted: deviceField.focusField()
                                }
                            }

                            Entry {
                                id: deviceField
                                width: parent.width
                                label: "Device name"
                                placeholder: "e.g. punar-studio"
                                icon: "device"
                                help: "The name shown on your network. Timezone is selected automatically."
                                errorText: panel.deviceBackendError !== "" ? panel.deviceBackendError : panel.deviceError()
                                enabled: !panel.accountBusy
                                onTextChanged: panel.deviceBackendError = ""
                                onBlurred: panel.deviceTouched = true
                                onAccepted: panel.createAccount()
                            }

                            Text {
                                width: parent.width
                                visible: panel.formFailure !== ""
                                text: panel.formFailure
                                wrapMode: Text.Wrap
                                font.family: Theme.fontSans
                                font.pixelSize: 13
                                lineHeight: 1.3
                                color: Theme.shellStatusBad
                                Accessible.role: Accessible.AlertMessage
                            }

                            Grid {
                                id: footerGrid

                                width: parent.width
                                columns: width >= 760 ? 2 : 1
                                columnSpacing: 24
                                rowSpacing: 18

                                Grid {
                                    id: privacyGrid

                                    width: footerGrid.columns === 2 ? footerGrid.width - footerGrid.columnSpacing - 142 : footerGrid.width
                                    columns: width >= 560 ? 3 : 1
                                    columnSpacing: 20
                                    rowSpacing: 12

                                    Repeater {
                                        model: [
                                            {
                                                "title": "Local account",
                                                "detail": "Created on this device",
                                                "icon": "lock"
                                            },
                                            {
                                                "title": "No email required",
                                                "detail": "Start without a cloud login",
                                                "icon": "cloud_off"
                                            },
                                            {
                                                "title": "Private setup",
                                                "detail": "These details stay here",
                                                "icon": "shield"
                                            }
                                        ]

                                        Row {
                                            id: privacyFact

                                            required property var modelData
                                            width: privacyGrid.columns === 3 ? (privacyGrid.width - privacyGrid.columnSpacing * 2) / 3 : privacyGrid.width
                                            spacing: 10

                                            Glyph {
                                                anchors.top: parent.top
                                                anchors.topMargin: 1
                                                kind: privacyFact.modelData.icon
                                                ink: Theme.shellInk3
                                            }

                                            Column {
                                                width: privacyFact.width - 30
                                                spacing: 3

                                                Text {
                                                    width: parent.width
                                                    text: privacyFact.modelData.title
                                                    font.family: Theme.fontSans
                                                    font.pixelSize: 12
                                                    font.weight: 650
                                                    color: Theme.shellFg
                                                }
                                                Text {
                                                    width: parent.width
                                                    text: privacyFact.modelData.detail
                                                    wrapMode: Text.Wrap
                                                    font.family: Theme.fontSans
                                                    font.pixelSize: 11
                                                    color: Theme.shellInk3
                                                }
                                            }
                                        }
                                    }
                                }

                                Item {
                                    width: footerGrid.columns === 2 ? 142 : footerGrid.width
                                    height: 46

                                    Action {
                                        id: retryButton
                                        anchors.right: parent.right
                                        anchors.verticalCenter: parent.verticalCenter
                                        label: panel.formFailure === "" ? "Continue" : "Retry"
                                        busy: panel.accountBusy
                                        enabled: !panel.accountBusy
                                        onInvoked: panel.createAccount()
                                    }
                                }
                            }
                        }

                        Column {
                            id: receiptPane
                            width: parent.width
                            visible: root.firstRun && panel.receipt
                            opacity: 0
                            y: 18
                            spacing: 26

                            Behavior on opacity {
                                NumberAnimation {
                                    duration: root.reducedMotion ? 0 : Theme.durStandard
                                    easing.type: Easing.BezierSpline
                                    easing.bezierCurve: Theme.easingCurve
                                }
                            }
                            Behavior on y {
                                NumberAnimation {
                                    duration: root.reducedMotion ? 0 : Theme.durStandard
                                    easing.type: Easing.BezierSpline
                                    easing.bezierCurve: Theme.easingCurve
                                }
                            }

                            Text {
                                id: receiptHeading
                                width: parent.width
                                text: "You're ready, " + panel.createdUsername
                                wrapMode: Text.Wrap
                                font.family: Theme.fontSans
                                font.pixelSize: 30
                                font.weight: 700
                                font.letterSpacing: -0.02 * 30
                                color: Theme.shellFg
                                focus: true
                                Accessible.role: Accessible.Heading
                                Accessible.name: text
                            }

                            Rectangle {
                                width: parent.width
                                height: recoveryColumn.implicitHeight + 36
                                radius: Theme.radiusTag
                                color: Theme.shellMuted
                                border.width: Theme.hairline
                                border.color: Theme.shellBorder

                                Column {
                                    id: recoveryColumn
                                    anchors.left: parent.left
                                    anchors.right: copyButton.left
                                    anchors.leftMargin: 18
                                    anchors.rightMargin: 16
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: 8

                                    Meta {
                                        text: "Recovery code"
                                        color: Theme.shellInk3
                                    }
                                    Text {
                                        width: parent.width
                                        text: panel.recoveryCode
                                        wrapMode: Text.WrapAnywhere
                                        font.family: Theme.fontMono
                                        font.pixelSize: 16
                                        font.weight: 600
                                        font.letterSpacing: Theme.tracking(16, 0.08)
                                        color: Theme.shellFg
                                        Accessible.name: "Recovery code " + panel.recoveryCode
                                        Accessible.description: "Shown once. Save it somewhere off this device."
                                    }
                                    Text {
                                        width: parent.width
                                        text: "Save this somewhere off the device. It is shown once."
                                        wrapMode: Text.Wrap
                                        font.family: Theme.fontSans
                                        font.pixelSize: 12
                                        color: Theme.shellInk3
                                    }
                                }

                                Action {
                                    id: copyButton
                                    anchors.right: parent.right
                                    anchors.rightMargin: 16
                                    anchors.verticalCenter: parent.verticalCenter
                                    label: copyProcess.running ? "Copied" : "Copy"
                                    hint: ""
                                    quiet: true
                                    enabled: !copyProcess.running
                                    onInvoked: {
                                        copyProcess.stdinEnabled = true;
                                        copyProcess.running = true;
                                    }
                                }
                            }

                            Text {
                                width: parent.width
                                visible: panel.formFailure !== ""
                                text: panel.formFailure
                                wrapMode: Text.Wrap
                                font.family: Theme.fontSans
                                font.pixelSize: 13
                                color: Theme.shellStatusBad
                                Accessible.role: Accessible.AlertMessage
                            }

                            Item {
                                width: parent.width
                                height: 48
                                Action {
                                    id: enterButton
                                    anchors.right: parent.right
                                    label: "Enter desktop"
                                    busy: false
                                    onInvoked: {
                                        enterButton.busy = true;
                                        panel.formFailure = "";
                                        firstSession.command = ["/usr/bin/punar-greet", "first", panel.createdUsername];
                                        firstSession.running = true;
                                    }
                                }
                            }
                        }

                        Column {
                            id: loginForm
                            width: parent.width
                            visible: !root.firstRun
                            spacing: 28

                            Column {
                                width: parent.width
                                spacing: 8
                                Text {
                                    width: parent.width
                                    text: "Welcome back"
                                    font.family: Theme.fontSans
                                    font.pixelSize: 30
                                    font.weight: 700
                                    font.letterSpacing: -0.02 * 30
                                    color: Theme.shellFg
                                }
                                Text {
                                    width: parent.width
                                    text: "Your work is where you left it."
                                    font.family: Theme.fontSans
                                    font.pixelSize: 15
                                    color: Theme.shellInk2
                                }
                            }

                            Row {
                                spacing: 14
                                Rectangle {
                                    anchors.verticalCenter: parent.verticalCenter
                                    width: 44
                                    height: 44
                                    radius: 22
                                    color: Theme.shellSurface
                                    border.width: Theme.hairline
                                    border.color: Theme.shellInputBorder
                                    Text {
                                        anchors.centerIn: parent
                                        text: root.accountName === "" ? "·" : root.accountName.substring(0, 1).toUpperCase()
                                        font.family: Theme.fontSans
                                        font.pixelSize: 17
                                        font.weight: 700
                                        color: Theme.shellFg
                                    }
                                }
                                Column {
                                    anchors.verticalCenter: parent.verticalCenter
                                    spacing: 3
                                    Text {
                                        text: root.accountName
                                        font.family: Theme.fontSans
                                        font.pixelSize: 16
                                        font.weight: 600
                                        color: Theme.shellFg
                                    }
                                    Meta {
                                        text: "Local account"
                                    }
                                }
                            }

                            Entry {
                                id: loginPassword
                                width: parent.width
                                label: "Password"
                                help: "Unlock " + root.accountName + " on this device."
                                errorText: panel.loginFailure
                                secret: true
                                enabled: !panel.loginBusy
                                onAccepted: panel.login()
                            }

                            Item {
                                width: parent.width
                                height: 48
                                Action {
                                    anchors.right: parent.right
                                    label: "Sign in"
                                    busy: panel.loginBusy
                                    enabled: !panel.loginBusy
                                    onInvoked: panel.login()
                                }
                            }
                        }
                    }
                }
            }

            Column {
                visible: panel.primary && !root.stateLoaded
                anchors.centerIn: parent
                spacing: 10
                Meta {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "Preparing this device"
                    color: Theme.shellFg
                }
                Text {
                    anchors.horizontalCenter: parent.horizontalCenter
                    text: "Identity services are starting."
                    font.family: Theme.fontSans
                    font.pixelSize: 13
                    color: Theme.shellInk2
                }
            }
        }
    }
}
