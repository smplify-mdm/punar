pragma Singleton
// DeviceAdmin — whether the person in this session administers the device
// (F0-S1; docs/api/ipc.md §23.3), read through `punarctl --json admins
// list`, the verb a terminal runs (terminal parity).
//
// WHY A SURFACE ASKS BEFORE IT SHOWS A PASSWORD FIELD. A change that reaches
// everyone on the device needs a device administrator, and punard checks the
// role before it spends a password. A surface that asked everyone for their
// password first would have a person without the role type it for a change
// that cannot happen — and punarctl, which also checks first, would never
// send it. So a surface reads this, and shows a person without the role who
// can act instead of a password field.
//
// This is display state, never the authorization: punard decides every
// change, and a stale answer here only costs a refusal punard then gives.
// Read on user action (a surface opening), never on a clock.

import QtQuick
import Quickshell
import Quickshell.Io

Singleton {
    id: root

    // True once an answer has parsed. Until then a surface shows its password
    // field, and punarctl's own role check stands behind it.
    property bool known: false
    property bool administrator: false
    property bool isRoot: false
    // Who administers the device, as punard names them.
    property var administrators: []
    // "local", "pinned" or "none" (an organization decides).
    property string mode: "local"
    // The organization that decides, when one does.
    property string organization: ""

    /// Whether this person may make a change that reaches everyone, as far
    /// as this surface knows. Unknown counts as yes: punard decides.
    readonly property bool mayAdminister: !root.known || root.administrator || root.isRoot

    function refresh(): void {
        if (list.running)
            return;
        try {
            list.running = true;
        } catch (e) {
            root.known = false;
        }
    }

    /// What a person without the role reads in place of a password field:
    /// what they asked for, why it needs an administrator, and who can act.
    function refusal(doing: string): string {
        var names = Array.isArray(root.administrators) ? root.administrators.join(", ") : "";
        if (root.mode === "none")
            return doing + " needs a device administrator, and "
                + (root.organization !== "" ? root.organization : "your organization")
                + " has turned local administration off on this device. Ask them to make this change.";
        if (root.mode === "pinned")
            return doing + " needs a device administrator, and "
                + (root.organization !== "" ? root.organization : "your organization")
                + " decides who that is"
                + (names !== "" ? ": " + names + "." : ".")
                + " Ask " + (names !== "" ? names : "them") + " to make this change.";
        if (names === "")
            return doing + " needs a device administrator, and this device has none right now.";
        return doing + " reaches everyone who uses this device, so it needs a device administrator: "
            + names + ". Ask " + names + " to make this change, or to make you an administrator.";
    }

    Process {
        id: list

        command: ["/usr/bin/punarctl", "--json", "admins", "list"]
        stdout: StdioCollector {
            id: listOut
            waitForEnd: true
        }

        // Connected, not declared: see Probe in SystemControl/ControlData.qml.
        Component.onCompleted: list.exited.connect(function (exitCode) {
            var said = null;
            if (exitCode === 0) {
                try {
                    said = JSON.parse(String(listOut.text));
                } catch (e) {
                    said = null;
                }
            }
            if (said === null || typeof said !== "object" || said.caller === null
                    || typeof said.caller !== "object") {
                root.known = false;
                return;
            }
            root.administrator = said.caller.administrator === true;
            root.isRoot = said.caller.root === true;
            root.administrators = Array.isArray(said.administrators) ? said.administrators : [];
            root.mode = typeof said.mode === "string" ? said.mode : "local";
            root.organization = said.source !== null && typeof said.source === "object"
                && typeof said.source.name === "string" ? said.source.name : "";
            root.known = true;
        })
    }
}
