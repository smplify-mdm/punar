// Live, fixture-free Mail model. Every row originates in the protected local
// PIM channel inherited by `punar-mail-bridge`; a transport failure produces an
// explicit state and never falls back to sample messages.

pragma ComponentBehavior: Bound

import QtQuick
import Quickshell
import Quickshell.Io

QtObject {
    id: root

    property bool enabled: true
    readonly property string socketPath: Quickshell.env("PUNAR_MAIL_SOCKET")
    property string state: "connecting"
    property string detail: "Connecting to your private Mail service…"
    property string account: ""
    property string protocol: ""
    property string syncedAt: ""
    property var threads: []
    property var folders: []
    property var views: [{ "name": "Inbox", "count": -1, "current": true }]
    property int nextRequest: 1
    property var requests: ({})

    readonly property int unreadCount: {
        var count = 0;
        for (var i = 0; i < root.threads.length; i++)
            if (root.threads[i].unread === true)
                count++;
        return count;
    }

    readonly property string stateTitle: {
        if (root.state === "no_account")
            return "Connect a mail account";
        if (root.state === "auth_required")
            return "Your mail account needs attention";
        if (root.state === "empty")
            return "Inbox zero";
        if (root.state === "error")
            return "Mail is unavailable";
        return "Loading your inbox";
    }

    readonly property string footerStatus: {
        if (root.state === "ready" || root.state === "empty")
            return root.syncedAt === "" ? "LOCAL MAIL · WAITING FOR FIRST SYNC"
                : "LAST SYNC · " + root.syncedAt;
        return root.detail.toUpperCase();
    }

    signal threadLoaded(var thread, var messages)
    signal threadFailed(var thread, string message)

    Component.onCompleted: {
        if (root.enabled && root.socketPath === "")
            root.fail("Mail was not launched through its protected service.");
    }

    function slotFor(label: string): int {
        // A stable neutral sequence until user-owned label colours are stored.
        var slots = [1, 5, 3, 4, 6, 2, 7, 0];
        var value = 0;
        for (var i = 0; i < label.length; i++)
            value = (value * 33 + label.charCodeAt(i)) % slots.length;
        return slots[value];
    }

    function request(method: string, params: var, context: var): void {
        if (!transport.connected) {
            fail("The private Mail service is not connected.");
            return;
        }
        var id = "mail-ui-" + root.nextRequest++;
        root.requests[id] = { "method": method, "context": context };
        transport.write(JSON.stringify({
            "v": 1,
            "id": id,
            "method": method,
            "params": params
        }) + "\n");
        transport.flush();
    }

    function bootstrap(): void {
        root.state = "connecting";
        root.detail = "Reading your account list…";
        root.request("accounts.list", { "cursor": null, "limit": 100 }, null);
    }

    function openThread(thread: var): void {
        root.request("mail.thread", {
            "thread_id": thread.thread_id,
            "cursor": null,
            "limit": 100
        }, thread);
    }

    function handleFrame(frame: string): void {
        var response;
        try {
            response = JSON.parse(frame);
        } catch (error) {
            fail("Mail returned an unreadable response.");
            return;
        }
        var pending = root.requests[response.id];
        if (pending === undefined)
            return;
        delete root.requests[response.id];
        if (response.error !== undefined) {
            handleError(pending, response.error);
            return;
        }
        if (response.result === undefined) {
            fail("Mail returned an incomplete response.");
            return;
        }
        if (pending.method === "accounts.list")
            acceptAccounts(response.result);
        else if (pending.method === "mail.list")
            acceptInbox(response.result);
        else if (pending.method === "mail.thread")
            acceptThread(pending.context, response.result);
    }

    function acceptAccounts(result: var): void {
        var accounts = result.items === undefined ? [] : result.items;
        var selected = null;
        for (var i = 0; i < accounts.length; i++) {
            var capabilities = accounts[i].capabilities || [];
            if (capabilities.indexOf("mail") >= 0
                    && (selected === null || accounts[i].auth_state === "ready"))
                selected = accounts[i];
        }
        if (selected === null) {
            root.state = "no_account";
            root.detail = "Open Settings → Accounts to connect one.";
            root.account = "";
            root.protocol = "";
            root.threads = [];
            return;
        }
        root.account = selected.primary_address !== null
            ? selected.primary_address.address : selected.display_name;
        root.protocol = selected.provider_type === "open_protocols" ? "IMAP"
            : selected.provider_type.toUpperCase();
        root.syncedAt = formatSync(selected.last_sync_at);
        if (selected.auth_state !== "ready") {
            root.state = "auth_required";
            root.detail = "Open Settings → Accounts to sign in again.";
            root.threads = [];
            return;
        }
        root.state = "loading";
        root.detail = selected.connectivity === "offline"
            ? "Offline · showing mail stored on this device…"
            : "Reading Inbox…";
        root.request("mail.list", {
            "account_id": selected.account_id,
            "view": "inbox",
            "query": null,
            "cursor": null,
            "limit": 100
        }, selected);
    }

    function acceptInbox(result: var): void {
        var source = result.items === undefined ? [] : result.items;
        var mapped = [];
        for (var i = 0; i < source.length; i++)
            mapped.push(mapSummary(source[i]));
        root.threads = mapped;
        root.state = mapped.length === 0 ? "empty" : "ready";
        root.detail = mapped.length === 0 ? "No messages are stored for this inbox yet." : "";
    }

    function acceptThread(thread: var, result: var): void {
        var source = result.messages === undefined ? [] : result.messages;
        var messages = [];
        for (var i = 0; i < source.length; i++)
            messages.push(mapMessage(source[i]));
        root.threadLoaded(thread, messages);
    }

    function handleError(pending: var, error: var): void {
        var code = error.code === undefined ? "internal" : error.code;
        var message = code === "upstream_auth_required"
            ? "Open Settings → Accounts to sign in again."
            : code === "offline" || code === "upstream_unreachable"
                ? "Mail could not reach the account. Stored messages remain available."
                : "The private Mail service refused this request.";
        if (pending.method === "mail.thread") {
            root.threadFailed(pending.context, message);
            return;
        }
        root.state = code === "upstream_auth_required" ? "auth_required" : "error";
        root.detail = message;
        root.threads = [];
    }

    function fail(message: string): void {
        if (!root.enabled)
            return;
        root.state = "error";
        root.detail = message;
        root.threads = [];
    }

    function mapSummary(summary: var): var {
        return {
            "thread_id": summary.thread_id,
            "group": groupFor(summary.received_at),
            "unread": summary.unread === true,
            "marked": summary.starred === true,
            "correspondent": correspondents(summary.correspondents),
            "depth": 0,
            "subject": summary.subject || "(no subject)",
            "preview": summary.preview || "",
            "labels": summary.labels || [],
            "attachment": attachmentText(summary.attachments_count || 0),
            "time": timeFor(summary.received_at)
        };
    }

    function mapMessage(message: var): var {
        var sender = message.sender || { "name": null, "address": "unknown" };
        return {
            "from": sender.name === null || sender.name === "" ? sender.address : sender.name,
            "address": sender.address,
            "date": fullDate(message.sent_at),
            "remote": message.remote_content_blocked === true,
            "body": message.plain_text || ""
        };
    }

    function correspondents(values: var): string {
        if (values === undefined || values.length === 0)
            return "Unknown sender";
        var first = values[0].name === null || values[0].name === ""
            ? values[0].address : values[0].name;
        return values.length === 1 ? first : first + " +" + (values.length - 1);
    }

    function attachmentText(count: int): string {
        if (count <= 0)
            return "";
        return count === 1 ? "1 FILE" : count + " FILES";
    }

    function parsed(iso: string): var {
        var date = new Date(iso);
        return isNaN(date.getTime()) ? null : date;
    }

    function sameDate(a: var, b: var): bool {
        return a.getFullYear() === b.getFullYear()
            && a.getMonth() === b.getMonth() && a.getDate() === b.getDate();
    }

    function groupFor(iso: string): string {
        var date = parsed(iso);
        if (date === null)
            return "Earlier";
        var now = new Date();
        if (sameDate(date, now))
            return "Today";
        var yesterday = new Date(now.getFullYear(), now.getMonth(), now.getDate() - 1);
        if (sameDate(date, yesterday))
            return "Yesterday";
        var age = now.getTime() - date.getTime();
        if (age >= 0 && age < 7 * 24 * 60 * 60 * 1000)
            return "This week";
        if (date.getFullYear() === now.getFullYear() && date.getMonth() === now.getMonth())
            return "Earlier this month";
        return date.getFullYear() === now.getFullYear()
            ? Qt.formatDate(date, "MMMM") : Qt.formatDate(date, "MMMM yyyy");
    }

    function timeFor(iso: string): string {
        var date = parsed(iso);
        if (date === null)
            return "";
        var now = new Date();
        if (sameDate(date, now))
            return Qt.formatTime(date, "HH:mm");
        return date.getFullYear() === now.getFullYear()
            ? Qt.formatDate(date, "dd MMM").toUpperCase()
            : Qt.formatDate(date, "yyyy");
    }

    function fullDate(iso: string): string {
        var date = parsed(iso);
        return date === null ? "" : Qt.formatDateTime(date, "d MMM yyyy · HH:mm");
    }

    function formatSync(iso: var): string {
        if (iso === null || iso === undefined)
            return "";
        var date = parsed(iso);
        return date === null ? "" : Qt.formatDateTime(date, "d MMM · HH:mm").toUpperCase();
    }

    property Socket transport: Socket {
        path: root.socketPath
        connected: root.enabled && root.socketPath !== ""

        onConnectedChanged: {
            if (connected)
                root.bootstrap();
            else if (root.enabled)
                root.fail("The private Mail service disconnected.");
        }
        // Quickshell exposes the C++ QLocalSocket error enum in this signal,
        // but does not register that enum as a QML type for qmllint. The
        // handler deliberately ignores the unrepresentable argument.
        // qmllint disable signal-handler-parameters
        onError: root.fail("The private Mail service could not be reached.")
        // qmllint enable signal-handler-parameters
        parser: SplitParser {
            onRead: function(data) {
                root.handleFrame(data);
            }
        }
    }
}
