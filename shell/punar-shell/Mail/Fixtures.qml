// Static fixture data for the Mail index.
//
// THIS IS NOT A MAILBOX AND MUST NEVER BECOME ONE. Every string here is written
// by hand so the rail and the thread list can be judged on density, rhythm and
// type before any protocol code exists. Nothing reads a server, nothing touches
// the disk, and the surface that renders this says so in its own footer.
//
// It is deliberately awkward in the places a real mailbox is awkward — a
// fourteen-message thread, a sender with two co-recipients, a subject that must
// elide, three labels where only two fit, a group with a single row, an
// eight-month-old thread that falls past the month heads into a year. A fixture
// that is all short tidy strings proves a layout that does not exist.
//
// Times and dates are FIXED STRINGS, not computed. A fixture that changes with
// the clock cannot be screenshotted twice and compared, and the design's own
// rule is that the time column is fixed-width so the column never jitters.

import QtQuick

QtObject {
    id: root

    readonly property string account: "alice@example.com"
    readonly property string protocol: "IMAP"
    readonly property string syncedAt: "08:26"

    // VIEWS carry counts; a count of 0 is absent rather than rendered as "0".
    readonly property var views: [
        { "name": "Inbox", "count": 12, "current": true },
        { "name": "Starred", "count": 3, "current": false },
        { "name": "Attachments", "count": 0, "current": false },
        { "name": "Drafts", "count": 1, "current": false }
    ]

    // Server strings, printed VERBATIM and never uppercased — the folder names
    // belong to the server, and rewriting them would be the shell asserting
    // something about someone else's mailbox.
    readonly property var folders: ["Sent", "Archive", "Junk", "Receipts/2026"]

    // `group` is the fixed time ladder from the design: TODAY · YESTERDAY ·
    // THIS WEEK · LAST 30 DAYS · one head per month · then one per year.
    readonly property var threads: [
        {
            "group": "Today", "unread": true, "marked": false,
            "correspondent": "Stripe", "depth": 0,
            "subject": "Your invoice for August",
            "preview": "A copy of invoice 4C21-8890 is attached. No action is needed if you have already paid.",
            "labels": ["Receipts"], "attachment": "PDF", "time": "14:02"
        },
        {
            "group": "Today", "unread": true, "marked": false,
            "correspondent": "Aisha Rahman +2", "depth": 14,
            "subject": "Re: Release notes for the September build",
            "preview": "I have folded in the installer section. The rollback paragraph still needs a number from you.",
            "labels": ["Work", "Release"], "attachment": "", "time": "11:47"
        },
        {
            "group": "Today", "unread": false, "marked": false,
            "correspondent": "Deutsche Bahn", "depth": 0,
            "subject": "Ihre Fahrkarte · Berlin Hbf → München Hbf",
            "preview": "Bitte halten Sie diese Fahrkarte während der Fahrt bereit.",
            "labels": ["Travel"], "attachment": "2 FILES", "time": "09:15"
        },
        {
            "group": "Yesterday", "unread": true, "marked": false,
            "correspondent": "Nadia Okonkwo", "depth": 3,
            "subject": "The thing we talked about on Tuesday, and why I think the second option is worse than it looks",
            "preview": "Sorry for the length. The short version is that the migration cost is front-loaded and we would be paying it twice.",
            "labels": ["Work", "Decisions", "Q3"], "attachment": "", "time": "18:31"
        },
        {
            "group": "Yesterday", "unread": false, "marked": false,
            "correspondent": "GitHub", "depth": 2,
            "subject": "[punar] CI failed on reboot-polkit-and-policy-set-review-fixes",
            "preview": "arm64-image failed. snapshot.debian.org returned 503 for 20 packages.",
            "labels": ["Automated"], "attachment": "", "time": "16:04"
        },
        {
            "group": "This week", "unread": false, "marked": false,
            "correspondent": "Mum", "depth": 6,
            "subject": "Sunday",
            "preview": "Bring the blue dish back if you remember. No rush at all.",
            "labels": [], "attachment": "", "time": "07 SEP"
        },
        {
            "group": "This week", "unread": false, "marked": false,
            "correspondent": "Flathub", "depth": 0,
            "subject": "org.gnome.Evolution has been updated",
            "preview": "A new build is available for aarch64 and x86_64.",
            "labels": ["Automated"], "attachment": "", "time": "06 SEP"
        },
        {
            "group": "Last 30 days", "unread": false, "marked": false,
            "correspondent": "Ines Varga", "depth": 0,
            "subject": "Invoice + the two photographs you asked for",
            "preview": "Both are full resolution. Let me know if you need them in another format.",
            "labels": ["Receipts"], "attachment": "ZIP", "time": "22 AUG"
        },
        {
            "group": "August 2026", "unread": false, "marked": false,
            "correspondent": "Council Tax", "depth": 0,
            "subject": "Your annual statement is ready",
            "preview": "Sign in to view your statement. This message was sent to a notification-only address.",
            "labels": [], "attachment": "", "time": "03 AUG"
        },
        {
            "group": "2025", "unread": false, "marked": false,
            "correspondent": "Tomás Ferreira", "depth": 9,
            "subject": "Re: Re: the flat",
            "preview": "Landlord finally replied. Keys on the 14th, which is later than either of us wanted.",
            "labels": ["Personal"], "attachment": "", "time": "2025"
        }
    ]

    readonly property int unreadCount: {
        var n = 0;
        for (var i = 0; i < root.threads.length; i++)
            if (root.threads[i].unread === true)
                n++;
        return n;
    }
}
