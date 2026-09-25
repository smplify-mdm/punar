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
    // Inbox carries -1, meaning "ask the model" — it printed a hand-written 12
    // while the masthead printed the fixture's real 3, and two numbers about
    // the same thing disagreeing in one window is the failure this whole
    // language is built to avoid.
    readonly property var views: [
        { "name": "Inbox", "count": -1, "current": true },
        { "name": "Starred", "count": 3, "current": false },
        { "name": "Attachments", "count": 0, "current": false },
        { "name": "Drafts", "count": 1, "current": false }
    ]

    // WHICH IDENTITY SLOT EACH LABEL CARRIES. A real client stores the person's
    // own choice; a fixture states it, because deriving a hue from a hash of the
    // name would look identical here and be wrong in the one way that matters —
    // the colour would not be theirs. An unlisted label falls to the neutral.
    readonly property var labelSlot: ({
        "Receipts": 1,
        "Work": 5,
        "Release": 3,
        "Travel": 4,
        "Decisions": 6,
        "Q3": 2,
        "Automated": 7,
        "Personal": 0
    })

    function slotFor(label: string): int {
        var v = root.labelSlot[label];
        return v === undefined ? 7 : v;
    }

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

    // MESSAGE BODIES for the threads a reader is most likely to open. Keyed by
    // correspondent so a thread and its messages cannot drift apart the way two
    // parallel arrays would.
    //
    // `remote` marks a message whose HTML referenced something off-device. The
    // thread window states that it BLOCKED it — after the fact, on the message
    // it happened to, rather than as a setting somewhere. A disclosure a person
    // has to go looking for is not one.
    readonly property var bodies: ({
        "Stripe": [
            {
                "from": "Stripe", "address": "receipts@stripe.com",
                "date": "10 Sep 2026 · 14:02", "remote": true,
                "body": "A copy of invoice 4C21-8890 is attached.\n\nNo action is needed if you have already paid. This receipt is for your records.\n\nAmount  £48.00\nPeriod  1 Aug – 31 Aug 2026"
            }
        ],
        "Aisha Rahman +2": [
            {
                "from": "Aisha Rahman", "address": "aisha@example.org",
                "date": "9 Sep 2026 · 16:20", "remote": false,
                "body": "First pass at the release notes is in the shared doc. I have left the installer section empty because I could not tell from the changelog whether the ISO path changed."
            },
            {
                "from": "Wei Chen", "address": "wei@example.org",
                "date": "10 Sep 2026 · 09:04", "remote": false,
                "body": "It did change — the hybrid ISO now carries both UEFI forms. I can write that paragraph if you would rather not guess at it."
            },
            {
                "from": "Aisha Rahman", "address": "aisha@example.org",
                "date": "10 Sep 2026 · 11:47", "remote": false,
                "body": "I have folded in the installer section.\n\nThe rollback paragraph still needs a number from you — how long does the automatic rollback actually take on the ARM64 path? I do not want to write \"quickly\"."
            }
        ],
        "Nadia Okonkwo": [
            {
                "from": "Nadia Okonkwo", "address": "nadia@example.net",
                "date": "9 Sep 2026 · 18:31", "remote": false,
                "body": "Sorry for the length.\n\nThe short version is that the migration cost is front-loaded and we would be paying it twice: once to move onto the new store, and again in six months when the schema settles. Option one costs more this quarter and less every quarter after.\n\nI am not certain about the second half of that. Happy to be argued out of it."
            }
        ]
    })

    function messagesFor(correspondent: string): var {
        var m = root.bodies[correspondent];
        return m === undefined ? [] : m;
    }

    readonly property int unreadCount: {
        var n = 0;
        for (var i = 0; i < root.threads.length; i++)
            if (root.threads[i].unread === true)
                n++;
        return n;
    }
}
