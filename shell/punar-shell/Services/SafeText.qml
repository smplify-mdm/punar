pragma Singleton
// SafeText — the one place a string from outside Punar becomes drawable.
//
// WHY THIS IS A SINGLETON AND NOT A HELPER IN ONE FILE. Two independent
// services take text from outside the shell and hand it to a Text item:
// Notifications (any application, over D-Bus) and Alerts (punar-agentd, whose
// `executable` is a path read from `/proc/<pid>/exe`). They must not depend on
// each other — a security surface importing the notification daemon to borrow
// a regex would be a worse design than duplicating it — so the rule lives here
// and both read it. A third caller should read it too rather than write a
// fourth variant.
//
// THE THREAT IS NOT "STRANGE CHARACTERS". It is that the sender chooses how
// Punar's own chrome is laid out and read:
//
//   - A Text item honours an explicit newline even with wrapping off and
//     eliding on. A row that sizes its container, inside a card whose height
//     is unbounded, grows without limit. That is not theoretical; the toast's
//     meta row shipped that way.
//   - Bidi overrides and isolates reorder text visually WITHOUT changing it.
//     They exist for exactly that, which makes them a spoofing primitive.
//     Nothing that legitimately names an application or an executable needs
//     one. On the shadow-AI alert card the stakes are plain: a filename on
//     Linux may contain any byte but `/` and NUL, so a hostile binary would
//     otherwise choose how it is rendered on the one surface whose entire
//     purpose is to tell the user it is running.
//   - Control characters can fuse two words into a third, so they become
//     spaces rather than disappearing.
//
// WHAT IT IS NOT. Not an escaper and not a validator. Every surface already
// renders `Text.PlainText`, so markup is printed literally and there is
// nothing to escape; this bounds LAYOUT, which PlainText does not. It also
// makes no judgement about the content — a rude application name stays rude.
// Punar chooses the layout, the sender keeps the words.

import QtQuick
import Quickshell

Singleton {
    id: root

    // Bidi reorderers: LRM, RLM, the embedding/override run (U+202A-U+202E)
    // and the isolates (U+2066-U+2069). Dropped outright.
    readonly property var reorderers: /[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g
    // C0 and C1. Replaced with a space, never removed.
    readonly property var controls: /[\u0000-\u001F\u007F-\u009F]/g

    // A generous default bound. It is far above what any Punar surface can
    // display — the longest is a toast body at two wrapped lines — so nothing
    // a reader would have seen is lost, and the text layout engine can never
    // be handed a megabyte. Callers that want a tighter bound pass one.
    readonly property int defaultCap: 240

    function plain(value: var, cap: int): string {
        if (typeof value !== "string" || value === "")
            return "";
        var out = value
            .replace(root.reorderers, "")
            .replace(root.controls, " ")
            .replace(/\s+/g, " ")
            .trim();
        var limit = (typeof cap === "number" && cap > 0) ? cap : root.defaultCap;
        // The ellipsis says the sender said more, which is true, and is a
        // different claim from a surface running out of room.
        return out.length > limit ? out.slice(0, limit) + "\u2026" : out;
    }
}
