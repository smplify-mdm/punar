// punar-shell — Quickshell entrypoint (Milestone 1).
//
// Top bar + command center overlay, implementing the field-note designs:
//   docs/design/DESIGN_LANGUAGE.md (binding)
//   docs/design/mockups/command-approval.html (Sect I — acceptance reference)
// All design values flow through the Theme singleton (punar-tokens.json).

import Quickshell
import Quickshell.Io
import "Bar"
import "CommandCenter"

ShellRoot {
    id: shellRoot

    Bar {
        onBarCreated: readyMarker.running = true
    }

    CommandCenter {
    }

    // Ready marker (milestone-1.md §7 / survey decision 6): once the bar is
    // constructed, touch /run/punar/shell-ready. /run/punar is created by a
    // root tmpfiles.d entry (0755 punar punar); desktop-ready.sh — run by
    // Hyprland exec-once — waits on this file (fallback: pgrep quickshell),
    // then screenshots and touches /run/punar/desktop-ready, which the root
    // punar-desktop-marker unit turns into PUNAR_DESKTOP_OK on serial.
    // On a dev machine without /run/punar the touch fails harmlessly.
    Process {
        id: readyMarker
        command: ["touch", "/run/punar/shell-ready"]
    }
}
