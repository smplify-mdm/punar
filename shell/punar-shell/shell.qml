// punar-shell — Quickshell entrypoint (Milestones 1–2, 7).
//
// Top bar + command center overlay + SUPER+TAB overview + SUPER+A AI
// panel, implementing the field-note designs:
//   docs/design/DESIGN_LANGUAGE.md (binding)
//   docs/design/mockups/command-approval.html (Sect I — command center,
//                                               Sect II — approval overlay)
//   docs/design/mockups/identity-elevation.html (Plate D-012 — the bar's
//                                                ELEVATED countdown chip)
//   docs/design/mockups/desktop-multitasking.html (Plate D-007 — overview)
//   docs/design/mockups/ai-panel.html (Plate D-005 — AI panel)
// All design values flow through the Theme singleton (punar-tokens.json).

import QtQuick
import Quickshell
import Quickshell.Io
import "AiPanel"
import "Approval"
import "Bar"
import "CommandCenter"
import "Overview"
import "Services"

ShellRoot {
    id: shellRoot

    // Instantiate WorkspaceState at startup (singletons are lazy): it
    // restores stored workspace names via `renameworkspace` dispatches and
    // persists renames/preset changes to ~/.local/state/punar/workspaces.json
    // (milestone-2.md §6).
    Component.onCompleted: WorkspaceState.init()

    Bar {
        onBarCreated: readyMarker.running = true
    }

    CommandCenter {
    }

    Overview {
    }

    // The M9 approval gate (Plate D-003). It has no keybinding by
    // design: it opens ITSELF whenever punard records something pending,
    // because a gate the human has to go looking for is not a gate. Fed
    // by the Approvals singleton's FileView on /run/punard/approvals.json;
    // on a machine where punard never wrote that file it never appears.
    // Driven in CI with: qs -p /usr/share/punar/shell ipc call approval open
    ApprovalOverlay {
    }

    // SUPER+A — "AI on this device" (M7, Plate D-005). Renders from
    // /run/punar/agents.json via the Agents singleton's FileView; on a
    // machine where punar-agentd never wrote that file the panel opens
    // to its calm empty state.
    AiPanel {
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
