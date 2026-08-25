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
//   docs/design/mockups/notifications-osd.html (Plate D-009 Sect I — the
//                                               M10 shadow-AI alert card)
// All design values flow through the Theme singleton (punar-tokens.json).

import QtQuick
import Quickshell
import Quickshell.Io
import "AiPanel"
import "Alert"
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
        id: aiPanel
    }

    // The M10 shadow-AI alert region (Plate D-009 Sect I). Like the M9
    // gate it has no keybinding of its own: punar-agentd raises a card by
    // writing /run/punar-agentd/alerts.json, the Alerts singleton's
    // FileView follows the change, and the card appears — because an
    // alert the human has to go looking for is not an alert. On a machine
    // where agentd never wrote that file, nothing is ever drawn (fail
    // closed). Driven in CI with:
    //   qs -p /usr/share/punar/shell ipc call alerts open
    //
    // [I] Inspect is wired here rather than inside the card so the alert
    // surface never reaches into another surface directly: it asks, and
    // the shell root hands the detection to the SUPER+A panel, which opens
    // with its rail already sitting on that detection (milestone-10.md
    // §5.1). A shell built without an AI panel simply has nothing
    // connected to the signal.
    AlertStack {
        onInspectRequested: function (detectionId) {
            aiPanel.showDetection(detectionId);
        }
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
