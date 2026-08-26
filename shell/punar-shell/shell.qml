// punar-shell — Quickshell entrypoint.
//
// The whole graphical shell is ONE process. Every surface below is a
// `Scope` holding its own layer-shell window(s), so the shell owns exactly
// one Wayland client, one D-Bus name, one IPC socket and one set of file
// watches — the arrangement PERFORMANCE_BUDGETS.md assumes and the reason
// there is no second daemon for the wallpaper, the notifications or the
// lock (Plate D-015 Sect V.04).
//
// Acceptance references (docs/design/):
//   DESIGN_LANGUAGE.md (binding) — §2 colour only where it means something,
//     §4 motion, §6 surface assignment, §7 dashed = unshipped, §8
//     unmanaged-first, §9 non-negotiables.
//   mockups/command-approval.html   (D-003) command center + approval gate
//   mockups/desktop-multitasking.html (D-007) project overview
//   mockups/ai-panel.html            (D-005) AI panel
//   mockups/system-control.html      (D-004) system control / settings
//   mockups/notifications-osd.html   (D-009) toasts, centre, OSD, AI alert
//   mockups/identity-elevation.html  (D-012) elevated chip, lock screen
//   mockups/menubar.html             (D-016) bar + status cluster
//   mockups/shortcuts.html           (D-017) shortcut help
//   mockups/wallpaper.html           (D-015) the desktop field
//   theme-system.md                          themes + contrast gate
// All design values flow through the Theme singleton, which reads
// punar-tokens.json and the active theme document. No surface holds a
// literal colour.
//
// IPC TARGETS REGISTERED BY THIS TREE (all reachable as
// `qs -p /usr/share/punar/shell ipc call <target> <method>`; every target
// name is unique, verified by `qs ipc show` and by grep over the tree):
//   bar · commandcenter · overview · aipanel · approval · alerts
//   systemcontrol · notifications · toasts · osd · shortcuts · lock · theme
//
// CROSS-SURFACE SIGNALS ARE WIRED HERE AND NOWHERE ELSE. No surface
// reaches into another: a surface raises a signal saying what it wants,
// and this file decides what answers it. That is why a shell built
// without some surface still runs — the signal is simply unconnected.

import QtQuick
import Quickshell
import Quickshell.Io
import "AiPanel"
import "Alert"
import "Approval"
import "Bar"
import "CommandCenter"
import "Lock"
import "Notifications"
import "Overview"
import "Services"
import "Shortcuts"
import "SystemControl"
import "Wallpaper"

ShellRoot {
    id: shellRoot

    // Instantiate WorkspaceState at startup (singletons are lazy): it
    // restores stored workspace names via `renameworkspace` dispatches and
    // persists renames/preset changes to ~/.local/state/punar/workspaces.json
    // (milestone-2.md §6).
    Component.onCompleted: {
        WorkspaceState.init();
        SurfaceTiming.init();
    }

    // ── THE FIELD ────────────────────────────────────────────────────────
    // One background layer window per output (Plate D-015 Sect V.03). Zero
    // data inputs, zero timers, no keyboard focus: it follows the active
    // theme's mood and nothing else. Declared first because it is the sheet
    // everything else is drawn on; layer-shell (not declaration order) is
    // what actually keeps it underneath.
    Wallpaper {
    }

    Bar {
        onBarCreated: readyMarker.running = true
    }

    CommandCenter {
    }

    Overview {
    }

    // SUPER+S — System Control (spec §63, Plate D-004). The settings
    // surface: the §63 taxonomy rail, real measured views, and dashed
    // panels wherever no capability ships. Its one cross-surface ask is
    // the AI views' link to SUPER+A rather than duplicating §20.
    SystemControl {
        onAiPanelRequested: aiPanel.show()
    }

    // SUPER+/ — the §12.3 discoverability surface (Plate D-017). Generated
    // from `hyprctl binds -j`, so it cannot drift from the machine it
    // describes. One query per session, on first open.
    Shortcuts {
    }

    // The M9 approval gate (Plate D-003). It has no keybinding by
    // design: it opens ITSELF whenever punard records something pending,
    // because a gate the human has to go looking for is not a gate. Fed
    // by the Approvals singleton's FileView on /run/punard/approvals.json;
    // on a machine where punard never wrote that file it never appears.
    // Driven in CI with: qs -p /usr/share/punar/shell ipc call approval open
    ApprovalOverlay {
        id: approvalOverlay
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

    // ── NOTIFICATIONS (Plate D-009) ──────────────────────────────────────
    // Three surfaces over one freedesktop daemon (Services/Notifications.qml,
    // which binds org.freedesktop.Notifications — Punar had no notification
    // daemon at all before this). Toasts are the interruption, the centre is
    // the record, and the two are the same records seen twice: dismissing a
    // toast FILES it, it never destroys it.
    //
    // Toasts never take the keyboard exclusively, so they can never swallow
    // a keystroke while the user is typing; the guaranteed keyboard path to
    // the record is SUPER+SHIFT+N.
    ToastStack {
        onCenterRequested: notificationCenter.show()
    }

    // SUPER+SHIFT+N — the centre. It reads three registers and owns only
    // one of them: application notifications are its own daemon's; the
    // approval rows come from the SAME M9 Approvals singleton the gate
    // above uses, and the punar-agentd rows from the SAME M10 Alerts
    // singleton the alert region uses. That is why "approvals and alerts
    // resolve, they don't dismiss" is true by construction — they are not
    // in the daemon's model, so no code path can clear them.
    //
    // Its two cross-surface asks are answered here, on the
    // AlertStack.onInspectRequested precedent: a row that points at a
    // pending approval opens the M9 gate on that approval, and a row that
    // points at a detection opens the SUPER+A panel on that detection.
    NotificationCenter {
        id: notificationCenter

        onApprovalRequested: function (approvalId) {
            approvalOverlay.selectedId = approvalId;
            approvalOverlay.show();
        }
        onInspectRequested: function (detectionId) {
            aiPanel.showDetection(detectionId);
        }
    }

    // The volume/brightness OSD (Plate D-009 Sect III) — the one surface
    // the §6 surface-assignment table puts on PANEL regardless of the
    // active mood, because an OSD overlay is a plate. Volume is real: it
    // follows the PipeWire default sink's own change event and draws the
    // level the sink settled on, whoever moved it. Brightness renders
    // dashed with its SIM · VM tag — no backlight capability ships, so no
    // brightness key is bound (spec §1.22).
    Osd {
    }

    // ── THE LOCK ─────────────────────────────────────────────────────────
    // SUPER+SHIFT+L. A real ext-session-lock-v1 lock authenticating through
    // PAM, not a full-screen overlay pretending to be one. It holds no
    // surface at all until locked, and there is deliberately no IPC
    // `unlock` verb — that would make the session socket a complete bypass
    // of the passphrase.
    Lock {
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
