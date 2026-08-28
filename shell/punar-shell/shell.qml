pragma ComponentBehavior: Bound
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
//   bar · commandcenter · overview · windowactions · aipanel · approval · alerts
//   systemcontrol · notifications · toasts · osd · shortcuts · lock · theme
//   wallpaper
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
import "WindowActions"

ShellRoot {
    id: shellRoot

    // Instantiate WorkspaceState at startup (singletons are lazy): it
    // restores stored workspace names via `renameworkspace` dispatches and
    // persists renames/preset changes to ~/.local/state/punar/workspaces.json
    // (milestone-2.md §6).
    Component.onCompleted: {
        WorkspaceState.init();
        WallpaperState.init();
        SurfaceTiming.init();
    }

    // The user-invoked surfaces below retain 104–120 MiB apiece in an
    // isolated process but construct in 31–59 ms (run 33044217553). Keep only
    // their tiny IPC proxies resident. Construction starts on the same user
    // action that opens the surface; the object is destroyed after its exit
    // animation. `state()` therefore answers "closed" without creating what
    // it is observing.
    component DeferredSurface: Loader {
        id: deferred

        required property string surfaceName
        property bool openWhenLoaded: false
        readonly property DeferredSurfaceBase surface: deferred.item as DeferredSurfaceBase

        active: false
        asynchronous: false

        function ensureLoaded(openAfter: bool): var {
            if (deferred.surface !== null) {
                if (openAfter)
                    deferred.surface.show();
                return deferred.surface;
            }

            deferred.openWhenLoaded = openAfter;
            SurfaceTiming.beginConstruction(deferred.surfaceName, Date.now());
            deferred.active = true;
            return deferred.surface;
        }

        function openSurface(): void {
            deferred.ensureLoaded(true);
        }

        function toggleSurface(): void {
            if (deferred.surface === null) {
                deferred.openSurface();
                return;
            }
            deferred.surface.toggle();
        }

        function closeSurface(): void {
            if (deferred.surface !== null)
                deferred.surface.dismiss();
        }

        function surfaceState(): string {
            return deferred.surface === null ? "closed" : deferred.surface.ipcState();
        }

        function residency(): string {
            return deferred.surface === null ? "unloaded" : "resident";
        }

        // Called by the surface after its 300 ms exit animation, never at
        // dismiss-begin. callLater prevents an object from destroying itself
        // inside its own signal handler; the open check handles an immediate
        // reopen without a race.
        function releaseIfClosed(): void {
            Qt.callLater(function () {
                if (deferred.surface !== null && !deferred.surface.open) {
                    deferred.openWhenLoaded = false;
                    deferred.active = false;
                }
            });
        }

        onLoaded: {
            if (deferred.surface === null)
                return;
            deferred.surface.unloadRequested.connect(deferred.releaseIfClosed);
            if (deferred.openWhenLoaded) {
                deferred.openWhenLoaded = false;
                deferred.surface.show();
            }
        }
    }

    // ── THE FIELD ────────────────────────────────────────────────────────
    // One background layer window per output. Zero timers, no keyboard focus:
    // it follows one atomic user preference and otherwise does no work.
    // Declared first because it is the sheet everything else is drawn on;
    // layer-shell (not declaration order) keeps it underneath.
    Wallpaper {
    }

    Bar {
        onBarCreated: readyMarker.running = true
        onCommandCenterRequested: commandCenterSurface.openSurface()
        onWindowActionsRequested: windowActionsSurface.openSurface()
    }

    // The normal close path is always available directly on PUNAR+Q. This
    // compact surface adds pointer discoverability and a guarded force-quit
    // path without keeping another layer window resident at idle.
    DeferredSurface {
        id: windowActionsSurface
        surfaceName: "windowactions"
        sourceComponent: WindowActions {}
    }

    IpcHandler {
        target: "windowactions"

        function toggle(): void {
            windowActionsSurface.toggleSurface();
        }
        function open(): void {
            windowActionsSurface.openSurface();
        }
        function close(): void {
            windowActionsSurface.closeSurface();
        }
        function state(): string {
            return windowActionsSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("windowactions");
        }
        function residency(): string {
            return windowActionsSurface.residency();
        }
    }

    DeferredSurface {
        id: commandCenterSurface
        surfaceName: "commandcenter"
        sourceComponent: CommandCenter {}
    }

    IpcHandler {
        target: "commandcenter"

        function toggle(): void {
            commandCenterSurface.toggleSurface();
        }
        function open(): void {
            commandCenterSurface.openSurface();
        }
        function close(): void {
            commandCenterSurface.closeSurface();
        }
        function state(): string {
            return commandCenterSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("commandcenter");
        }
        function residency(): string {
            return commandCenterSurface.residency();
        }
        function explain(): string {
            var surface = commandCenterSurface.surface;
            return surface === null ? "none" : surface.ipcExplain();
        }
        function query(text: string): string {
            var surface = commandCenterSurface.ensureLoaded(false);
            return surface === null ? "unavailable" : surface.ipcQuery(text);
        }
        function run(): string {
            var surface = commandCenterSurface.surface;
            return surface === null ? "closed" : surface.ipcRun();
        }
    }

    DeferredSurface {
        id: overviewSurface
        surfaceName: "overview"
        sourceComponent: Overview {}
    }

    IpcHandler {
        target: "overview"

        function toggle(): void {
            overviewSurface.toggleSurface();
        }
        function open(): void {
            overviewSurface.openSurface();
        }
        function close(): void {
            overviewSurface.closeSurface();
        }
        function state(): string {
            return overviewSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("overview");
        }
        function residency(): string {
            return overviewSurface.residency();
        }
    }

    DeferredSurface {
        id: systemControlSurface
        surfaceName: "systemcontrol"
        sourceComponent: SystemControl {
            onAiPanelRequested: shellRoot.showAiPanel()
            onApplicationRequested: function(entry, catalogId) {
                systemControlSurface.closeSurface();
                if (entry !== null && entry !== undefined) {
                    Apps.launch(entry);
                    return;
                }
                var surface = commandCenterSurface.ensureLoaded(false);
                if (surface === null) {
                    commandCenterSurface.openSurface();
                    return;
                }
                if (catalogId !== "")
                    surface.ipcApplication(catalogId);
                else
                    surface.show();
            }
        }
    }

    IpcHandler {
        target: "systemcontrol"

        function toggle(): void {
            systemControlSurface.toggleSurface();
        }
        function open(): void {
            systemControlSurface.openSurface();
        }
        function close(): void {
            systemControlSurface.closeSurface();
        }
        function state(): string {
            return systemControlSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("systemcontrol");
        }
        function residency(): string {
            return systemControlSurface.residency();
        }
        function rail(): string {
            var surface = systemControlSurface.ensureLoaded(false);
            if (surface === null)
                return "[]";
            var result = surface.ipcRail();
            systemControlSurface.releaseIfClosed();
            return result;
        }
        function model(id: string): string {
            var surface = systemControlSurface.ensureLoaded(false);
            if (surface === null)
                return "{}";
            var result = surface.ipcModel(id);
            systemControlSurface.releaseIfClosed();
            return result;
        }
    }

    // PUNAR+/ — the §12.3 discoverability surface (Plate D-017). Generated
    // from `hyprctl binds -j`, so it cannot drift from the machine it
    // describes. One query per session, on first open.
    DeferredSurface {
        id: shortcutsSurface
        surfaceName: "shortcuts"
        sourceComponent: Shortcuts {}
    }

    IpcHandler {
        target: "shortcuts"

        function toggle(): void {
            shortcutsSurface.toggleSurface();
        }
        function open(): void {
            shortcutsSurface.openSurface();
        }
        function close(): void {
            shortcutsSurface.closeSurface();
        }
        function state(): string {
            return shortcutsSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("shortcuts");
        }
        function residency(): string {
            return shortcutsSurface.residency();
        }
        function reload(): string {
            var surface = shortcutsSurface.ensureLoaded(false);
            return surface === null ? "unavailable" : surface.ipcReload();
        }
        function rows(): string {
            var surface = shortcutsSurface.ensureLoaded(false);
            if (surface === null)
                return "0";
            var result = surface.ipcRows();
            shortcutsSurface.releaseIfClosed();
            return result;
        }
        function undescribed(): string {
            var surface = shortcutsSurface.ensureLoaded(false);
            if (surface === null)
                return "0";
            var result = surface.ipcUndescribed();
            shortcutsSurface.releaseIfClosed();
            return result;
        }
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

    // PUNAR+A — "AI on this device" (M7, Plate D-005). Renders from
    // /run/punar/agents.json via the Agents singleton's FileView; on a
    // machine where punar-agentd never wrote that file the panel opens
    // to its calm empty state.
    function showAiPanel(): void {
        aiPanelSurface.openSurface();
    }

    function showAiPanelDetection(detectionId: string): void {
        var panel = aiPanelSurface.ensureLoaded(false);
        if (panel !== null)
            panel.showDetection(detectionId);
    }

    DeferredSurface {
        id: aiPanelSurface
        surfaceName: "aipanel"
        sourceComponent: AiPanel {}
    }

    IpcHandler {
        target: "aipanel"

        function toggle(): void {
            aiPanelSurface.toggleSurface();
        }
        function open(): void {
            aiPanelSurface.openSurface();
        }
        function close(): void {
            aiPanelSurface.closeSurface();
        }
        function state(): string {
            return aiPanelSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("aipanel");
        }
        function residency(): string {
            return aiPanelSurface.residency();
        }
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
    // the shell root hands the detection to the PUNAR+A panel, which opens
    // with its rail already sitting on that detection (milestone-10.md
    // §5.1). A shell built without an AI panel simply has nothing
    // connected to the signal.
    AlertStack {
        onInspectRequested: function (detectionId) {
            shellRoot.showAiPanelDetection(detectionId);
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
    // the record is PUNAR+SHIFT+N.
    ToastStack {
        onCenterRequested: notificationCenterSurface.openSurface()
    }

    // PUNAR+SHIFT+N — the centre. It reads three registers and owns only
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
    // points at a detection opens the PUNAR+A panel on that detection.
    DeferredSurface {
        id: notificationCenterSurface
        surfaceName: "notifications"
        sourceComponent: NotificationCenter {
            onApprovalRequested: function (approvalId) {
                approvalOverlay.selectedId = approvalId;
                approvalOverlay.show();
            }
            onInspectRequested: function (detectionId) {
                shellRoot.showAiPanelDetection(detectionId);
            }
        }
    }

    IpcHandler {
        target: "notifications"

        function toggle(): void {
            notificationCenterSurface.toggleSurface();
        }
        function open(): void {
            notificationCenterSurface.openSurface();
        }
        function close(): void {
            notificationCenterSurface.closeSurface();
        }
        function state(): string {
            return notificationCenterSurface.surfaceState();
        }
        function latency(): string {
            return SurfaceTiming.sample("notifications");
        }
        function residency(): string {
            return notificationCenterSurface.residency();
        }
        function count(): string {
            var surface = notificationCenterSurface.ensureLoaded(false);
            if (surface === null)
                return "0";
            var result = surface.ipcCount();
            notificationCenterSurface.releaseIfClosed();
            return result;
        }
        function focused(): string {
            var surface = notificationCenterSurface.ensureLoaded(false);
            if (surface === null)
                return "";
            var result = surface.ipcFocused();
            notificationCenterSurface.releaseIfClosed();
            return result;
        }
        function owner(): string {
            var surface = notificationCenterSurface.ensureLoaded(false);
            if (surface === null)
                return "unverified";
            var result = surface.ipcOwner();
            notificationCenterSurface.releaseIfClosed();
            return result;
        }
        function dismiss(): string {
            var surface = notificationCenterSurface.surface;
            return surface === null ? "" : surface.ipcDismiss();
        }
        function clear(): string {
            var surface = notificationCenterSurface.ensureLoaded(false);
            if (surface === null)
                return "0";
            var result = surface.ipcClear();
            notificationCenterSurface.releaseIfClosed();
            return result;
        }
        function dnd(mode: string): string {
            var surface = notificationCenterSurface.ensureLoaded(false);
            if (surface === null)
                return "off";
            var result = surface.ipcDnd(mode);
            notificationCenterSurface.releaseIfClosed();
            return result;
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
    // PUNAR+SHIFT+L. A real ext-session-lock-v1 lock authenticating through
    // PAM, not a full-screen overlay pretending to be one. It holds no
    // surface at all until locked, and there is deliberately no IPC
    // `unlock` verb — that would make the session socket a complete bypass
    // of the passphrase.
    Lock {
    }

    // Ready marker (milestone-1.md §7 / survey decision 6): once the bar is
    // constructed, touch a marker below the authenticated user's private
    // XDG runtime directory. /run/punar is deliberately root-owned in the
    // production profile, so a desktop process must never need write access
    // there. The update health gate validates that the marker and its runtime
    // directory belong to the UID named by /run/user/<uid> before trusting it.
    // On a dev machine without XDG_RUNTIME_DIR the command fails harmlessly.
    Process {
        id: readyMarker
        command: ["/bin/sh", "-c", "test -n \"${XDG_RUNTIME_DIR:-}\" && install -d -m 0700 \"${XDG_RUNTIME_DIR}/punar\" && touch \"${XDG_RUNTIME_DIR}/punar/shell-ready\""]
    }
}
