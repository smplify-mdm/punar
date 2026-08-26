// Bar — the top bar, a paper masthead (DESIGN_LANGUAGE.md §5 "Masthead
// meta rows": tracked mono, middle-dot separators, left context / right
// data, closed by a rule — here the hairline bottom border).
//
// Deliberately calm (§2: a screen with no status to report contains no
// color): left context, empty center, right data.
//
// M9 adds ONE element, and only while it is true: the ELEVATED countdown
// chip of docs/design/mockups/identity-elevation.html (Plate D-012 Sect
// I.03) — `ELEVATED · 14:32 REMAINING`, green while the grant is alive,
// amber in its final minute, GONE the moment it lapses. Privilege is
// never invisible on this device, and it is never permanent: there is no
// generic unrestricted root-shell API to fall back to. The chip is fed by
// the same summary file as the approval overlay (docs/api/ipc.md §15,
// which carries a `grants[]` array), read through the Approvals
// singleton's inotify FileView — no socket client in the bar.
//
// D-016 (docs/design/mockups/menubar.html) adds the LIVE CLUSTER, and
// adds it the way the plate asks: `StatusCluster { }` as one new child of
// the right-hand Row, with the existing `visible:` gating on the org
// chrome as the template. Row positioners skip invisible items, which is
// exactly the "grows leftward, the clock never moves" behaviour the zone
// register asks for — and it is why a personal, idle machine renders the
// SAME two facts it renders today. The calm bar is the finished design;
// every other state is a temporary annotation on it.
//
// THREE ZONES (D-016 Sect I): left is identity and answers WHERE AM I,
// never WHAT IS WRONG. The centre is empty and RESERVED FOR MODALITY —
// the D-007 submap chip lands there, and status may never move in,
// because that would put the loudest thing in the calmest place and
// leave the bar with nowhere to announce a mode. The right is the
// cluster, then the org annotation, then the clock.
//
// THE ORG ANNOTATION IS NOT A SLOT (deviation, stated): D-016 lists ORG
// in the cluster with System Control as its destination. The original
// reason for the deviation — that System Control was not shipped — has
// EXPIRED: System Control now ships as the `systemcontrol` IpcHandler
// target on SUPER+S, and its Organization branch is the door this
// annotation would open. The deviation nonetheless stands, on the other
// half of the argument: design language §8 says enrollment is additive
// chrome that "must never restructure a screen, only annotate it", and
// promoting ORG from an annotation to a focusable slot restructures the
// right-hand zone the moment a device enrols. The org name, dot and
// compliance word therefore stay what they are — a non-focusable
// annotation in the cluster's position, unchanged whether or not the
// cluster has slots — and the door is reached by its own chord. Turning
// it into a slot is a D-016 decision for whoever owns this surface, not
// a side effect of wiring System Control in.
//
// FOCUS IS NOT THEFT (D-016 Sect III·05): the bar's layer surface
// requests keyboard focus ONLY while the cluster is focused, so typing
// into an editor can never fall into the bar. The chord is bound in
// os/modules/desktop/hypr/punar-binds.conf and arrives here as
// `ipc call bar focus`.

import QtQuick
import Quickshell
import Quickshell.Io
import Quickshell.Wayland
import Quickshell.Hyprland
import "../Theme"
import "../Services"

Scope {
    id: root

    // Emitted once the bar object tree is complete — shell.qml uses this
    // to write the desktop ready marker (see shell.qml).
    signal barCreated()

    // Active Hyprland workspace in the masthead grammar (M2 named project
    // workspaces): a named workspace shows its NAME, an unnamed one falls
    // back to the number — Hyprland reports unnamed workspaces with the
    // numeric id as the name, which WorkspaceState.isNamed filters out.
    // Quickshell.Hyprland keeps this live via socket2 events (no polling);
    // renames land here the moment `renameworkspace` fires.
    // WHAT IS RUNNING, in the sense a menubar can honestly answer: the class
    // of the focused window. Class and not title on purpose — the class is the
    // application's identity ("chromium", "foot") and is stable, while the
    // title is the document and changes on every navigation, which would make
    // the bar's left zone flicker and its width jitter on a monospace row.
    //
    // READ FROM THE WAYLAND FOREIGN-TOPLEVEL MANAGER, NOT FROM HYPRLAND'S IPC,
    // and the difference is not stylistic. Quickshell's HyprlandToplevel
    // exposes no class property at all; the class is reachable only through
    // `lastIpcObject`, which is written ONLY by HyprlandIpc::refreshToplevels()
    // — an explicit `j/clients` request that runs at shell init and on
    // configreloaded, and nowhere else. A window opened after the shell starts
    // is built by updateInitial(), which sets address, title and workspace and
    // nothing more, so its lastIpcObject is never written and stays an empty
    // map. In JS that is `{}`, which is truthy, so a `!ipc` guard sails past it
    // and the class reads empty forever. The Overview escapes this only because
    // it calls refreshToplevels() on every open; a bar has no "open" to hang a
    // refresh on, and adding one on a timer is the polling spec §6.3 forbids.
    //
    // ToplevelManager pushes app_id and the activated state as wayland events —
    // no refresh, no timer, and it is seeded at startup, which also fixes a
    // second latent defect: Hyprland.activeToplevel is written only by
    // activewindowv2/closewindow and is null after a shell restart until the
    // user next changes focus.
    //
    // The two readings share one source: Hyprland sends the same class string
    // as the foreign toplevel's app_id and as `hyprctl clients .class`, so the
    // check's comparison is a relation between two views of one fact. One
    // caveat, stated because it is not obvious: the wlr protocol sends app_id
    // ONCE, at map — its onClass handler is dead code in 0.56.2 — so a window
    // that renamed its class mid-life would keep its original name here while
    // hyprctl followed. Nothing Punar ships does that, and the alternative
    // (refresh-gated IPC) is stale in the far commoner case instead.
    //
    // Empty string when nothing is focused (an empty workspace), and the
    // label binds `visible` to that: a bare desktop reads "PUNAR · 1" exactly
    // as it did before, with no trailing separator left hanging.
    readonly property string focusedApp: {
        var top = ToplevelManager.activeToplevel;
        if (!top)
            return "";
        var cls = String(top.appId).trim();
        if (cls === "")
            return "";
        // A pathological class should not be allowed to push the clock off
        // the right-hand edge; the cluster's slots are the bar's priority.
        return cls.length > 24 ? cls.substring(0, 23) + "\u2026" : cls;
    }

    readonly property string workspaceLabel: {
        var ws = Hyprland.focusedWorkspace;
        if (ws === null)
            return "1";
        return WorkspaceState.isNamed(ws) ? ws.name : String(ws.id);
    }

    // ---- M9: the live privilege grant (Plate D-012 Sect I.03) ----

    // The grant about to lapse, recomputed every tick of `tickClock` —
    // which only runs while a grant or a countdown exists (see below), so
    // an idle device pays nothing for this.
    readonly property var grant: Approvals.liveGrant(root.nowMs)

    readonly property real nowMs: tickClock.date ? tickClock.date.getTime() : 0

    readonly property int grantSecondsLeft: root.grant === null ? 0
        : Approvals.secondsUntil(Approvals.str(root.grant, "expires_at"), root.nowMs)

    // Green while active, amber in the final minute (D-012), gone at
    // zero — `grant` itself goes null, because `liveGrant` only returns
    // one with time left.
    readonly property color grantColor: root.grantSecondsLeft < 60 ? Theme.shellStatusWarn
                                                                   : Theme.shellStatusOk

    // Two-step revoke: armed by the first click, cleared by the second,
    // by the grant lapsing, or by a new grant replacing it.
    property bool revokeArmed: false

    onGrantChanged: root.revokeArmed = false

    function revokeGrant(): void {
        var id = Approvals.str(root.grant, "grant_id");
        if (id === "")
            return;
        if (!root.revokeArmed) {
            root.revokeArmed = true;
            return;
        }
        root.revokeArmed = false;
        try {
            Quickshell.execDetached(["punarctl", "privilege", "revoke", id]);
        } catch (e) {
            // No punarctl on a dev machine: the grant stands, and the
            // daemon remains the only thing that can end it.
            console.warn("punar-shell: privilege revoke unavailable:", e);
        }
    }

    // Room the fixed right-hand items need, ESTIMATED IN THE MONO GRID
    // rather than measured off the items themselves. Geist Mono is a
    // fixed-advance face, so a character count is a width — and reading
    // the org row's rendered width back into the shed decision that
    // shortens the org row would be a binding loop.
    readonly property real orgReserve: Status.enrolled
        ? (Status.orgName.length + Status.label.length + 6) * 8 + 26 : 0

    // Meta-row label grammar: Geist Mono, tracked, uppercase (§1 type roles).
    component MetaLabel: Text {
        font.family: Theme.fontMono
        font.pixelSize: 11 // bar meta: 10–11px per type-role table
        font.weight: 500
        font.letterSpacing: Theme.tracking(11, 0.14)
        font.capitalization: Font.AllUppercase
        color: Theme.shellInk3
    }

    // THE CHORD (D-016 Sect III·01). SUPER+SHIFT+B focuses the status
    // cluster; focus lands on the leftmost slot unless something is warn
    // or bad, in which case it lands on the highest-severity slot. On a
    // calm bar there is nothing to focus and the call says so instead of
    // grabbing the keyboard for an empty row.
    //
    // DEVIATION, STATED: the plate writes SUPER+B. SUPER+B has opened the
    // browser since M1 (`bindd = $mod, B, Open browser, …`) and two binds
    // on one chord is not an option — Hyprland fires both. Rather than
    // silently take a working chord away from the user, the cluster takes
    // SUPER+SHIFT+B, keeps the B-for-bar mnemonic, and the shortcut help
    // surface prints whichever chord the config actually carries, so this
    // deviation cannot drift into a lie.
    IpcHandler {
        target: "bar"

        function focus(): string {
            return cluster.focusCluster() ? "focused" : "empty";
        }
        function release(): void {
            cluster.releaseFocus();
        }
        // Read-only probe (the `overview` / `aipanel` precedent).
        function state(): string {
            return cluster.focusIndex >= 0 ? "focused" : "idle";
        }
        // What the left zone is currently naming. Exposed so a check can
        // assert that the bar TRACKS the focused window rather than merely
        // rendering something — surfaces-check.sh focuses a browser and reads
        // this back. Returns the empty string when nothing is focused, which
        // is exactly when the label hides itself.
        function app(): string {
            return root.focusedApp;
        }
    }

    PanelWindow {
        id: bar

        anchors {
            top: true
            left: true
            right: true
        }
        implicitHeight: 30
        color: Theme.shellSurface
        WlrLayershell.namespace: "punar-bar"
        // At rest the bar requests NO keyboard focus at all; it takes
        // exclusive focus only for as long as the cluster holds it, and
        // Esc gives it straight back (D-016 Sect III·05).
        WlrLayershell.keyboardFocus: cluster.focusIndex >= 0 ? WlrKeyboardFocus.Exclusive
                                                             : WlrKeyboardFocus.None

        Component.onCompleted: root.barCreated()

        Item {
            anchors.fill: parent

            // Left: PUNAR · <workspace> · <app> — brand strong in ink,
            // context in ink-3. It answers WHERE AM I, and since the focused
            // application is half of that answer it lands here too. Nothing
            // else ever does: status belongs to the cluster on the right.
            Row {
                id: identity

                anchors.left: parent.left
                anchors.leftMargin: 12
                anchors.verticalCenter: parent.verticalCenter
                spacing: 0

                MetaLabel {
                    text: "Punar"
                    font.weight: 600
                    color: Theme.shellFg
                }
                MetaLabel {
                    text: " · " + root.workspaceLabel
                }
                MetaLabel {
                    text: " · " + root.focusedApp
                    // An empty workspace has no focused window, and a
                    // separator with nothing after it is worse than silence.
                    visible: root.focusedApp !== ""
                }
            }

            // Centre intentionally empty — reserved for modality only
            // (D-016 Sect I·02; the submap chip is drawn by D-007).

            // Right: the cluster, then the elevation chip, then the org
            // annotation (enrolled only), then the clock — data is always
            // mono tabular; Geist Mono is inherently tabular, so the
            // clock's width never jitters.
            Row {
                id: rightZone

                anchors.right: parent.right
                anchors.rightMargin: 12
                anchors.verticalCenter: parent.verticalCenter
                spacing: 6

                // D-016's one new child. Zero pixels on a calm machine.
                StatusCluster {
                    id: cluster

                    anchors.verticalCenter: parent.verticalCenter
                    nowMs: root.nowMs
                    // What the cluster may occupy before it shortens its
                    // own detail: everything the identity zone and the
                    // fixed right-hand items are not using.
                    availableWidth: bar.width - identity.implicitWidth
                        - root.orgReserve - 88
                }

                // Plate D-012's `.elevchip`. Absent by default: a calm bar
                // is a bar with no privilege to report, and its appearance
                // is the signal. It sits at D-016's CRED position because
                // a live privilege grant is the one credential-shaped TTL
                // this machine can observe without polling — punar-secrets
                // keeps leases in memory and writes no file at all
                // (docs/api/ipc.md §16), which is why there is no separate
                // CRED slot in the cluster.
                Rectangle {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: root.grant !== null
                    width: elevRow.implicitWidth + 16
                    height: elevRow.implicitHeight + 6
                    radius: Theme.radiusTag
                    color: "transparent"
                    border.width: Theme.hairline
                    border.color: root.grantColor

                    Row {
                        id: elevRow

                        anchors.centerIn: parent
                        spacing: 7

                        Rectangle {
                            anchors.verticalCenter: parent.verticalCenter
                            width: 5
                            height: 5
                            radius: 2.5
                            color: root.grantColor
                        }
                        MetaLabel {
                            anchors.verticalCenter: parent.verticalCenter
                            font.pixelSize: 9
                            font.letterSpacing: Theme.tracking(9, 0.13)
                            color: root.grantColor
                            // Tabular by construction — Geist Mono is.
                            text: "Elevated · " + Approvals.clockWide(root.grantSecondsLeft)
                                + " remaining"
                        }
                    }

                    // Revoking is one action, and it is real: the same
                    // fixed argv `punarctl privilege revoke <gnt_id>` the
                    // CLI runs, detached, with the daemon as the
                    // authorization point. Two-step, like the AI panel's
                    // SHIFT+DEL — the first click arms and the chip asks,
                    // the second acts — because dropping privilege by
                    // accident is a surprise, and Punar does not surprise.
                    //
                    // HONEST DEVIATION (stated, not hidden): D-012 draws
                    // `R` as the binding. The bar holds the keyboard only
                    // while the cluster is focused, so M9 ships the click
                    // here and the keystroke with the graphical elevation
                    // dialog (M13). The verb itself already exists:
                    // punarctl privilege revoke.
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: root.revokeGrant()
                    }
                }

                MetaLabel {
                    anchors.verticalCenter: parent.verticalCenter
                    visible: root.grant !== null && root.revokeArmed
                    color: Theme.shellStatusBad
                    text: "Click again to revoke · "
                }

                // Unmanaged-first (§8): org chrome renders only when
                // enrolled — a personal device's bar stays name + clock,
                // byte-identical to the pre-M5 bar (Row positioners skip
                // invisible items). Enrolled grammar (M5): ORG NAME ·
                // <dot> STATE-WORD · CLOCK. Colour only for a deviation:
                // the dot carries the compliance state and the word names
                // it, and a compliant device spends the ok colour on one
                // 5px dot and nothing else.
                Row {
                    id: orgZone

                    anchors.verticalCenter: parent.verticalCenter
                    spacing: 5
                    visible: Status.enrolled

                    MetaLabel {
                        anchors.verticalCenter: parent.verticalCenter
                        // Truncated at 12ch when the row is tight
                        // (D-016 Sect I·05's ladder).
                        text: (cluster.detailLevel >= 2 || Status.orgName.length <= 12
                               ? Status.orgName
                               : Status.orgName.substring(0, 11) + "…") + " · "
                    }
                    Rectangle {
                        anchors.verticalCenter: parent.verticalCenter
                        width: 5
                        height: 5
                        radius: 2.5
                        color: Status.color // live compliance via status.json (M5)
                    }
                    MetaLabel {
                        anchors.verticalCenter: parent.verticalCenter
                        // The word is the last thing to go; the dot keeps
                        // the colour.
                        visible: cluster.detailLevel >= 2
                        text: Status.label + " · "
                    }
                }

                MetaLabel {
                    id: clockLabel

                    anchors.verticalCenter: parent.verticalCenter
                    text: Qt.formatDateTime(minuteClock.date, "HH:mm")
                    color: Theme.shellInk2
                }
            }

            // The rule that closes the masthead (§3: structure drawn with rules).
            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                height: Theme.hairline
                color: Theme.shellBorder
            }
        }
    }

    // The popover hangs below the bar on its own surface, because a 30px
    // bar cannot contain a 200px card. It is masked to the card, so the
    // desktop under it stays clickable.
    SlotPopover {
        slotData: cluster.activeSlot
        anchorRight: cluster.activeSlotRight
        barHeight: bar.implicitHeight
    }

    // The bar's only unconditional timer: one wake per minute for the
    // clock (D-016 Sect IV·08).
    SystemClock {
        id: minuteClock
        precision: SystemClock.Minutes
    }

    // The second hand, and the whole of the concession to spec §6.3
    // (D-016 Sect IV·10). `enabled` is bound to the existence of
    // something that is counting down — a live privilege grant or a
    // pending approval — so this clock does not tick at all on an idle
    // device, and it performs no I/O when it does: it re-renders a local
    // subtraction against a timestamp already in memory.
    SystemClock {
        id: tickClock
        precision: SystemClock.Seconds
        enabled: Approvals.grants.length > 0 || cluster.needsSeconds
    }
}
