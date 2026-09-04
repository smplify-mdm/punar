-- Punar desktop compositor configuration.
--
-- Hyprland 0.55 made Lua its native configuration provider and 0.56 warns on
-- every legacy .conf session. Keep the product session on the supported API;
-- the separate modules make look-and-feel and keyboard grammar reviewable.

local commandCenter = "qs -p /usr/share/punar/shell ipc call commandcenter toggle"
local overview = "qs -p /usr/share/punar/shell ipc call overview toggle"
local aiPanel = "qs -p /usr/share/punar/shell ipc call aipanel toggle"
local lock = "qs -p /usr/share/punar/shell ipc call lock lock"
local layoutScript = "/usr/lib/punar/punar-layout.sh"
local shell = "qs -p /usr/share/punar/shell"

hl.monitor({ output = "Virtual-1", mode = "preferred", position = "auto", scale = 1 })
hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })

hl.env("XDG_CURRENT_DESKTOP", "Hyprland")
hl.env("XDG_SESSION_DESKTOP", "Hyprland")
hl.env("QT_QPA_PLATFORM", "wayland")

-- The event is emitted once per compositor lifetime, unlike config reloads.
-- This is the Lua equivalent of exec-once and preserves the low idle surface.
hl.on("hyprland.start", function()
    -- URI launches commonly cross a D-Bus-activated desktop portal.  The
    -- portal is owned by the user manager, not this session process, so it
    -- must see the mutable Punar application roots exported by session.sh.
    -- Without these two variables a browser can resolve `claude:` against
    -- only the immutable image defaults and leave OAuth stranded in a tab.
    hl.exec_cmd("dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP HYPRLAND_INSTANCE_SIGNATURE XDG_CONFIG_DIRS XDG_DATA_DIRS")
    hl.exec_cmd(shell)
    hl.exec_cmd(layoutScript .. " restore")
    -- User-created web-app rules are derived from punard's root-owned
    -- inventory. session.sh guarantees this file exists before Hyprland;
    -- `punarctl web-apps sync` refreshes and reloads it after each change.
    hl.exec_cmd("hyprctl keyword source ${XDG_CONFIG_HOME:-${HOME}/.config}/hypr/punar-webapps.conf")
    hl.exec_cmd("systemctl --user start hyprpolkitagent.service")
    hl.exec_cmd("foot --server")
end)

hl.config({
    input = {
        kb_layout = "us",
        follow_mouse = 0,
    },
    binds = {
        window_direction_monitor_fallback = true,
    },
    cursor = {
        no_hardware_cursors = 2,
        inactive_timeout = 8,
        hide_on_key_press = true,
    },
    misc = {
        focus_on_activate = true,
        disable_watchdog_warning = true,
    },
    ecosystem = {
        no_update_news = true,
        no_donation_nag = true,
    },
})

-- Hyprland evaluates the top-level file with the compositor's process working
-- directory, not the directory containing this file. Absolute product paths
-- keep module loading identical for greetd, a login shell and config reloads.
require("/etc/xdg/hypr/punar-look.lua")
require("/etc/xdg/hypr/punar-binds.lua")({
    mod = "SUPER",
    command_center = commandCenter,
    overview = overview,
    ai_panel = aiPanel,
    lock = lock,
    layout_script = layoutScript,
    shell = shell,
    -- --no-wait returns success as soon as the server accepts the window.
    -- Without it, a normally closed shell can return non-zero and trigger
    -- the fallback below, immediately replacing the window the user closed.
    terminal = "footclient --no-wait",
    terminal_fallback = "foot",
    browser = "punarctl web-apps browse",
    scratch_class = "punar-scratch",
    assistant_class = "punar-assistant",
    notes_class = "punar-notes",
    scratchpad_script = "/usr/lib/punar/punar-scratchpad.sh",
})

-- The product file is empty. The development profile overlays it with one
-- hyprland.start hook for VM/CI readiness evidence.
require("/etc/xdg/hypr/punar-session-profile.lua")
