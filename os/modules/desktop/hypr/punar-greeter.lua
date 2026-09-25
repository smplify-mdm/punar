-- Minimal pre-login compositor: one Quickshell process and no desktop agents.

hl.monitor({ output = "", mode = "preferred", position = "auto", scale = 1 })

hl.env("XDG_CURRENT_DESKTOP", "Hyprland")
hl.env("XDG_SESSION_DESKTOP", "Hyprland")
hl.env("QT_QPA_PLATFORM", "wayland")

hl.on("hyprland.start", function()
    hl.exec_cmd("qs -p /usr/share/punar/shell/Greeter")
end)

-- The device's keyboard layout, rendered by greeter-session.sh with the same
-- `punarctl keyboard layout render` the desktop uses, and read here as data:
-- the login screen types in the layout the person types in everywhere else.
hl.config({
    input = require("/etc/xdg/hypr/punar-input.lua").config(),
    cursor = {
        no_hardware_cursors = 2,
        inactive_timeout = 8,
        hide_on_key_press = true,
    },
    animations = { enabled = false },
    decoration = {
        rounding = 0,
        shadow = { enabled = false },
        blur = { enabled = false },
    },
    misc = {
        focus_on_activate = true,
        disable_hyprland_logo = true,
        disable_splash_rendering = true,
        disable_watchdog_warning = true,
    },
    ecosystem = {
        no_update_news = true,
        no_donation_nag = true,
    },
})
