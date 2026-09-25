-- Keyboard and pointer input for both Punar compositor sessions, the desktop
-- (hyprland.lua) and the login screen (punar-greeter.lua). SMP-1405 WP-02.
--
-- THE KEYBOARD LAYOUT ARRIVES AS DATA. Session start runs `punarctl keyboard
-- layout render`, which reads the device's layout (punard's system.keymap
-- capability, /etc/vconsole.conf), checks it against the image's XKB list and
-- writes three values to $XDG_RUNTIME_DIR/punar/session/input.lua. That file
-- is Lua-shaped so a person can read it as Lua, but it is NEVER RUN here: the
-- reader below matches three fixed `key = "value",` lines with a pattern and
-- admits only the characters a layout list can contain. A file that does not
-- match is ignored and the session types US English, which is also what a
-- machine with no file (a first boot, a failed render) gets.
--
-- Latin letters keep working under every layout: the renderer leads the list
-- with a Latin layout and adds the both-Alt-keys switch chord whenever there
-- is more than one layout. Hyprland resolves binds against the first layout,
-- so PUNAR+Return opens a terminal under Russian exactly as under US.
--
-- Pointer defaults follow Omarchy 4.0.4's input.lua where it is a measured
-- convenience (repeat 40/250, clickfinger, 0.4 touchpad scroll, numlock on)
-- and keep Punar's own where it is a deliberate choice (click to focus,
-- follow_mouse = 0). Caps Lock is left as Caps Lock: Omarchy's compose-on-
-- Caps remaps a key everyone knows by name, which is a taste, not a default.

local M = {}

local function data_value(value)
    return type(value) == "string" and #value <= 256 and value:match("^[A-Za-z0-9_,:-]*$") ~= nil
end

-- The three keyboard values from a rendered file, or nil.
function M.read(path)
    local file = io.open(path, "r")
    if not file then
        return nil
    end
    local found = {}
    for line in file:lines() do
        local key, value = line:match('^%s*(kb_[a-z]+)%s*=%s*"([^"]*)",%s*$')
        if (key == "kb_layout" or key == "kb_variant" or key == "kb_options") and data_value(value) then
            found[key] = value
        end
    end
    file:close()
    if not found.kb_layout or found.kb_layout == "" or not found.kb_variant or not found.kb_options then
        return nil
    end
    return found
end

-- This session's rendered file, below the person's own runtime directory
-- (root owns /run/punar, and no desktop process may write there).
function M.session_file()
    local runtime = os.getenv("XDG_RUNTIME_DIR")
    if not runtime or runtime:sub(1, 1) ~= "/" then
        return nil
    end
    return runtime .. "/punar/session/input.lua"
end

-- The `input` table both sessions give hl.config.
function M.config()
    local path = M.session_file()
    local keyboard = path and M.read(path) or nil
    keyboard = keyboard or { kb_layout = "us", kb_variant = "", kb_options = "" }
    return {
        kb_layout = keyboard.kb_layout,
        kb_variant = keyboard.kb_variant,
        kb_options = keyboard.kb_options,
        follow_mouse = 0,
        repeat_rate = 40,
        repeat_delay = 250,
        numlock_by_default = true,
        touchpad = {
            tap_to_click = true,
            clickfinger_behavior = true,
            natural_scroll = false,
            scroll_factor = 0.4,
            disable_while_typing = true,
        },
    }
end

return M
