-- Punar desktop compositor configuration.
--
-- Hyprland 0.55 made Lua its native configuration provider and 0.56 warns on
-- every legacy .conf session. Keep the product session on the supported API;
-- the separate modules make look-and-feel and keyboard grammar reviewable.

local commandCenter = "qs -p /usr/share/punar/shell ipc call commandcenter toggle"
local overview = "qs -p /usr/share/punar/shell ipc call overview toggle"
local aiPanel = "qs -p /usr/share/punar/shell ipc call aipanel toggle"
local lock = "qs -p /usr/share/punar/shell ipc call lock lock"
local session = "qs -p /usr/share/punar/shell ipc call session toggle"
-- PUNAR+SHIFT+E asks before it ends anything: it opens the session menu with
-- "End session" already armed, and only a second press (or E, or a click)
-- signs out. Esc keeps the session. When the shell is not there to ask, the
-- helper asks through the compositor instead (a notification, then a second
-- press within five seconds), so the chord is never a silent no-op.
local sessionEnd = "/usr/lib/punar/punar-end-session"
local layoutScript = "/usr/lib/punar/punar-layout.sh"
local shell = "qs -p /usr/share/punar/shell"
-- The shell itself runs under a small supervisor: no core dumps (soft and
-- hard RLIMIT_CORE 0 — it holds passwords while people type them) and a
-- restart after a crash, so the lock chord and the session menu come back.
local shellRun = "/usr/lib/punar/punar-shell-run"

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
    hl.exec_cmd(shellRun)
    hl.exec_cmd(layoutScript .. " restore")
    -- The import above and this start are two INDEPENDENT spawns, so their
    -- order is not guaranteed — and hyprpolkitagent.service carries
    -- ConditionEnvironment=WAYLAND_DISPLAY. Losing that race does not fail the
    -- unit, it SKIPS it silently, and the desktop then has no authentication
    -- agent: every polkit action that needs one fails with no dialog and no
    -- message. Repeat the import inside the same shell so the ordering is a
    -- property of this line rather than of the scheduler.
    hl.exec_cmd("sh -c 'dbus-update-activation-environment --systemd WAYLAND_DISPLAY XDG_CURRENT_DESKTOP HYPRLAND_INSTANCE_SIGNATURE; exec systemctl --user start hyprpolkitagent.service'")
    hl.exec_cmd("foot --server")
    -- Idle auto-lock. Started here rather than through the packaged
    -- hypridle.service (disabled in 00-punar-lean.preset) because that unit's
    -- ExecStart carries no -c and would read a user config this image does not
    -- ship. hypridle waits on ext-idle-notify-v1, so it adds no timer wakeups
    -- at idle.
    hl.exec_cmd("hypridle -c /etc/xdg/hypr/punar-hypridle.conf")
end)

-- A configuration reload (a web-app sync, the clipboard-keys setting) re-reads
-- this file but not the presets punar-layout.sh applied with `hyprctl eval`,
-- so the session's preset and every workspace's own preset are put back
-- here. `config.reloaded` fires once per reload, never at startup.
hl.on("config.reloaded", function()
    hl.exec_cmd(layoutScript .. " restore")
end)

-- Keyboard layout (read as data from the session's rendered file, see
-- punar-input.lua), key repeat, touchpad and pointer. SMP-1405 WP-02.
local input = require("/etc/xdg/hypr/punar-input.lua")

local function config_home()
    local home = os.getenv("XDG_CONFIG_HOME")
    if not home or home:sub(1, 1) ~= "/" then
        home = (os.getenv("HOME") or "") .. "/.config"
    end
    return home
end

-- The first 4 KiB of one of the person's small preference files, or "".
local function preference_text(name)
    local file = io.open(config_home() .. "/punar/" .. name, "r")
    if not file then
        return ""
    end
    local text = file:read(4096) or ""
    file:close()
    return text
end

-- The person's optional Mac-style clipboard grammar, as data: one word from
-- ~/.config/punar/keyboard.json, written by `punarctl keyboard clipboard-keys`.
-- Anything but "mac" is the standard grammar.
local function clipboard_keys()
    if preference_text("keyboard.json"):match('"clipboardKeys"%s*:%s*"mac"') then
        return "mac"
    end
    return "standard"
end

-- The person's window look (transparency, gaps, a square lone window), as
-- data: three booleans from ~/.config/punar/look.json, written by `punarctl
-- window look`, which PUNAR+CTRL+T/G/A run. Matched with patterns, never
-- run, so the toggles survive a reload and the next session without the
-- code-as-state files Omarchy keeps (SMP-1405 WP-02). Missing or malformed
-- is the default look.
local function look()
    local text = preference_text("look.json")
    local versioned = text:match('"version"%s*:%s*1[^%d]') ~= nil
    local function flag(key, default)
        if not versioned then
            return default
        end
        local value = text:match('"' .. key .. '"%s*:%s*(%a+)')
        if value == "true" then
            return true
        elseif value == "false" then
            return false
        end
        return default
    end
    return {
        transparency = flag("transparency", false),
        gaps = flag("gaps", true),
        square = flag("square", false),
    }
end

hl.config({
    input = input.config(),
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
    session = session,
    session_end = sessionEnd,
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
    punarctl = "punarctl",
    -- The file manager opens through the launcher's own verb, so a key and a
    -- click on its row in the command center do the same thing one way.
    files = "punarctl app open thunar",
    clipboard_keys = clipboard_keys(),
    look = look(),
})

-- User-created web-app rules are derived from punard's root-owned inventory.
-- session.sh guarantees this file exists before Hyprland starts, and a later
-- `punarctl web-apps sync` performs a full config reload so removed rules
-- cannot remain live. The fragment contains only validated ids/workspaces and
-- calls `hl.window_rule`; it has no commands or browser arguments.
local configHome = os.getenv("XDG_CONFIG_HOME")
if not configHome or configHome == "" then
    configHome = (os.getenv("HOME") or "") .. "/.config"
end
local webAppRules = configHome .. "/hypr/punar-webapps.lua"
local webAppRulesFile = io.open(webAppRules, "r")
if webAppRulesFile then
    webAppRulesFile:close()
    dofile(webAppRules)
end

-- The product file is empty. The development profile overlays it with one
-- hyprland.start hook for VM/CI readiness evidence.
require("/etc/xdg/hypr/punar-session-profile.lua")
