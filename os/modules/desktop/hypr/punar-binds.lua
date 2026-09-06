-- Punar-key grammar. SUPER is the physical modifier name only; every product
-- surface and user-facing instruction calls it the Punar key.

return function(ctx)
    local mod = ctx.mod

    local function bind(keys, dispatcher, description, options)
        local opts = options or {}
        opts.description = description
        return hl.bind(keys, dispatcher, opts)
    end

    bind(mod .. " + H", hl.dsp.focus({ direction = "left" }), "Focus left")
    bind(mod .. " + J", hl.dsp.focus({ direction = "down" }), "Focus down")
    bind(mod .. " + K", hl.dsp.focus({ direction = "up" }), "Focus up")
    bind(mod .. " + L", hl.dsp.focus({ direction = "right" }), "Focus right")

    bind(mod .. " + SHIFT + H", hl.dsp.window.move({ direction = "left" }), "Move window left")
    bind(mod .. " + SHIFT + J", hl.dsp.window.move({ direction = "down" }), "Move window down")
    bind(mod .. " + SHIFT + K", hl.dsp.window.move({ direction = "up" }), "Move window up")
    bind(mod .. " + SHIFT + L", hl.dsp.window.move({ direction = "right" }), "Move window right")

    bind(mod .. " + G", hl.dsp.group.toggle(), "Toggle window group")
    bind(mod .. " + SHIFT + G", hl.dsp.window.move({ out_of_group = true }), "Move window out of group")
    bind(mod .. " + bracketleft", hl.dsp.group.prev(), "Previous window in group")
    bind(mod .. " + bracketright", hl.dsp.group.next(), "Next window in group")
    bind(mod .. " + CTRL + H", hl.dsp.window.move({ into_group = "left" }), "Move window into group left")
    bind(mod .. " + CTRL + J", hl.dsp.window.move({ into_group = "down" }), "Move window into group below")
    bind(mod .. " + CTRL + K", hl.dsp.window.move({ into_group = "up" }), "Move window into group above")
    bind(mod .. " + CTRL + L", hl.dsp.window.move({ into_group = "right" }), "Move window into group right")

    bind(mod .. " + R", hl.dsp.submap("resize"), "Enter resize mode")
    hl.define_submap("resize", function()
        bind("H", hl.dsp.window.resize({ x = -40, y = 0, relative = true }), "Resize narrower", { repeating = true })
        bind("J", hl.dsp.window.resize({ x = 0, y = 40, relative = true }), "Resize taller", { repeating = true })
        bind("K", hl.dsp.window.resize({ x = 0, y = -40, relative = true }), "Resize shorter", { repeating = true })
        bind("L", hl.dsp.window.resize({ x = 40, y = 0, relative = true }), "Resize wider", { repeating = true })
        bind("escape", hl.dsp.submap("reset"), "Exit resize mode")
        bind("Return", hl.dsp.submap("reset"), "Exit resize mode")
    end)

    bind(mod .. " + F", hl.dsp.window.fullscreen({ mode = "fullscreen" }), "Toggle fullscreen")
    bind(mod .. " + V", hl.dsp.window.float({ action = "toggle" }), "Toggle floating")
    bind(mod .. " + SHIFT + V", hl.dsp.window.pin({ action = "toggle" }), "Pin floating window")
    bind(mod .. " + C", hl.dsp.window.center(), "Center floating window")
    bind(mod .. " + comma", hl.dsp.exec_cmd(ctx.layout_script .. " prev"), "Previous layout preset")
    bind(mod .. " + period", hl.dsp.exec_cmd(ctx.layout_script .. " next"), "Next layout preset")

    for workspace = 1, 9 do
        local key = tostring(workspace)
        bind(mod .. " + " .. key, hl.dsp.focus({ workspace = workspace }), "Workspace " .. key)
        bind(mod .. " + SHIFT + " .. key, hl.dsp.window.move({ workspace = workspace }), "Move window to workspace " .. key)
    end

    bind(mod .. " + Tab", hl.dsp.exec_cmd(ctx.overview), "Project overview")
    bind(mod .. " + SHIFT + Tab", hl.dsp.focus({ workspace = "e-1" }), "Previous workspace")
    bind(mod .. " + Space", hl.dsp.exec_cmd(ctx.command_center), "Open command center")
    -- macOS commonly reserves Command+Space before a VM client can forward
    -- it. Shift+Space is the explicit transport-safe fallback; clicking the
    -- PUNAR brand in the bar reaches the same surface without a keyboard.
    bind(mod .. " + SHIFT + Space", hl.dsp.exec_cmd(ctx.command_center), "Open command center (VM fallback)")
    bind(mod .. " + Q", hl.dsp.window.close(), "Close window")
    -- The chord opens a confirmation surface; force quit itself is never a
    -- one-key compositor binding. The same surface is reachable by clicking
    -- the focused app name in the bar.
    bind(mod .. " + SHIFT + Q", hl.dsp.exec_cmd(ctx.shell .. " ipc call windowactions toggle"), "Window actions")
    bind(mod .. " + Return", hl.dsp.exec_cmd(ctx.terminal .. " || " .. ctx.terminal_fallback), "Open terminal")
    bind(mod .. " + B", hl.dsp.exec_cmd(ctx.browser), "Open browser")
    bind(mod .. " + A", hl.dsp.exec_cmd(ctx.ai_panel), "AI on this device")
    bind(mod .. " + P", hl.dsp.exec_cmd(ctx.shell .. " ipc call privacypanel toggle"), "Privacy and network activity")
    bind(mod .. " + T", hl.dsp.exec_cmd(ctx.scratchpad_script), "Toggle scratchpad terminal")
    bind(mod .. " + SHIFT + A", hl.dsp.workspace.toggle_special("assistant"), "Toggle assistant scratchpad")
    bind(mod .. " + N", hl.dsp.workspace.toggle_special("notes"), "Toggle notes scratchpad")

    local function scratchpad_rule(name, class, workspace)
        hl.window_rule({
            name = name,
            match = { class = "^(" .. class .. ")$" },
            workspace = "special:" .. workspace .. " silent",
            float = true,
            size = "monitor_w*0.6 monitor_h*0.6",
            center = true,
        })
    end

    scratchpad_rule("punar-terminal-scratchpad", ctx.scratch_class, "term")
    scratchpad_rule("punar-assistant-scratchpad", ctx.assistant_class, "assistant")
    scratchpad_rule("punar-notes-scratchpad", ctx.notes_class, "notes")

    hl.window_rule({
        name = "punar-portal-dialogs",
        match = { class = "^(xdg-desktop-portal-gtk|xdg-desktop-portal-gnome|org.freedesktop.impl.portal.desktop.kde)$" },
        float = true,
        center = true,
    })
    hl.window_rule({
        name = "punar-file-dialogs",
        match = { title = "^(Open File|Open Files|Open Folder|Save File|Save As|File Upload)$" },
        float = true,
        center = true,
    })

    bind(mod .. " + SHIFT + left", hl.dsp.window.move({ monitor = "l" }), "Move window to left monitor")
    bind(mod .. " + SHIFT + right", hl.dsp.window.move({ monitor = "r" }), "Move window to right monitor")
    bind(mod .. " + SHIFT + up", hl.dsp.window.move({ monitor = "u" }), "Move window to upper monitor")
    bind(mod .. " + SHIFT + down", hl.dsp.window.move({ monitor = "d" }), "Move window to lower monitor")

    bind("Print", hl.dsp.exec_cmd("grim - | wl-copy --type image/png"), "Screenshot output to clipboard")
    bind(mod .. " + SHIFT + S", hl.dsp.exec_cmd([[grim -g "$(slurp)" - | wl-copy --type image/png]]), "Screenshot region to clipboard")
    bind(mod .. " + SHIFT + N", hl.dsp.exec_cmd(ctx.shell .. " ipc call notifications toggle"), "Notification centre")
    bind("XF86AudioRaiseVolume", hl.dsp.exec_cmd("wpctl set-volume -l 1.0 @DEFAULT_AUDIO_SINK@ 5%+"), "Volume up", { repeating = true })
    bind("XF86AudioLowerVolume", hl.dsp.exec_cmd("wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"), "Volume down", { repeating = true })
    bind("XF86AudioMute", hl.dsp.exec_cmd("wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"), "Toggle mute")
    bind(mod .. " + SHIFT + E", hl.dsp.exit(), "End session")
    bind(mod .. " + slash", hl.dsp.exec_cmd(ctx.shell .. " ipc call shortcuts toggle"), "Shortcut help")
    bind(mod .. " + SHIFT + B", hl.dsp.exec_cmd(ctx.shell .. " ipc call bar focus"), "Focus status cluster")
    bind(mod .. " + S", hl.dsp.exec_cmd(ctx.shell .. " ipc call systemcontrol toggle"), "System control")
    bind(mod .. " + escape", hl.dsp.exec_cmd(ctx.lock), "Lock session")
end
