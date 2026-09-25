-- Punar-key grammar. SUPER is the physical modifier name only; every product
-- surface and user-facing instruction calls it the Punar key.
--
-- EVERY BIND HAS A DESCRIPTION, AND NO CHORD IS BOUND TWICE.
-- tests/desktop/keybind-contract-test.sh reads this file and fails on either,
-- and holds each Omarchy key family (Appendix B of the Punar-vs-Omarchy plan)
-- to a Punar row or a stated reason. The shortcut help (PUNAR+/) renders the
-- live table, so a description is also the only way a person finds a chord.
--
-- SMP-1405 WP-02 added the window grammar Omarchy has (split toggle, swap,
-- maximize, pop-out, a tenth workspace, quiet moves, workspace scroll, moving
-- a workspace between monitors), Alt+Tab with previews, the media, microphone
-- and brightness keys, the optional Mac-style clipboard keys, the file
-- manager on PUNAR+E, three kept look toggles, and pointer move and resize.
-- Keys that reach the system run a `punarctl` verb, so a terminal and the
-- keyboard do each thing one way.
--
-- EVERY CHORD WORKS UNDER EVERY KEYBOARD LAYOUT. Hyprland matches a keysym
-- bind against the first layout's UNSHIFTED symbol for the key pressed. A
-- letter is unshifted on every Latin layout (and the Latin lead covers the
-- rest, punar-input.lua), but digits and punctuation are not: on AZERTY the
-- number row types & é " ' ( … unshifted, and German, Spanish and Italian
-- put / and the brackets behind Shift or AltGr. So the number row is bound
-- by its key CODE (code:10 is the 1 key … code:19 the 0 key), as Omarchy's
-- workspace keys are, and every punctuation chord has a twin on a key every
-- layout names the same (F1, Tab), or a stated reason
-- (tests/desktop/keybind-contract-test.sh holds both rules).

return function(ctx)
    local mod = ctx.mod
    local mac_clipboard = ctx.clipboard_keys == "mac"

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

    -- Swap trades places with the neighbour; move (above) walks the window
    -- through the layout. Omarchy K26-K29.
    bind(mod .. " + ALT + H", hl.dsp.window.swap({ direction = "left" }), "Swap window left")
    bind(mod .. " + ALT + J", hl.dsp.window.swap({ direction = "down" }), "Swap window down")
    bind(mod .. " + ALT + K", hl.dsp.window.swap({ direction = "up" }), "Swap window up")
    bind(mod .. " + ALT + L", hl.dsp.window.swap({ direction = "right" }), "Swap window right")

    bind(mod .. " + G", hl.dsp.group.toggle(), "Toggle window group")
    bind(mod .. " + SHIFT + G", hl.dsp.window.move({ out_of_group = true }), "Move window out of group")
    bind(mod .. " + bracketleft", hl.dsp.group.prev(), "Previous window in group")
    bind(mod .. " + bracketright", hl.dsp.group.next(), "Next window in group")
    -- The brackets sit behind AltGr on German, French and Spanish keyboards;
    -- Tab is Tab everywhere (Omarchy's own chord for this, K58/K59).
    bind(mod .. " + ALT + Tab", hl.dsp.group.next(), "Next window in group (any layout)")
    bind(mod .. " + ALT + SHIFT + Tab", hl.dsp.group.prev(), "Previous window in group (any layout)")
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
    -- Maximize keeps the bar and the gaps; fullscreen covers everything.
    bind(mod .. " + M", hl.dsp.window.fullscreen({ mode = "maximized" }), "Toggle maximize")
    -- The Mac-style clipboard keys take PUNAR+C and PUNAR+V, so the two
    -- floating-window binds they displace move to the same letters with ALT.
    bind(mod .. (mac_clipboard and " + ALT + V" or " + V"), hl.dsp.window.float({ action = "toggle" }), "Toggle floating")
    bind(mod .. " + SHIFT + V", hl.dsp.window.pin({ action = "toggle" }), "Pin floating window")
    bind(mod .. (mac_clipboard and " + ALT + C" or " + C"), hl.dsp.window.center(), "Center floating window")
    -- Pop out: float, size, centre and pin the focused window over its
    -- workspace, or put a popped-out window back. `punarctl window pop`
    -- reads the window's state and sends the dispatchers in the right order.
    bind(mod .. " + O", hl.dsp.exec_cmd(ctx.punarctl .. " window pop"), "Pop window out")
    -- The split direction of the focused dwindle pair. In the other presets
    -- the layout owns direction and this does nothing.
    bind(mod .. " + D", hl.dsp.layout("togglesplit"), "Toggle split direction")
    bind(mod .. " + comma", hl.dsp.exec_cmd(ctx.layout_script .. " --workspace active prev"), "Previous layout preset")
    bind(mod .. " + period", hl.dsp.exec_cmd(ctx.layout_script .. " --workspace active next"), "Next layout preset")

    -- THREE LOOPS, AND THE ORDER IS THE POINT. Plate D-017 Sect I says the
    -- workspace binds are one idea, and the shortcut reference folds a
    -- contiguous digit run into a single row — but only when consecutive
    -- rows share a description base, because `hyprctl binds -j` reports
    -- binds in registration order and the reference renders that order.
    -- Registering them interleaved (Workspace 1, Move window to workspace
    -- 1, Workspace 2, ...) breaks the run at every step, so the fold never
    -- fired and the surface printed eighteen near-identical rows into the
    -- middle of the reference. The shipped proof counted 75 BINDS · 75
    -- ROWS: not one fold in the whole table.
    --
    -- Ten workspaces, as Omarchy has: the tenth is on the 0 key, the key
    -- after 9 on the number row, and the reference folds it into the run.
    -- By key CODE (the header says why): code:10 is the 1 key and code:19
    -- the 0 key on every keyboard, whatever the layout prints unshifted.
    local function number_key(workspace)
        return "code:" .. tostring(workspace + 9)
    end
    for workspace = 1, 10 do
        bind(mod .. " + " .. number_key(workspace), hl.dsp.focus({ workspace = workspace }), "Workspace " .. workspace)
    end
    for workspace = 1, 10 do
        bind(mod .. " + SHIFT + " .. number_key(workspace), hl.dsp.window.move({ workspace = workspace }), "Move window to workspace " .. workspace)
    end
    -- Quiet: the window goes, the person stays where they are.
    for workspace = 1, 10 do
        bind(mod .. " + ALT + " .. number_key(workspace), hl.dsp.window.move({ workspace = workspace, follow = false }), "Move window quietly to workspace " .. workspace)
    end

    bind(mod .. " + Tab", hl.dsp.exec_cmd(ctx.overview), "Project overview")
    bind(mod .. " + SHIFT + Tab", hl.dsp.focus({ workspace = "e-1" }), "Previous workspace")
    bind(mod .. " + CTRL + Tab", hl.dsp.focus({ workspace = "e+1" }), "Next workspace")
    bind(mod .. " + mouse_down", hl.dsp.focus({ workspace = "e+1" }), "Scroll to the next workspace")
    bind(mod .. " + mouse_up", hl.dsp.focus({ workspace = "e-1" }), "Scroll to the previous workspace")
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
    bind(mod .. " + E", hl.dsp.exec_cmd(ctx.files), "Open files")
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
    -- One definition of "a terminal", for the clipboard keys below: foot as
    -- itself, as a client of its server, and as the scratchpad.
    hl.window_rule({
        name = "punar-terminal-tag",
        match = { class = "^(foot|footclient|" .. ctx.scratch_class .. ")$" },
        tag = "+terminal",
    })

    bind(mod .. " + SHIFT + left", hl.dsp.window.move({ monitor = "l" }), "Move window to left monitor")
    bind(mod .. " + SHIFT + right", hl.dsp.window.move({ monitor = "r" }), "Move window to right monitor")
    bind(mod .. " + SHIFT + up", hl.dsp.window.move({ monitor = "u" }), "Move window to upper monitor")
    bind(mod .. " + SHIFT + down", hl.dsp.window.move({ monitor = "d" }), "Move window to lower monitor")
    bind(mod .. " + ALT + left", hl.dsp.workspace.move({ monitor = "l" }), "Move workspace to left monitor")
    bind(mod .. " + ALT + right", hl.dsp.workspace.move({ monitor = "r" }), "Move workspace to right monitor")
    bind(mod .. " + ALT + up", hl.dsp.workspace.move({ monitor = "u" }), "Move workspace to upper monitor")
    bind(mod .. " + ALT + down", hl.dsp.workspace.move({ monitor = "d" }), "Move workspace to lower monitor")

    -- ALT+TAB: THE WINDOW SWITCHER. The compositor counts the Tab presses of
    -- one Alt hold and the shell draws them: every press sends `step` with
    -- the gesture's number and its running count, and the release of Alt
    -- sends `commit` with the same two numbers. Because each call carries the
    -- whole state, the shell reaches the same answer whatever order two quick
    -- processes land in; a quick tap is `step 1` and `commit 1` and switches
    -- to the previous window, like every Alt+Tab. (Not `show`: `qs ipc`
    -- parses that word as its own subcommand wherever it appears.) The shell focuses the chosen
    -- window with `punarctl window focus --address`. Alt released while Shift
    -- is still held is covered by the SHIFT release binds.
    local switching = false
    -- Seeded from the clock, so a configuration reload (which restarts this
    -- counter) can never hand the shell a gesture number it already finished.
    local gesture = os.time() * 100
    local steps = 0
    local function switcher(verb)
        hl.exec_cmd(ctx.shell .. " ipc call windowswitcher " .. verb .. " " .. tostring(gesture) .. " " .. tostring(steps))
    end
    local function switch_step(delta)
        return function()
            if not switching then
                switching = true
                gesture = gesture + 1
                steps = 0
            end
            steps = steps + delta
            switcher("step")
        end
    end
    local function switch_done()
        if switching then
            switching = false
            switcher("commit")
        end
    end
    bind("ALT + Tab", switch_step(1), "Switch windows")
    bind("ALT + SHIFT + Tab", switch_step(-1), "Switch windows backwards")
    -- NON-CONSUMING: the release of Alt still reaches the focused window.
    -- A consuming release bind would eat EVERY Alt release, switching or not,
    -- and Firefox, Thunderbird and every GTK or Qt app with a menu bar opens
    -- it on a bare Alt release. The bind only listens; it never takes the key.
    bind("ALT + Alt_L", switch_done, "Choose the window on Alt release", { release = true, non_consuming = true })
    bind("ALT + Alt_R", switch_done, "Choose the window on right Alt release", { release = true, non_consuming = true })
    bind("ALT + SHIFT + Alt_L", switch_done, "Choose the window on Shift+Alt release", { release = true, non_consuming = true })
    bind("ALT + SHIFT + Alt_R", switch_done, "Choose the window on Shift+right Alt release", { release = true, non_consuming = true })
    bind("CTRL + ALT + Tab", hl.dsp.focus({ monitor = "+1" }), "Focus next monitor")
    bind("CTRL + ALT + SHIFT + Tab", hl.dsp.focus({ monitor = "-1" }), "Focus previous monitor")

    bind("Print", hl.dsp.exec_cmd("grim - | wl-copy --type image/png"), "Screenshot output to clipboard")
    bind(mod .. " + SHIFT + S", hl.dsp.exec_cmd([[grim -g "$(slurp)" - | wl-copy --type image/png]]), "Screenshot region to clipboard")
    bind(mod .. " + SHIFT + N", hl.dsp.exec_cmd(ctx.shell .. " ipc call notifications toggle"), "Notification centre")

    -- MEDIA, MICROPHONE AND BRIGHTNESS. `locked = true`: these work on the
    -- lock screen too, as on every laptop; none of them reveals anything.
    -- Volume stays on wireplumber directly because the OSD reads the sink,
    -- not the key. The rest run punarctl: MPRIS for the media keys, the
    -- default source for the microphone, and logind's SetBrightness on this
    -- session's own object for the backlight (no root, no video group, no
    -- udev rule). On a machine with no backlight the verb says so and exits
    -- 6, and nothing is drawn.
    bind("XF86AudioRaiseVolume", hl.dsp.exec_cmd("wpctl set-volume -l 1.0 @DEFAULT_AUDIO_SINK@ 5%+"), "Volume up", { repeating = true, locked = true })
    bind("XF86AudioLowerVolume", hl.dsp.exec_cmd("wpctl set-volume @DEFAULT_AUDIO_SINK@ 5%-"), "Volume down", { repeating = true, locked = true })
    bind("ALT + XF86AudioRaiseVolume", hl.dsp.exec_cmd("wpctl set-volume -l 1.0 @DEFAULT_AUDIO_SINK@ 1%+"), "Volume up a little", { repeating = true, locked = true })
    bind("ALT + XF86AudioLowerVolume", hl.dsp.exec_cmd("wpctl set-volume @DEFAULT_AUDIO_SINK@ 1%-"), "Volume down a little", { repeating = true, locked = true })
    bind("XF86AudioMute", hl.dsp.exec_cmd("wpctl set-mute @DEFAULT_AUDIO_SINK@ toggle"), "Toggle mute", { locked = true })
    bind("XF86AudioMicMute", hl.dsp.exec_cmd(ctx.punarctl .. " audio mute --input"), "Toggle microphone mute", { locked = true })
    bind("XF86AudioPlay", hl.dsp.exec_cmd(ctx.punarctl .. " media play-pause"), "Play or pause", { locked = true })
    bind("XF86AudioPause", hl.dsp.exec_cmd(ctx.punarctl .. " media play-pause"), "Play or pause (pause key)", { locked = true })
    bind("XF86AudioNext", hl.dsp.exec_cmd(ctx.punarctl .. " media next"), "Next track", { locked = true })
    bind("XF86AudioPrev", hl.dsp.exec_cmd(ctx.punarctl .. " media previous"), "Previous track", { locked = true })
    bind("XF86MonBrightnessUp", hl.dsp.exec_cmd(ctx.punarctl .. " display brightness +5%"), "Brightness up", { repeating = true, locked = true })
    bind("XF86MonBrightnessDown", hl.dsp.exec_cmd(ctx.punarctl .. " display brightness -5%"), "Brightness down", { repeating = true, locked = true })
    bind("ALT + XF86MonBrightnessUp", hl.dsp.exec_cmd(ctx.punarctl .. " display brightness +1%"), "Brightness up a little", { repeating = true, locked = true })
    bind("ALT + XF86MonBrightnessDown", hl.dsp.exec_cmd(ctx.punarctl .. " display brightness -1%"), "Brightness down a little", { repeating = true, locked = true })
    bind("XF86KbdBrightnessUp", hl.dsp.exec_cmd(ctx.punarctl .. " display brightness --keyboard +34%"), "Keyboard light up", { locked = true })
    bind("XF86KbdBrightnessDown", hl.dsp.exec_cmd(ctx.punarctl .. " display brightness --keyboard -34%"), "Keyboard light down", { locked = true })

    bind(mod .. " + SHIFT + E", hl.dsp.exit(), "End session")
    bind(mod .. " + slash", hl.dsp.exec_cmd(ctx.shell .. " ipc call shortcuts toggle"), "Shortcut help")
    -- / is Shift+7 on German, Spanish and Italian keyboards and Shift+: on
    -- French ones, where PUNAR+/ cannot be pressed at all; F1 is F1 on every
    -- layout, and it is the help key everywhere else too.
    bind(mod .. " + F1", hl.dsp.exec_cmd(ctx.shell .. " ipc call shortcuts toggle"), "Shortcut help (any layout)")
    bind(mod .. " + SHIFT + B", hl.dsp.exec_cmd(ctx.shell .. " ipc call bar focus"), "Focus status cluster")
    bind(mod .. " + S", hl.dsp.exec_cmd(ctx.shell .. " ipc call systemcontrol toggle"), "System control")
    bind(mod .. " + escape", hl.dsp.exec_cmd(ctx.lock), "Lock session")
    -- The session menu: lock, end session, restart, shut down in one place.
    -- BackSpace because it is free and because it is the chord this class of
    -- menu has on other Linux desktops; every letter key is already taken.
    bind(mod .. " + backspace", hl.dsp.exec_cmd(ctx.session), "Session menu")

    -- THE LOOK, FOR THIS SESSION. Omarchy persists its toggles by copying Lua
    -- files into ~/.local/state that its configuration then runs, the
    -- code-as-state pattern it had to patch in 4.0.1. These live in the
    -- compositor, write nothing, and end with the session or a reload.
    local translucent = false
    bind(mod .. " + CTRL + T", function()
        translucent = not translucent
        hl.config({
            decoration = {
                active_opacity = translucent and 0.96 or 1.0,
                inactive_opacity = translucent and 0.88 or 1.0,
            },
        })
    end, "Toggle window transparency")
    local gapless = false
    bind(mod .. " + CTRL + G", function()
        gapless = not gapless
        hl.config({
            general = {
                gaps_in = gapless and 0 or 4,
                gaps_out = gapless and 0 or 8,
            },
        })
    end, "Toggle window gaps")
    local square = false
    bind(mod .. " + CTRL + A", function()
        square = not square
        hl.config({ layout = { single_window_aspect_ratio = square and { 1, 1 } or { 0, 0 } } })
    end, "Toggle square shape for a lone window")

    -- MAC-STYLE CLIPBOARD KEYS, when the person turned them on
    -- (`punarctl keyboard clipboard-keys on`). The chord is sent to the
    -- focused surface as key state with explicit modifiers, so the held
    -- Punar key cannot leak into it; the release follows 50 ms later, the
    -- split Omarchy uses to keep Hyprland's synthetic state from sticking. A
    -- terminal gets Ctrl+Insert and Shift+Insert, which foot binds to copy
    -- and paste (foot.ini), so Ctrl+C still interrupts a program there.
    if mac_clipboard then
        local function send(mods, key)
            hl.dispatch(hl.dsp.send_key_state({ mods = mods, key = key, state = "down" }))
            hl.timer(function()
                hl.dispatch(hl.dsp.send_key_state({ mods = mods, key = key, state = "up" }))
            end, { timeout = 50, type = "oneshot" })
        end
        local function in_terminal()
            local window = hl.get_active_window()
            if not window then
                return false
            end
            for _, tag in ipairs(window.tags or {}) do
                if tag:gsub("%*$", "") == "terminal" then
                    return true
                end
            end
            return false
        end
        local function clipboard(plain_mods, plain_key, terminal_mods, terminal_key)
            return function()
                if in_terminal() then
                    send(terminal_mods, terminal_key)
                else
                    send(plain_mods, plain_key)
                end
            end
        end
        bind(mod .. " + C", clipboard("CTRL", "C", "CTRL", "Insert"), "Copy")
        bind(mod .. " + V", clipboard("CTRL", "V", "SHIFT", "Insert"), "Paste")
        bind(mod .. " + X", clipboard("CTRL", "X", "CTRL", "X"), "Cut")
    end

    -- POINTER MOVE AND RESIZE, LAST AND FENCED. The first attempt was backed
    -- out (BUILD-QUEUE.md, 2026-09 back-out): `hl.dsp.window.drag()` without
    -- the bind's `mouse = true` option has no argument semantics, and a
    -- throw during evaluation took every bind after it. `{ mouse = true }` is
    -- the missing piece, taken from Omarchy 4.0.4's tiling.lua (K50/K51) and
    -- accepted by Hyprland 0.56.2's --verify-config. Registered last, inside
    -- pcall, so even an unexpected error here leaves every bind above intact
    -- and is written to the compositor log instead.
    local pointer_ok, pointer_error = pcall(function()
        bind(mod .. " + mouse:272", hl.dsp.window.drag(), "Move window with the pointer", { mouse = true })
        bind(mod .. " + mouse:273", hl.dsp.window.resize(), "Resize window with the pointer", { mouse = true })
    end)
    if not pointer_ok then
        print("punar-binds: pointer move and resize are not bound: " .. tostring(pointer_error))
    end
end
