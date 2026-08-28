-- Punar's restrained paper-and-ink compositor treatment.

hl.config({
    general = {
        border_size = 1,
        col = {
            active_border = "rgb(000000)",
            inactive_border = "rgb(26282E)",
        },
        gaps_in = 4,
        gaps_out = 8,
        layout = "dwindle",
        -- Keyboard-first never means pointer-hostile. The visible 1 px rule
        -- retains the field-note grammar; Hyprland's invisible 15 px grab
        -- area makes tiled dividers and floating edges practical to drag.
        resize_on_border = true,
        extend_border_grab_area = 15,
        hover_icon_on_border = true,
    },
    decoration = {
        rounding = 10,
        blur = { enabled = false },
        shadow = { enabled = false },
        dim_inactive = false,
        dim_special = 0,
    },
    group = {
        col = {
            border_active = "rgb(000000)",
            border_inactive = "rgb(26282E)",
            border_locked_active = "rgb(333333)",
            border_locked_inactive = "rgb(26282E)",
        },
        groupbar = {
            enabled = true,
            font_family = "Geist Mono",
            font_size = 10,
            font_weight_active = "medium",
            font_weight_inactive = "normal",
            gradients = false,
            rounding = 0,
            height = 18,
            indicator_height = 2,
            text_color = "rgb(000000)",
            text_color_inactive = "rgb(666666)",
            col = {
                active = "rgb(000000)",
                inactive = "rgb(E6E4DE)",
                locked_active = "rgb(333333)",
                locked_inactive = "rgb(E6E4DE)",
            },
        },
    },
    animations = { enabled = true },
    misc = {
        disable_hyprland_logo = true,
        disable_splash_rendering = true,
        force_default_wallpaper = 0,
        background_color = "rgb(FAF9F6)",
        font_family = "Instrument Sans",
    },
    dwindle = { preserve_split = true },
})

hl.curve("punar", { type = "bezier", points = { { 0.2, 0 }, { 0, 1 } } })
hl.animation({ leaf = "global", enabled = false })
hl.animation({ leaf = "windowsMove", enabled = true, speed = 3, bezier = "punar" })
hl.animation({ leaf = "workspaces", enabled = true, speed = 3, bezier = "punar", style = "slide" })
hl.animation({ leaf = "specialWorkspace", enabled = true, speed = 3, bezier = "punar", style = "slidevert" })
