-- Development/CI hook layered over the product Hyprland configuration.
hl.on("hyprland.start", function()
    hl.exec_cmd("/usr/lib/punar/desktop-ready.sh")
end)
