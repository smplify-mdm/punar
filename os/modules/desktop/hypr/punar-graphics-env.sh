#!/bin/sh
# Select the compositor rendering path from the DRM devices present at login.
#
# Punar's QEMU gate deliberately uses virtio-vga without virgl, so that path
# needs Mesa software rendering and disabled buffer modifiers. Exporting those
# flags on every machine, however, silently disables the GPU on bare metal.
# Any real DRM device therefore wins over virtual/fallback devices; systems
# with only a virtual adapter (or no resolvable adapter) keep the proven safe
# software path. This file is sourced by session.sh before Hyprland starts.

punar_configure_graphics() {
    punar_drm_root="${PUNAR_DRM_SYSFS_ROOT:-/sys/class/drm}"
    punar_drm_drivers=""
    punar_drm_cards=0
    punar_real_gpu=0

    for punar_card in "${punar_drm_root}"/card[0-9]*; do
        [ -e "${punar_card}" ] || continue
        punar_drm_cards=$((punar_drm_cards + 1))
        punar_driver=""

        # module is the useful name for PCI wrapper drivers (virtio-pci's DRM
        # module is virtio_gpu). Fall back to the bound driver's own name for
        # built-in drivers that do not expose a module symlink.
        if [ -L "${punar_card}/device/driver/module" ]; then
            punar_link="$(readlink "${punar_card}/device/driver/module" 2>/dev/null || true)"
            punar_driver="${punar_link##*/}"
        elif [ -L "${punar_card}/device/driver" ]; then
            punar_link="$(readlink "${punar_card}/device/driver" 2>/dev/null || true)"
            punar_driver="${punar_link##*/}"
        fi
        [ -n "${punar_driver}" ] || punar_driver="unknown"

        if [ -n "${punar_drm_drivers}" ]; then
            punar_drm_drivers="${punar_drm_drivers},${punar_driver}"
        else
            punar_drm_drivers="${punar_driver}"
        fi

        case "${punar_driver}" in
            virtio_gpu|virtio_pci|virtio-pci|qxl|vmwgfx|vboxvideo|hyperv_drm|\
            bochs|bochs_drm|simpledrm|vkms|udl|evdi|ast|unknown)
                :
                ;;
            *)
                # i915/xe/amdgpu/radeon/nouveau/nvidia_drm and ARM display
                # drivers such as vc4/panfrost/msm all land here. An unknown
                # but correctly bound DRM driver should get its accelerator.
                punar_real_gpu=1
                ;;
        esac
    done

    if [ "${punar_real_gpu}" -eq 1 ]; then
        PUNAR_GRAPHICS_MODE=hardware
        unset AQ_NO_MODIFIERS LIBGL_ALWAYS_SOFTWARE
    else
        PUNAR_GRAPHICS_MODE=software
        AQ_NO_MODIFIERS=1
        LIBGL_ALWAYS_SOFTWARE=1
        export AQ_NO_MODIFIERS LIBGL_ALWAYS_SOFTWARE
    fi

    if [ "${punar_drm_cards}" -eq 0 ]; then
        punar_drm_drivers=none
    fi
    PUNAR_DRM_DRIVERS="${punar_drm_drivers}"
    export PUNAR_GRAPHICS_MODE PUNAR_DRM_DRIVERS
}

# Select the compositor config after punar_configure_graphics. Real GPUs use
# the product config directly. An unaccelerated virtual adapter receives the
# same Lua config through one private runtime overlay that disables compositor
# animation; this avoids asking llvmpipe to draw transition frames while
# leaving bare-metal motion untouched and never falls back to legacy hyprlang.
punar_select_hyprland_config() {
    punar_system_config="${PUNAR_HYPRLAND_SYSTEM_CONFIG:-/etc/xdg/hypr/hyprland.lua}"
    PUNAR_HYPRLAND_CONFIG="${punar_system_config}"

    if [ "${PUNAR_GRAPHICS_MODE:-software}" = software ] \
        && [ -n "${XDG_RUNTIME_DIR:-}" ] \
        && [ -d "${XDG_RUNTIME_DIR}" ]; then
        PUNAR_HYPRLAND_CONFIG="${XDG_RUNTIME_DIR}/punar-hyprland-software.lua"
        umask 077
        {
            printf 'require(%s)\n' "$(printf '%s' "${punar_system_config}" | sed 's/\\/\\\\/g; s/"/\\"/g; s/^/"/; s/$/"/')"
            printf '%s\n' 'hl.config({ animations = { enabled = false } })'
        } > "${PUNAR_HYPRLAND_CONFIG}"
    fi

    export PUNAR_HYPRLAND_CONFIG
}
