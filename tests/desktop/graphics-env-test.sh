#!/bin/sh
# Unit proof for the pre-compositor DRM policy. Fake sysfs trees make every
# branch deterministic and keep the hardware decision testable on CI runners.
set -eu

REPO_ROOT="$(cd -- "$(dirname "$0")/../.." && pwd)"
HELPER="${REPO_ROOT}/os/modules/desktop/hypr/punar-graphics-env.sh"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/punar-graphics-test.XXXXXX")"
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

make_card() {
    case_root="$1"
    card_number="$2"
    module_name="$3"
    mkdir -p "${case_root}/card${card_number}/device/driver"
    ln -s "../../../../module/${module_name}" \
        "${case_root}/card${card_number}/device/driver/module"
}

probe() {
    probe_root="$1"
    (
        AQ_NO_MODIFIERS=parent-value
        LIBGL_ALWAYS_SOFTWARE=parent-value
        export AQ_NO_MODIFIERS LIBGL_ALWAYS_SOFTWARE
        PUNAR_DRM_SYSFS_ROOT="${probe_root}"
        export PUNAR_DRM_SYSFS_ROOT
        # shellcheck source=/dev/null
        . "${HELPER}"
        punar_configure_graphics
        printf '%s|%s|%s|%s\n' \
            "${PUNAR_GRAPHICS_MODE}" \
            "${PUNAR_DRM_DRIVERS}" \
            "${AQ_NO_MODIFIERS-unset}" \
            "${LIBGL_ALWAYS_SOFTWARE-unset}"
    )
}

assert_probe() {
    name="$1"
    expected="$2"
    root="$3"
    actual="$(probe "${root}")"
    if [ "${actual}" != "${expected}" ]; then
        printf 'FAIL %s: expected %s, got %s\n' \
            "${name}" "${expected}" "${actual}" >&2
        exit 1
    fi
    printf 'ok   %s = %s\n' "${name}" "${actual}"
}

mkdir -p "${TEST_ROOT}/none"
assert_probe "no DRM device fails safe" \
    "software|none|1|1" "${TEST_ROOT}/none"

mkdir -p "${TEST_ROOT}/virtio"
make_card "${TEST_ROOT}/virtio" 0 virtio_gpu
assert_probe "virtio VM uses software rendering" \
    "software|virtio_gpu|1|1" "${TEST_ROOT}/virtio"

# Debian's ARM virtio stack can expose the wrapper module as virtio_pci
# rather than the DRM child module virtio_gpu. Both spellings describe the
# same unaccelerated QEMU rendering path.
mkdir -p "${TEST_ROOT}/virtio-pci"
make_card "${TEST_ROOT}/virtio-pci" 0 virtio_pci
assert_probe "virtio PCI wrapper uses software rendering" \
    "software|virtio_pci|1|1" "${TEST_ROOT}/virtio-pci"

mkdir -p "${TEST_ROOT}/amd"
make_card "${TEST_ROOT}/amd" 0 amdgpu
assert_probe "AMD bare metal keeps acceleration" \
    "hardware|amdgpu|unset|unset" "${TEST_ROOT}/amd"

mkdir -p "${TEST_ROOT}/mixed"
make_card "${TEST_ROOT}/mixed" 0 virtio_gpu
make_card "${TEST_ROOT}/mixed" 1 i915
assert_probe "a real GPU wins over a virtual secondary" \
    "hardware|virtio_gpu,i915|unset|unset" "${TEST_ROOT}/mixed"

mkdir -p "${TEST_ROOT}/pi"
make_card "${TEST_ROOT}/pi" 0 simpledrm
make_card "${TEST_ROOT}/pi" 1 vc4
assert_probe "Pi VC4 wins over early simpledrm" \
    "hardware|simpledrm,vc4|unset|unset" "${TEST_ROOT}/pi"

SOFTWARE_RUNTIME="${TEST_ROOT}/software-runtime"
mkdir -m 0700 "${SOFTWARE_RUNTIME}"
(
    # shellcheck source=/dev/null
    . "${HELPER}"
    PUNAR_GRAPHICS_MODE=software
    XDG_RUNTIME_DIR="${SOFTWARE_RUNTIME}"
    PUNAR_HYPRLAND_SYSTEM_CONFIG=/test/product-hyprland.conf
    export PUNAR_GRAPHICS_MODE XDG_RUNTIME_DIR PUNAR_HYPRLAND_SYSTEM_CONFIG
    punar_select_hyprland_config
    [ "${PUNAR_HYPRLAND_CONFIG}" = \
        "${SOFTWARE_RUNTIME}/punar-hyprland-software.conf" ]
)
EXPECTED_SOFTWARE_CONFIG='source = /test/product-hyprland.conf
animations { enabled = false }'
ACTUAL_SOFTWARE_CONFIG="$(cat "${SOFTWARE_RUNTIME}/punar-hyprland-software.conf")"
[ "${ACTUAL_SOFTWARE_CONFIG}" = "${EXPECTED_SOFTWARE_CONFIG}" ] || {
    printf 'FAIL software compositor overlay: got %s\n' \
        "${ACTUAL_SOFTWARE_CONFIG}" >&2
    exit 1
}
printf 'ok   software compositor overlay disables animation\n'

HARDWARE_RUNTIME="${TEST_ROOT}/hardware-runtime"
mkdir -m 0700 "${HARDWARE_RUNTIME}"
HARDWARE_CONFIG="$(
    # shellcheck source=/dev/null
    . "${HELPER}"
    PUNAR_GRAPHICS_MODE=hardware
    XDG_RUNTIME_DIR="${HARDWARE_RUNTIME}"
    PUNAR_HYPRLAND_SYSTEM_CONFIG=/test/product-hyprland.conf
    export PUNAR_GRAPHICS_MODE XDG_RUNTIME_DIR PUNAR_HYPRLAND_SYSTEM_CONFIG
    punar_select_hyprland_config
    printf '%s' "${PUNAR_HYPRLAND_CONFIG}"
)"
[ "${HARDWARE_CONFIG}" = /test/product-hyprland.conf ] || {
    printf 'FAIL hardware compositor config: got %s\n' "${HARDWARE_CONFIG}" >&2
    exit 1
}
[ ! -e "${HARDWARE_RUNTIME}/punar-hyprland-software.conf" ] || {
    printf 'FAIL hardware path created a software compositor overlay\n' >&2
    exit 1
}
printf 'ok   hardware compositor path keeps product motion\n'

echo PUNAR_GRAPHICS_ENV_OK
