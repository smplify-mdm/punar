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

echo PUNAR_GRAPHICS_ENV_OK
