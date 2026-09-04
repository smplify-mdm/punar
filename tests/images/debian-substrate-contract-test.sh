#!/usr/bin/env bash
# Cheap guard for ADR-005's temporary migration overlap. Both Debian lanes
# must share one snapshot/version pin while retaining distinct builder-image
# digests and outputs; the Arch baseline remains untouched until runtime proof.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMON="${REPO_ROOT}/os/images/debian-snapshot.env"
ARM="${REPO_ROOT}/os/images/arm64/snapshot.env"
AMD64="${REPO_ROOT}/os/images/amd64-debian/snapshot.env"

fail() {
    echo "debian-substrate-contract-test: FAIL: $*" >&2
    exit 1
}

read_adapter() {
    local adapter=$1
    (
        # shellcheck source=/dev/null
        . "${adapter}"
        printf '%s|%s|%s|%s\n' \
            "${PUNAR_DEBIAN_SNAPSHOT}" \
            "${PUNAR_DEBIAN_SOURCE_DATE_EPOCH}" \
            "${PUNAR_BASE_IMAGE_VERSION}" \
            "${PUNAR_DEBIAN_BUILDER_BASE}"
    )
}

package_set() {
    awk '
        /^[[:space:]]*Packages=/ {
            collecting = 1
            sub(/^[[:space:]]*Packages=/, "")
            if (length($0)) print $0
            next
        }
        collecting && /^[[:space:]]+[^[:space:]#]/ {
            sub(/^[[:space:]]+/, "")
            print
            next
        }
        collecting { exit }
    ' "$1" | LC_ALL=C sort -u
}

[ -f "${COMMON}" ] || fail "shared Debian snapshot pin is missing"
arm_values="$(read_adapter "${ARM}")"
amd64_values="$(read_adapter "${AMD64}")"

[ "${arm_values%|*}" = "${amd64_values%|*}" ] \
    || fail "amd64 and arm64 do not share the snapshot, epoch and image version"
[ "${arm_values##*|}" != "${amd64_values##*|}" ] \
    || fail "architecture-specific builder images unexpectedly share a digest"

grep -Fxq 'Distribution=debian' "${REPO_ROOT}/os/images/amd64-debian/mkosi.conf" \
    || fail "amd64 candidate is not Debian"
grep -Fxq 'Release=unstable' "${REPO_ROOT}/os/images/amd64-debian/mkosi.conf" \
    || fail "amd64 candidate does not track pinned sid"
grep -Fxq 'Architecture=x86-64' "${REPO_ROOT}/os/images/amd64-debian/mkosi.conf" \
    || fail "amd64 candidate architecture is not x86-64"
for config in \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.conf" \
    "${REPO_ROOT}/os/images/arm64/mkosi.conf"; do
    grep -Fxq 'ExtraTrees=../debian-mkosi.extra' "${config}" \
        || fail "${config#"${REPO_ROOT}/"} does not compose the shared Debian adapter tree"
done
for adapter in \
    usr/lib/systemd/system/greetd.service.d/punar-vt.conf \
    usr/share/punar/platform/debian-chromium-flags; do
    [ -f "${REPO_ROOT}/os/images/debian-mkosi.extra/${adapter}" ] \
        || fail "shared Debian adapter is missing ${adapter}"
done
grep -Fxq '         linux-image-amd64' "${REPO_ROOT}/os/images/amd64-debian/mkosi.conf" \
    || fail "amd64 candidate lacks Debian's kernel metapackage"
grep -Fq 'console=ttyS0' \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/dev/mkosi.conf" \
    || fail "amd64 dev candidate cannot reach the x86 serial boot harness"
if grep -Eq '^Hostname=.*_' \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/dev/mkosi.conf"; then
    fail "amd64 candidate hostname contains a systemd-invalid underscore"
fi

arm_desktop_packages="$(package_set \
    "${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.conf")"
amd64_desktop_packages="$(package_set \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/desktop/mkosi.conf")"
[ "${arm_desktop_packages}" = "${amd64_desktop_packages}" ] \
    || fail "Debian desktop package adapters have drifted across architectures"
grep -Fxq '           mkosi.extra' \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/desktop/mkosi.conf" \
    || fail "amd64 desktop does not compose its architecture-local extra tree"
grep -Fxq 'Repositories=contrib,non-free,non-free-firmware' \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/hardware-x86/mkosi.conf" \
    || fail "amd64 hardware profile does not enable Debian's signed firmware components"
for package in firmware-linux firmware-iwlwifi firmware-realtek \
    firmware-sof-signed intel-microcode amd64-microcode \
    mesa-vulkan-drivers intel-media-va-driver-non-free; do
    grep -Eq "^(Packages=|[[:space:]]+)${package}$" \
        "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/hardware-x86/mkosi.conf" \
        || fail "amd64 hardware profile lacks ${package}"
done
grep -Fq -- '--profile desktop,hardware-x86,dev' \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    || fail "amd64 desktop candidate omits the bare-hardware support floor"
grep -Fq -- '--profile desktop,hardware-x86' \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    || fail "amd64 release candidate omits the bare-hardware support floor"
grep -Fq -- '--profile desktop,hardware-x86,installer' \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    || fail "amd64 installer candidate omits the product and hardware profiles"
grep -Fxq \
    'KernelCommandLine=console=tty0 rd.systemd.gpt_auto=0 systemd.getty_auto=no punar.live=1' \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/installer/mkosi.conf" \
    || fail "amd64 installer candidate lacks the bounded live-root command line"
for package in xorriso grub-common; do
    grep -Eq "^[[:space:]]+${package}( \\\\)?$" \
        "${REPO_ROOT}/os/images/builder-debian/Containerfile" \
        || fail "Debian builder lacks ISO assembly package ${package}"
done
# shellcheck disable=SC2016  # Literal Dockerfile guard; expansion is a defect.
grep -Fq 'if [ "$(dpkg --print-architecture)" = amd64 ]; then' \
    "${REPO_ROOT}/os/images/builder-debian/Containerfile" \
    || fail "Debian builder does not scope x86 GRUB modules to amd64"
grep -Fq 'apt-get install -y --no-install-recommends grub-efi-amd64-bin' \
    "${REPO_ROOT}/os/images/builder-debian/Containerfile" \
    || fail "Debian amd64 builder lacks the standalone EFI GRUB modules"
for variable in PUNAR_RELEASE_SNAPSHOT_PIN PUNAR_RELEASE_BUILDER_BASE \
    PUNAR_RELEASE_SOURCE_DATE_EPOCH PUNAR_RELEASE_TOOL; do
    grep -Fq "${variable}=" \
        "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
        || fail "amd64 installer does not pass ${variable} to the shared assembler"
done

# The migration lane must not overwrite the canonical artifact while the
# baseline remains the release authority.
grep -Fq 'run_mkosi punar-dev-debian-x86_64' \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    || fail "candidate output is not independently named"
# shellcheck disable=SC2016  # Literal source contracts; expansion is a defect.
grep -Fq 'PUNAR_AMD64_DEBIAN_IMAGES="${PUNAR_AMD64_DEBIAN_IMAGES:-minimal}"' \
    "${REPO_ROOT}/tools/build-amd64-debian-image.sh" \
    || fail "host wrapper does not expose the candidate image selector"
# shellcheck disable=SC2016  # Literal source contracts; expansion is a defect.
grep -Fq -- '--env "PUNAR_AMD64_DEBIAN_IMAGES=${PUNAR_AMD64_DEBIAN_IMAGES}"' \
    "${REPO_ROOT}/tools/build-amd64-debian-image.sh" \
    || fail "host wrapper does not pass the candidate image selector"
grep -Fq 'PUNAR_ENABLED_UNITS_MANIFEST=expected-enabled-units.x86_64-debian.txt' \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    || fail "candidate does not select its Debian-specific unit manifest"
grep -Fq 'minimal|desktop|release|iso|all' \
    "${REPO_ROOT}/tools/build-amd64-debian-image.sh" \
    || fail "host wrapper does not expose the Debian installer build selector"
grep -Fxq 'Distribution=arch' "${REPO_ROOT}/os/images/mkosi.conf" \
    || fail "shipping x86 baseline changed before Debian runtime proof"

echo 'PUNAR_DEBIAN_SUBSTRATE_CONTRACT_OK'
