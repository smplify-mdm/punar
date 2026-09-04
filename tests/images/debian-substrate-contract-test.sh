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
grep -Fxq '         linux-image-amd64' "${REPO_ROOT}/os/images/amd64-debian/mkosi.conf" \
    || fail "amd64 candidate lacks Debian's kernel metapackage"
grep -Fq 'console=ttyS0' \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/dev/mkosi.conf" \
    || fail "amd64 dev candidate cannot reach the x86 serial boot harness"

# The migration lane must not overwrite the canonical artifact while the
# baseline remains the release authority.
grep -Fq 'punar-dev-debian-x86_64.qcow2' \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    || fail "candidate output is not independently named"
grep -Fxq 'Distribution=arch' "${REPO_ROOT}/os/images/mkosi.conf" \
    || fail "shipping x86 baseline changed before Debian runtime proof"

echo 'PUNAR_DEBIAN_SUBSTRATE_CONTRACT_OK'
