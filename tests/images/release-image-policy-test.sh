#!/bin/sh
# Fixture proof for every release-image assertion. No image build or root
# privilege is required, so a denylist regression fails in seconds.
set -eu

REPO_ROOT=$(cd -- "$(dirname "$0")/../.." && pwd)
CHECKER="${REPO_ROOT}/os/images/check-release-image.sh"
FINALIZE="${REPO_ROOT}/os/images/mkosi.finalize"
ARM_POSTINSTALL="${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.postinst.chroot"
DESKTOP_STAGER="${REPO_ROOT}/os/images/scripts/container-build.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/punar-release-policy.XXXXXX")
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

grep -Fq 'systemctl disable seatd.service' "${ARM_POSTINSTALL}" || {
    echo 'FAIL ARM adapter: package-created seatd enablement must be removed' >&2
    exit 1
}
grep -Fq 'systemctl mask seatd.service' "${ARM_POSTINSTALL}" || {
    echo 'FAIL ARM adapter: seatd must remain masked when Debian presets run' >&2
    exit 1
}

# Browser pages used to exercise storage isolation are dev/CI input. Catch a
# destination regression here in seconds rather than after the release image
# has downloaded packages and reached its final tree scan.
grep -Fq "\"\${dev_extra}/usr/share/punar/fixtures/webapps/notes/index.html\"" \
    "${DESKTOP_STAGER}" || {
    echo 'FAIL desktop staging: the M11 fixture is not in the dev overlay' >&2
    exit 1
}
if grep -Fq "\"\${extra}/usr/share/punar/fixtures/webapps/notes/" \
    "${DESKTOP_STAGER}"; then
    echo 'FAIL desktop staging: an M11 fixture entered the release tree' >&2
    exit 1
fi
echo 'ok   browser exercise fixtures are confined to the dev overlay'

CLEAN="${TEST_ROOT}/clean"
CASE="${TEST_ROOT}/case"
EXPECTED="${TEST_ROOT}/expected-enabled-units.txt"
mkdir -p "${CLEAN}/etc/greetd" "${CLEAN}/etc/sudoers.d" \
    "${CLEAN}/etc/xdg/hypr" \
    "${CLEAN}/usr/lib/systemd/system/multi-user.target.wants" \
    "${CLEAN}/usr/lib/systemd/system/sysinit.target.wants" \
    "${CLEAN}/etc/systemd/system/punard.service.wants" \
    "${CLEAN}/usr/lib/systemd/user/default.target.wants" \
    "${CLEAN}/usr/lib/punar" "${CLEAN}/usr/bin" \
    "${CLEAN}/usr/share/punar"
printf '%s\n' 'hl.config({ misc = { disable_hyprland_logo = true } })' \
    > "${CLEAN}/etc/xdg/hypr/hyprland.lua"
printf '%s\n' 'hl.config({ animations = { enabled = false } })' \
    > "${CLEAN}/etc/xdg/hypr/punar-greeter.lua"
printf '%s\n' \
    'root:!:20500:0:99999:7:::' \
    'daemon:*:20500:0:99999:7:::' > "${CLEAN}/etc/shadow"
printf '%s\n' \
    'root:x:0:0:root:/root:/bin/sh' \
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' \
    > "${CLEAN}/etc/passwd"
printf '%s\n' \
    'ID=punar-test-substrate' \
    'VERSION_ID=1' \
    'IMAGE_ID=punar-desktop' \
    'IMAGE_VERSION=2026.08.20.1' \
    'PUNAR_SNAPSHOT_PIN=20260820T000000Z' \
    > "${CLEAN}/usr/lib/os-release"
cp "${CLEAN}/usr/lib/os-release" "${CLEAN}/etc/os-release"
printf '%s\n' \
    '[default_session]' \
    'command = "agreety --cmd /usr/lib/punar/session.sh"' \
    'user = "greeter"' > "${CLEAN}/etc/greetd/config.toml"
printf '%s\n' '[Unit]' 'Description=Punar product service' \
    > "${CLEAN}/usr/lib/systemd/system/punard.service"
ln -s ../punard.service \
    "${CLEAN}/usr/lib/systemd/system/multi-user.target.wants/punard.service"
printf '%s\n' '[Unit]' 'Description=Punar product helper' \
    > "${CLEAN}/usr/lib/systemd/system/punar-helper.service"
ln -s /usr/lib/systemd/system/punar-helper.service \
    "${CLEAN}/etc/systemd/system/punard.service.wants/punar-helper.service"
printf '%s\n' '[Unit]' 'Description=Punar user product service' \
    > "${CLEAN}/usr/lib/systemd/user/punar-user.service"
ln -s ../punar-user.service \
    "${CLEAN}/usr/lib/systemd/user/default.target.wants/punar-user.service"
printf '%s\n' '[Unit]' 'Description=Harden shared memory' \
    > "${CLEAN}/usr/lib/systemd/system/punar-shm-hardening.service"
ln -s ../punar-shm-hardening.service \
    "${CLEAN}/usr/lib/systemd/system/sysinit.target.wants/punar-shm-hardening.service"
printf '%s\n' \
    'etc/systemd/system/punard.service.wants/punar-helper.service -> /usr/lib/systemd/system/punar-helper.service' \
    'usr/lib/systemd/user/default.target.wants/punar-user.service -> ../punar-user.service' \
    'usr/lib/systemd/system/multi-user.target.wants/punard.service -> ../punard.service' \
    'usr/lib/systemd/system/sysinit.target.wants/punar-shm-hardening.service -> ../punar-shm-hardening.service' \
    > "${EXPECTED}"

KERNEL='console=tty0 systemd.getty_auto=no root=PARTUUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea rw'

reset_case() {
    rm -rf "${CASE}"
    cp -R "${CLEAN}" "${CASE}"
}

expect_fail() {
    code=$1
    shift
    reset_case
    "$@"
    if "${CHECKER}" "${CASE}" desktop "${KERNEL}" "${EXPECTED}" \
        > "${TEST_ROOT}/stdout" 2> "${TEST_ROOT}/stderr"; then
        echo "FAIL ${code}: checker accepted the violating tree" >&2
        exit 1
    fi
    grep -q "release-image violation ${code}:" "${TEST_ROOT}/stderr" || {
        echo "FAIL ${code}: checker failed without the expected diagnosis" >&2
        cat "${TEST_ROOT}/stderr" >&2
        exit 1
    }
    echo "ok   ${code} rejects its fixture"
}

mutate_a1() { printf '%s\n' 'root::20500:0:99999:7:::' > "${CASE}/etc/shadow"; }
mutate_a0() {
    printf '%s\n' \
        'ID=punar-test-substrate' \
        'VERSION_ID=1' \
        'IMAGE_ID=punar-desktop' \
        'IMAGE_VERSION=latest' \
        'PUNAR_SNAPSHOT_PIN=20260820T000000Z' \
        > "${CASE}/usr/lib/os-release"
}
mutate_a2() { printf '%s\n' 'punar:x:1000:1000::/home/punar:/bin/sh' >> "${CASE}/etc/passwd"; }
mutate_a3() { printf '%s\n' 'punar:100000:65536' > "${CASE}/etc/subuid"; }
mutate_a4() { printf '%s\n' '[initial_session]' >> "${CASE}/etc/greetd/config.toml"; }
mutate_a5() { : > "${CASE}/usr/lib/punar/m10-check.sh"; }
mutate_a6() {
    ln -s ../punar-idle-ram.service \
        "${CASE}/usr/lib/systemd/system/multi-user.target.wants/innocent.service"
}
mutate_a7() { printf '%s\n' 'wheel ALL=(ALL) NOPASSWD: ALL' > "${CASE}/etc/sudoers.d/dev"; }
mutate_noop() { :; }
mutate_a9() {
    : > "${CASE}/usr/lib/systemd/user/surprise.service"
    ln -s ../surprise.service \
        "${CASE}/usr/lib/systemd/user/default.target.wants/surprise.service"
}
mutate_a10() {
    mv "${CASE}/etc/xdg/hypr/punar-greeter.lua" \
        "${CASE}/etc/xdg/hypr/punar-greeter.conf"
}
mutate_a11() {
    mkdir -p "${CASE}/var/lib/punar/agents"
    printf '%s\n' '{"session_id":"agt_fixture"}' \
        > "${CASE}/var/lib/punar/agents/registry.jsonl"
}

reset_case
"${CHECKER}" "${CASE}" desktop "${KERNEL}" "${EXPECTED}" \
    | grep -q PUNAR_RELEASE_IMAGE_POLICY_OK
echo 'ok   clean release fixture passes'

# Dev deliberately bypasses the release-only policy even with an invalid root.
"${CHECKER}" "${TEST_ROOT}/missing-root" dev 'console=ttyS0 punar.live=1' \
    "${TEST_ROOT}/missing-manifest" \
    | grep -q PUNAR_RELEASE_IMAGE_POLICY_SKIPPED
echo 'ok   dev profile bypass is explicit'

printf '%s\n' '{"KernelCommandLine":["console=tty0","console=ttyS0"]}' \
    > "${TEST_ROOT}/mkosi-config.json"
reset_case
mkdir -p "${CASE}/etc/systemd/system/network-online.target.wants"
ln -s /usr/lib/systemd/system/systemd-networkd-wait-online.service \
    "${CASE}/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service"
BUILDROOT="${CASE}" \
PROFILES='desktop dev' \
ARCHITECTURE=x86-64 \
SRCDIR="${REPO_ROOT}/os/images" \
MKOSI_CONFIG="${TEST_ROOT}/mkosi-config.json" \
PUNAR_IMAGE_ID=punar-desktop \
PUNAR_IMAGE_VERSION=2026.08.20.1 \
PUNAR_SNAPSHOT_PIN=20260820T000000Z \
    "${FINALIZE}" | grep -q PUNAR_RELEASE_IMAGE_POLICY_SKIPPED
[ ! -e "${CASE}/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service" ]
echo 'ok   mkosi finalize resolves image sources, removes wait-online, and preserves the dev bypass'

MINIMAL="${TEST_ROOT}/minimal-dev"
mkdir -p "${MINIMAL}/usr/lib"
printf '%s\n' 'ID=punar-test-substrate' > "${MINIMAL}/usr/lib/os-release"
mkdir -p "${MINIMAL}/etc"
cp "${MINIMAL}/usr/lib/os-release" "${MINIMAL}/etc/os-release"
PROFILES='dev' \
BUILDROOT="${MINIMAL}" \
ARCHITECTURE=x86-64 \
SRCDIR="${REPO_ROOT}/os/images" \
MKOSI_CONFIG="${TEST_ROOT}/mkosi-config.json" \
PUNAR_IMAGE_ID=punar-desktop \
PUNAR_IMAGE_VERSION=2026.08.20.1 \
PUNAR_SNAPSHOT_PIN=20260820T000000Z \
    "${FINALIZE}" | grep -q PUNAR_RELEASE_IMAGE_POLICY_SKIPPED
[ ! -e "${MINIMAL}/usr/lib/systemd/system/sysinit.target.wants/punar-shm-hardening.service" ]
echo 'ok   mkosi finalize leaves the minimal dev profile free of desktop mount policy'

expect_fail A0 mutate_a0
expect_fail A1 mutate_a1
expect_fail A2 mutate_a2
expect_fail A3 mutate_a3
expect_fail A4 mutate_a4
expect_fail A5 mutate_a5
expect_fail A6 mutate_a6
expect_fail A7 mutate_a7

reset_case
if "${CHECKER}" "${CASE}" desktop "${KERNEL} console=ttyS0" "${EXPECTED}" \
    > "${TEST_ROOT}/stdout" 2> "${TEST_ROOT}/stderr"; then
    echo 'FAIL A8: serial console was accepted' >&2
    exit 1
fi
grep -q 'release-image violation A8:' "${TEST_ROOT}/stderr"
echo 'ok   A8 rejects a release serial console'

reset_case
if "${CHECKER}" "${CASE}" desktop \
    'console=tty0 root=PARTUUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea rw' \
    "${EXPECTED}" > "${TEST_ROOT}/stdout" 2> "${TEST_ROOT}/stderr"; then
    echo 'FAIL A8: automatic firmware getty generation was accepted' >&2
    exit 1
fi
grep -q 'release-image violation A8:' "${TEST_ROOT}/stderr"
echo 'ok   A8 rejects automatic firmware serial gettys'

reset_case
if "${CHECKER}" "${CASE}" desktop "${KERNEL} punar.live=1" "${EXPECTED}" \
    > "${TEST_ROOT}/stdout" 2> "${TEST_ROOT}/stderr"; then
    echo 'FAIL A8: live mode outside installer was accepted' >&2
    exit 1
fi
grep -q 'release-image violation A8:' "${TEST_ROOT}/stderr"
"${CHECKER}" "${CASE}" 'desktop,installer' "${KERNEL} punar.live=1" \
    "${EXPECTED}" | grep -q PUNAR_RELEASE_IMAGE_POLICY_OK
echo 'ok   A8 scopes live mode to the installer profile'

expect_fail A9 mutate_a9
expect_fail A10 mutate_a10
expect_fail A11 mutate_a11

echo PUNAR_RELEASE_IMAGE_POLICY_TEST_OK
