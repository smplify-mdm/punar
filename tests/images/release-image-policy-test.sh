#!/bin/sh
# Fixture proof for every release-image assertion. No image build or root
# privilege is required, so a denylist regression fails in seconds.
set -eu

REPO_ROOT=$(cd -- "$(dirname "$0")/../.." && pwd)
CHECKER="${REPO_ROOT}/tools/check-release-image.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/punar-release-policy.XXXXXX")
trap 'rm -rf "${TEST_ROOT}"' EXIT INT TERM

CLEAN="${TEST_ROOT}/clean"
CASE="${TEST_ROOT}/case"
EXPECTED="${TEST_ROOT}/expected-enabled-units.txt"
mkdir -p "${CLEAN}/etc/greetd" "${CLEAN}/etc/sudoers.d" \
    "${CLEAN}/usr/lib/systemd/system/multi-user.target.wants" \
    "${CLEAN}/usr/lib/punar" "${CLEAN}/usr/bin" \
    "${CLEAN}/usr/share/punar"
printf '%s\n' \
    'root:!:20500:0:99999:7:::' \
    'daemon:*:20500:0:99999:7:::' > "${CLEAN}/etc/shadow"
printf '%s\n' \
    'root:x:0:0:root:/root:/bin/sh' \
    'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin' \
    > "${CLEAN}/etc/passwd"
printf '%s\n' \
    '[default_session]' \
    'command = "agreety --cmd /usr/lib/punar/session.sh"' \
    'user = "greeter"' > "${CLEAN}/etc/greetd/config.toml"
printf '%s\n' '[Unit]' 'Description=Punar product service' \
    > "${CLEAN}/usr/lib/systemd/system/punard.service"
ln -s ../punard.service \
    "${CLEAN}/usr/lib/systemd/system/multi-user.target.wants/punard.service"
printf '%s\n' \
    'usr/lib/systemd/system/multi-user.target.wants/punard.service -> ../punard.service' \
    > "${EXPECTED}"

KERNEL='console=tty0 root=PARTUUID=1beabfe0-9cb8-4b49-91ef-d372b845e7ea rw'

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
    : > "${CASE}/usr/lib/systemd/system/surprise.service"
    ln -s ../surprise.service \
        "${CASE}/usr/lib/systemd/system/multi-user.target.wants/surprise.service"
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

echo PUNAR_RELEASE_IMAGE_POLICY_TEST_OK
