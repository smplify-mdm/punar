#!/usr/bin/env bash
# Contract for the step that frees the unpacked initramfs before switch-root
# (os/images/initrd-common; PERFORMANCE_BUDGETS.md, "Unpacked initramfs").
#
# On Linux 7.0 to 7.2 the unpacked initramfs stays resident as Unevictable
# memory for the whole boot. punar-release-initramfs.service deletes it, less
# what the switch-root call still executes, as the last step in the initrd. A
# mistake here either wastes that memory silently or deletes a file the boot
# still needs, so this pins:
#   - the unit is in the member every lane's mkosi.finalize appends to the
#     default initrd, and is pulled in by initrd-switch-root.target;
#   - its ordering: after initrd-cleanup.service, before
#     initrd-switch-root.service;
#   - it cannot run outside the initrd (ConditionPathExists=/etc/initrd-release,
#     and the helper's own checks refuse outside one);
#   - the keep set: the helper, run against fake initramfs trees with a fake
#     dynamic loader, keeps systemctl, systemd, systemd-executor, whatever
#     initrd-switch-root.service runs, each one's libraries and every symlink
#     on those paths, deletes everything else, never touches /sysroot, /run,
#     /dev, /proc or /sys, and keeps everything when anything is unresolved.
#
# Needs bash 4.4+, GNU find and cpio (the CI runners have them). Deletes
# nothing outside its own temporary directory: the helper runs only in its
# --dry-run and --check modes here.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGES="${REPO_ROOT}/os/images"
TREE="${IMAGES}/initrd-common"
HELPER="${TREE}/usr/lib/punar/release-initramfs"
UNIT="${TREE}/usr/lib/systemd/system/punar-release-initramfs.service"
WANTS="${TREE}/usr/lib/systemd/system/initrd-switch-root.target.d/50-punar-release-initramfs.conf"
FINALIZER="${IMAGES}/mkosi.finalize"
BUILDER="${IMAGES}/scripts/build-installer-initrd.sh"

fail() {
    echo "initramfs-release-contract-test: FAIL: $*" >&2
    exit 1
}

assert_line() {
    grep -Fqx -- "$2" "$1" || fail "${1#"${REPO_ROOT}/"} is missing: $2"
}

# --- The unit and how it is pulled in ---------------------------------------
for file in "${HELPER}" "${UNIT}" "${WANTS}" "${FINALIZER}" "${BUILDER}"; do
    [ -f "${file}" ] || fail "missing ${file#"${REPO_ROOT}/"}"
done
[ -x "${HELPER}" ] || fail 'the release helper is not executable'

assert_line "${UNIT}" 'DefaultDependencies=no'
assert_line "${UNIT}" 'ConditionPathExists=/etc/initrd-release'
assert_line "${UNIT}" 'Before=initrd-switch-root.service'
assert_line "${UNIT}" 'Type=oneshot'
assert_line "${UNIT}" 'ExecStart=-/usr/lib/punar/release-initramfs'
assert_line "${UNIT}" 'PrivateMounts=yes'
assert_line "${UNIT}" 'StandardOutput=kmsg'
# journald forwards only notice and above to the kernel log.
assert_line "${UNIT}" 'SyslogLevel=notice'
# systemd ignores an output setting it cannot parse (journal+kmsg once slipped
# through this way), so pin each one to a value systemd.exec(5) documents.
while IFS= read -r setting; do
    case "${setting#*=}" in
        inherit|null|tty|journal|kmsg|journal+console|kmsg+console|socket|file:/*|append:/*|truncate:/*|fd:*) ;;
        *) fail "the unit has an output setting systemd does not accept: ${setting}" ;;
    esac
done < <(grep -E '^Standard(Output|Error)=' "${UNIT}")
after_line="$(grep -E '^After=' "${UNIT}")" || fail 'the unit has no After= line'
for unit in initrd-cleanup.service initrd-switch-root.target initrd-udevadm-cleanup-db.service; do
    case " ${after_line#After=} " in
        *" ${unit} "*) ;;
        *) fail "the unit is not ordered after ${unit}" ;;
    esac
done
if grep -Eq '^(After|Wants|Requires|BindsTo)=.*initrd-switch-root\.service' "${UNIT}"; then
    fail 'the unit waits for the switch-root it must precede'
fi
if grep -Eq '^\[Install\]' "${UNIT}"; then
    fail 'the unit has an [Install] section; the initrd pulls it in by drop-in'
fi
assert_line "${WANTS}" 'Wants=punar-release-initramfs.service'

# --- Every lane appends the member to its default initrd --------------------
publish_line="$(grep -n 'io.mkosi.initrd/50-punar-release-initramfs.initrd' "${FINALIZER}" \
    | cut -d: -f1 | head -n 1 || true)"
[ -n "${publish_line}" ] || fail 'mkosi.finalize does not publish the release member'
# shellcheck disable=SC2016 # the literal source line
grep -Fq 'COMMON_INITRD_SOURCE="${CHECKER_DIR}/initrd-common"' "${FINALIZER}" \
    || fail 'mkosi.finalize does not build the member from os/images/initrd-common'
installer_start="$(grep -n "\*' installer '\*)" "${FINALIZER}" | cut -d: -f1 | head -n 1 || true)"
[ -n "${installer_start}" ] || fail 'cannot find the installer branch of mkosi.finalize'
[ "${publish_line}" -lt "${installer_start}" ] \
    || fail 'the release member is published only for the installer profile'
# The Arch lane discovers os/images/mkosi.finalize beside its mkosi.conf; the
# Debian lanes name it.
[ -f "${IMAGES}/mkosi.conf" ] || fail 'the Arch lane configuration moved'
for config in "${IMAGES}/arm64/mkosi.conf" "${IMAGES}/amd64-debian/mkosi.conf"; do
    assert_line "${config}" 'FinalizeScripts=../mkosi.finalize'
done
# find(1) is the one tool the helper needs beyond bash, mount and systemd.
for config in "${IMAGES}/mkosi.conf" "${IMAGES}/arm64/mkosi.conf" "${IMAGES}/amd64-debian/mkosi.conf"; do
    # A list setting continues on the following indented lines.
    awk '
        function check(value,    n, i, parts) {
            n = split(value, parts, /[[:space:],]+/)
            for (i = 1; i <= n; i++) if (parts[i] == "findutils") found = 1
        }
        /^InitrdPackages=/ { in_list = 1; check(substr($0, 16)); next }
        in_list && /^[[:space:]]+[^[:space:]#]/ { check($0); next }
        { in_list = 0 }
        END { exit !found }
    ' "${config}" || fail "${config#"${REPO_ROOT}/"} does not declare findutils in InitrdPackages="
done

command -v cpio >/dev/null || fail 'cpio is required to build the member'
# shellcheck disable=SC2185 # asks for the version only
find_version="$(find --version 2>/dev/null || true)"
grep -q 'GNU findutils' <<< "${find_version}" \
    || fail 'GNU find is required (the helper uses -printf)'
[ "${BASH_VERSINFO[0]}" -gt 4 ] \
    || { [ "${BASH_VERSINFO[0]}" -eq 4 ] && [ "${BASH_VERSINFO[1]}" -ge 4 ]; } \
    || fail 'bash 4.4 or later is required'

WORK="$(mktemp -d "${TMPDIR:-/tmp}/initramfs-release-test.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

# --- The built member carries the unit, the drop-in and the helper ----------
"${BUILDER}" "${TREE}" "${WORK}/member.initrd"
listing="$(cpio -itv --quiet < "${WORK}/member.initrd")"
member_has() {
    # member_has MODE PATH
    awk -v mode="$1" -v path="$2" '$1 == mode && $NF == path { found = 1 } END { exit !found }' \
        <<< "${listing}" || fail "the built member lacks $1 $2"
}
member_has -rwxr-xr-x usr/lib/punar/release-initramfs
member_has -rw-r--r-- usr/lib/systemd/system/punar-release-initramfs.service
member_has -rw-r--r-- usr/lib/systemd/system/initrd-switch-root.target.d/50-punar-release-initramfs.conf
member_has drwxr-xr-x .
if awk '$2 !~ /^[0-9]+$/ || $3 != "root" || $4 != "root" { bad = 1 } END { exit !bad }' \
        <<< "${listing}"; then
    fail 'the built member has an entry not owned by root:root'
fi
"${BUILDER}" "${TREE}" "${WORK}/member-again.initrd"
cmp -s "${WORK}/member.initrd" "${WORK}/member-again.initrd" \
    || fail 'the member is not reproducible'

# --- Fake initramfs trees ------------------------------------------------------
mkfile() {
    mkdir -p "$(dirname "$1")"
    printf '%s\n' "${2:-content of $1}" > "$1"
}
mkexe() {
    mkfile "$1" "$2"
    chmod 0755 "$1"
}
mklink() {
    # mklink TARGET LINK
    mkdir -p "$(dirname "$2")"
    ln -s "$1" "$2"
}

# As systemd 261 reports upstream initrd-switch-root.service: the unit says
# "systemctl", and systemd looks it up on its search path when it runs it.
SHOW_SWITCH_ROOT='
{ path=systemctl ; argv[]=systemctl --no-block switch-root ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
'

# A fake systemctl whose "show" prints $1. Like the real one, it answers
# nothing when it believes it runs in a chroot, which from a unit with its own
# mount namespace it does unless SYSTEMD_IGNORE_CHROOT is set.
fake_systemctl() {
    # shellcheck disable=SC2016 # the lines of the fake script, verbatim
    printf '%s\n' '#!/bin/sh' \
        '[ "$1" = show ] || exit 1' \
        '[ "${SYSTEMD_IGNORE_CHROOT:-}" = 1 ] || { echo "Running in chroot, ignoring command '"'"'show'"'"'" >&2; exit 0; }' \
        "printf '%s' '$1'"
}

# A Debian arm64 initrd, laid out as measured on the release image.
make_debian_tree() {
    local t=$1 systemctl_libs=$2
    local gnu=usr/lib/aarch64-linux-gnu
    mklink usr/bin "${t}/bin"
    mklink usr/lib "${t}/lib"
    mklink usr/sbin "${t}/sbin"
    mklink /usr/lib/systemd/systemd "${t}/init"
    mkfile "${t}/etc/os-release" 'ID=debian'
    mklink /etc/os-release "${t}/etc/initrd-release"
    mkfile "${t}/usr/lib/os-release" 'ID=debian'
    mkfile "${t}/etc/ld.so.cache"
    mklink aarch64-linux-gnu/ld-linux-aarch64.so.1 "${t}/usr/lib/ld-linux-aarch64.so.1"
    for lib in libc.so.6 libm.so.6 libtinfo.so.6 libx.so 'lib[x].so' libz.so.1.3 \
        systemd/libsystemd-shared-261.so systemd/libsystemd-core-261.so gconv/UTF-16.so; do
        mkfile "${t}/${gnu}/${lib}"
    done
    mklink libz.so.1.3 "${t}/${gnu}/libz.so.1"
    mkexe "${t}/usr/lib/systemd/systemd" '#!/bin/sh'
    mkexe "${t}/usr/lib/systemd/systemd-executor" '#!/bin/sh'
    mkexe "${t}/usr/bin/bash" '#!/bin/sh'
    mkexe "${t}/usr/bin/find" '#!/bin/sh'
    mklink bash "${t}/usr/bin/sh"
    mkfile "${t}/usr/lib/modules/7.1.12+deb14-arm64/kernel/fs/btrfs/btrfs.ko.xz"
    mkfile "${t}/usr/share/doc/perl/copyright"
    mkfile "${t}/usr/lib/systemd/system/initrd-switch-root.service"
    # Mount points in the real initrd: never to be touched.
    mkexe "${t}/sysroot/usr/lib/systemd/systemd" '#!/bin/sh'
    mkfile "${t}/sysroot/etc/os-release"
    mkfile "${t}/run/systemd/journal/socket-stand-in"
    mkfile "${t}/dev/console-stand-in"
    mkfile "${t}/proc/cmdline"
    mkfile "${t}/sys/kernel/stand-in"

    local vdso=$'\tlinux-vdso.so.1 (0x0000ffffb478c000)'
    local core=$'\tlibm.so.6 => /usr/lib/aarch64-linux-gnu/libm.so.6 (0x0000ffff98810000)\n\tlibsystemd-core-261.so => /usr/lib/aarch64-linux-gnu/systemd/libsystemd-core-261.so (0x0000ffff98550000)\n\tlibsystemd-shared-261.so => /usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-261.so (0x0000ffff97fb0000)\n\tlibc.so.6 => /usr/lib/aarch64-linux-gnu/libc.so.6 (0x0000ffff97df0000)\n\t/lib/ld-linux-aarch64.so.1 (0x0000ffff98930000)'
    mkexe "${t}/${gnu}/ld-linux-aarch64.so.1" "#!/bin/sh
[ \"\$1\" = --list ] || exit 1
case \$2 in
    */usr/lib/systemd/systemd|*/usr/lib/systemd/systemd-executor)
        printf '%s\n' '${vdso}' '${core}' ;;
    */usr/bin/systemctl)
        printf '%s\n' '${vdso}' '${systemctl_libs}' ;;
    *) echo \"\$2: not a dynamic executable\" >&2; exit 1 ;;
esac"
    mkexe "${t}/usr/bin/systemctl" "$(fake_systemctl "${SHOW_SWITCH_ROOT}")"
}

DEBIAN_SYSTEMCTL_LIBS=$'\tlibm.so.6 => /usr/lib/aarch64-linux-gnu/libm.so.6 (0x0000ffffb4610000)\n\tlibsystemd-shared-261.so => /usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-261.so (0x0000ffffb4070000)\n\tlibc.so.6 => /usr/lib/aarch64-linux-gnu/libc.so.6 (0x0000ffffb3eb0000)\n\tlib[x].so => /usr/lib/aarch64-linux-gnu/lib[x].so (0x0000ffffb3e00000)\n\t/lib/ld-linux-aarch64.so.1 (0x0000ffffb4750000)'

# An Arch x86_64 initrd, with a drop-in that gives initrd-switch-root.service
# an ExecStartPre= of its own.
make_arch_tree() {
    local t=$1
    mklink usr/bin "${t}/bin"
    mklink usr/lib "${t}/lib"
    mklink usr/lib "${t}/lib64"
    mklink usr/bin "${t}/sbin"
    mklink lib "${t}/usr/lib64"
    mklink bin "${t}/usr/sbin"
    mklink usr/lib/systemd/systemd "${t}/init"
    mkfile "${t}/etc/initrd-release" 'ID=arch'
    mkfile "${t}/usr/lib/os-release" 'ID=arch'
    mklink ../usr/lib/os-release "${t}/etc/os-release"
    mkfile "${t}/etc/ld.so.cache"
    for lib in libc.so.6 libm.so.6 libcap.so.2.77 libply.so.5 libreadline.so.8 \
        systemd/libsystemd-shared-261.so systemd/libsystemd-core-261.so; do
        mkfile "${t}/usr/lib/${lib}"
    done
    mklink libcap.so.2.77 "${t}/usr/lib/libcap.so.2"
    mkexe "${t}/usr/lib/systemd/systemd" '#!/bin/sh'
    mkexe "${t}/usr/lib/systemd/systemd-executor" '#!/bin/sh'
    mkexe "${t}/usr/bin/plymouth" '#!/bin/sh'
    mkexe "${t}/usr/bin/bash" '#!/bin/sh'
    mkexe "${t}/usr/bin/mount" '#!/bin/sh'
    mkfile "${t}/usr/lib/firmware/regulatory.db"
    mkexe "${t}/sysroot/usr/lib/systemd/systemd" '#!/bin/sh'
    mkfile "${t}/sysroot/usr/lib/os-release"
    mkfile "${t}/run/stand-in"

    local vdso=$'\tlinux-vdso.so.1 (0x00007ffd4a5f2000)'
    local interp=$'\t/lib64/ld-linux-x86-64.so.2 => /usr/lib64/ld-linux-x86-64.so.2 (0x00007f0a1c9d2000)'
    local core=$'\tlibsystemd-core-261.so => /usr/lib/systemd/libsystemd-core-261.so (0x00007f0a1c400000)\n\tlibsystemd-shared-261.so => /usr/lib/systemd/libsystemd-shared-261.so (0x00007f0a1c000000)\n\tlibcap.so.2 => /usr/lib/libcap.so.2 (0x00007f0a1bf00000)\n\tlibm.so.6 => /usr/lib/libm.so.6 (0x00007f0a1be00000)\n\tlibc.so.6 => /usr/lib/libc.so.6 (0x00007f0a1bc00000)'
    local systemctl=$'\tlibsystemd-shared-261.so => /usr/lib/systemd/libsystemd-shared-261.so (0x00007f0a1c000000)\n\tlibc.so.6 => /usr/lib/libc.so.6 (0x00007f0a1bc00000)'
    local plymouth=$'\tlibply.so.5 => /usr/lib/libply.so.5 (0x00007f0a1b000000)\n\tlibc.so.6 => /usr/lib/libc.so.6 (0x00007f0a1bc00000)'
    mkexe "${t}/usr/lib/ld-linux-x86-64.so.2" "#!/bin/sh
[ \"\$1\" = --list ] || exit 1
case \$2 in
    */usr/lib/systemd/systemd|*/usr/lib/systemd/systemd-executor)
        printf '%s\n' '${vdso}' '${core}' '${interp}' ;;
    */usr/bin/systemctl) printf '%s\n' '${vdso}' '${systemctl}' '${interp}' ;;
    */usr/bin/plymouth) printf '%s\n' '${vdso}' '${plymouth}' '${interp}' ;;
    *) echo \"\$2: not a dynamic executable\" >&2; exit 1 ;;
esac"
    local show='
{ path=/usr/bin/plymouth ; argv[]=/usr/bin/plymouth update-root-fs --new-root-dir=/sysroot ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
{ path=systemctl ; argv[]=systemctl --no-block switch-root ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
'
    mkexe "${t}/usr/bin/systemctl" "$(fake_systemctl "${show}")"
}

# Every regular file and symlink of a tree outside the mount points, as
# tree-relative paths: the oracle for "deletes everything else".
all_candidates() {
    (cd "$1" && find . \( -type f -o -type l \) -printf '/%P\n') \
        | grep -Ev '^/(sysroot|proc|sys|dev|run)(/|$)' | LC_ALL=C sort
}

snapshot() {
    (cd "$1" && find . -printf '%y %m %s %p %l\n' | LC_ALL=C sort)
}

run_dry() {
    # run_dry TREE -> helper output
    "${HELPER}" --dry-run --root "$1"
}

check_tree() {
    # check_tree NAME TREE EXPECTED_KEEP...
    local name=$1 tree=$2 output before after
    shift 2
    before="$(snapshot "${tree}")"
    output="$(run_dry "${tree}")"
    after="$(snapshot "${tree}")"
    [ "${before}" = "${after}" ] || fail "${name}: a dry run changed the tree"
    if grep -q '^keeping the initramfs' <<< "${output}"; then
        printf '%s\n' "${output}" >&2
        fail "${name}: the helper refused a well-formed tree"
    fi
    local expected_keep actual_keep expected_delete actual_delete
    expected_keep="$(printf '%s\n' "$@" | LC_ALL=C sort)"
    actual_keep="$(sed -n 's/^keep //p' <<< "${output}" | LC_ALL=C sort)"
    if [ "${expected_keep}" != "${actual_keep}" ]; then
        diff <(printf '%s\n' "${expected_keep}") <(printf '%s\n' "${actual_keep}") >&2 || true
        fail "${name}: the keep set differs (< expected, > kept)"
    fi
    expected_delete="$(all_candidates "${tree}" | grep -Fxv -f <(printf '%s\n' "$@") || true)"
    actual_delete="$(sed -n 's/^delete //p' <<< "${output}" | LC_ALL=C sort)"
    if [ "${expected_delete}" != "${actual_delete}" ]; then
        diff <(printf '%s\n' "${expected_delete}") <(printf '%s\n' "${actual_delete}") >&2 || true
        fail "${name}: the delete set differs (< expected, > would delete)"
    fi
    if grep -Eq '^delete /(sysroot|proc|sys|dev|run)(/|$)' <<< "${output}"; then
        fail "${name}: the helper would delete below a mount point"
    fi
    grep -Eq '^dry run: would delete [0-9]+ files \([0-9]+ bytes\) and [0-9]+ symlinks, keep [0-9]+ paths \([0-9]+ bytes\)$' \
        <<< "${output}" || fail "${name}: no summary line"
}

check_refusal() {
    # check_refusal NAME TREE REASON-FRAGMENT
    local output
    output="$(run_dry "$2")"
    grep -Fq "keeping the initramfs: " <<< "${output}" \
        || fail "$1: the helper did not refuse"
    grep -Fq -- "$3" <<< "${output}" \
        || { printf '%s\n' "${output}" >&2; fail "$1: the refusal does not name: $3"; }
    if grep -q '^delete ' <<< "${output}"; then
        fail "$1: the helper listed deletions although it refused"
    fi
}

DEBIAN_KEEP=(
    /etc/initrd-release
    /etc/ld.so.cache
    /etc/os-release
    /init
    /lib
    /usr/bin/systemctl
    /usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1
    /usr/lib/aarch64-linux-gnu/libc.so.6
    /usr/lib/aarch64-linux-gnu/libm.so.6
    '/usr/lib/aarch64-linux-gnu/lib[x].so'
    /usr/lib/aarch64-linux-gnu/systemd/libsystemd-core-261.so
    /usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-261.so
    /usr/lib/ld-linux-aarch64.so.1
    /usr/lib/os-release
    /usr/lib/systemd/systemd
    /usr/lib/systemd/systemd-executor
)
make_debian_tree "${WORK}/debian" "${DEBIAN_SYSTEMCTL_LIBS}"
check_tree 'Debian arm64' "${WORK}/debian" "${DEBIAN_KEEP[@]}"
# A glob character in a kept name must not keep its look-alike.
debian_output="$(run_dry "${WORK}/debian")"
grep -Fqx 'delete /usr/lib/aarch64-linux-gnu/libx.so' <<< "${debian_output}" \
    || fail 'a kept name with a glob character also kept its look-alike'

ARCH_KEEP=(
    /etc/initrd-release
    /etc/ld.so.cache
    /etc/os-release
    /init
    /lib64
    /usr/bin/plymouth
    /usr/bin/systemctl
    /usr/lib/ld-linux-x86-64.so.2
    /usr/lib/libc.so.6
    /usr/lib/libcap.so.2
    /usr/lib/libcap.so.2.77
    /usr/lib/libm.so.6
    /usr/lib/libply.so.5
    /usr/lib/os-release
    /usr/lib/systemd/libsystemd-core-261.so
    /usr/lib/systemd/libsystemd-shared-261.so
    /usr/lib/systemd/systemd
    /usr/lib/systemd/systemd-executor
    /usr/lib64
    /usr/sbin
)
make_arch_tree "${WORK}/arch"
check_tree 'Arch x86_64 with an ExecStartPre= drop-in' "${WORK}/arch" "${ARCH_KEEP[@]}"

# --- Anything unresolved keeps everything ------------------------------------
make_debian_tree "${WORK}/missing-lib" \
    $'\tlibsystemd-shared-261.so => not found\n\tlibc.so.6 => /usr/lib/aarch64-linux-gnu/libc.so.6 (0x0000ffffb3eb0000)'
check_refusal 'a library the loader cannot find' "${WORK}/missing-lib" \
    'needs libsystemd-shared-261.so, which the dynamic loader cannot find'

make_debian_tree "${WORK}/dangling-lib" \
    $'\tlibgone.so.1 => /usr/lib/aarch64-linux-gnu/libgone.so.1 (0x0000ffffb3eb0000)'
check_refusal 'a listed library that does not exist' "${WORK}/dangling-lib" \
    'cannot resolve /usr/lib/aarch64-linux-gnu/libgone.so.1'

make_debian_tree "${WORK}/no-executor" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/no-executor/usr/lib/systemd/systemd-executor"
check_refusal 'no systemd-executor' "${WORK}/no-executor" \
    'cannot resolve /usr/lib/systemd/systemd-executor'

make_debian_tree "${WORK}/link-loop" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/link-loop/usr/bin/systemctl"
mklink systemctl.loop "${WORK}/link-loop/usr/bin/systemctl"
mklink systemctl "${WORK}/link-loop/usr/bin/systemctl.loop"
check_refusal 'a symlink loop' "${WORK}/link-loop" 'cannot resolve /usr/bin/systemctl'

make_debian_tree "${WORK}/unknown-command" "${DEBIAN_SYSTEMCTL_LIBS}"
mkexe "${WORK}/unknown-command/usr/bin/systemctl" "$(fake_systemctl '
{ path=frobnicate ; argv[]=frobnicate --now ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
')"
check_refusal 'a switch-root command on no search path directory' "${WORK}/unknown-command" \
    'cannot find frobnicate on the service search path'

make_debian_tree "${WORK}/no-loader" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/no-loader/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
check_refusal 'no dynamic loader' "${WORK}/no-loader" 'no dynamic loader'

# Without a PID 1 to report initrd-switch-root.service's commands (systemctl
# failing, or answering nothing as it does in a chroot), only a dry run may
# fall back to the fixed set; the boot step refuses.
for variant in 'exit 1' 'printf "\n\n\n"'; do
    rm -rf "${WORK}/no-pid1"
    make_debian_tree "${WORK}/no-pid1" "${DEBIAN_SYSTEMCTL_LIBS}"
    mkexe "${WORK}/no-pid1/usr/bin/systemctl" "#!/bin/sh
${variant}"
    no_pid1_output="$(run_dry "${WORK}/no-pid1")"
    grep -Fq 'dry run: no PID 1 reported' <<< "${no_pid1_output}" \
        || fail "a dry run without PID 1 (${variant}) did not say it used the fixed set"
    check_tree "the fixed set alone (${variant})" "${WORK}/no-pid1" "${DEBIAN_KEEP[@]}"
done
grep -Fq '|| keep_nothing "PID 1 reported no command for initrd-switch-root.service' "${HELPER}" \
    || fail 'the boot step does not refuse when PID 1 reports no switch-root command'

# --- Never through a mount boundary -----------------------------------------
# The boot step reads the real mount table: another file system below / is
# skipped (-xdev) and excluded, and so is any bind that is not the initramfs
# bound onto its own path. PID 1's read-only /usr is such a self-bind and must
# still be released. Reproduced with real mounts where an unprivileged user
# and mount namespace is available.
if unshare --user --map-root-user --mount true 2>/dev/null; then
    make_debian_tree "${WORK}/mounts-source" "${DEBIAN_SYSTEMCTL_LIBS}"
    mkfile "${WORK}/mounts-source/usr/share/misc/magic"
    mkdir -p "${WORK}/mounts" "${WORK}/mounts-source/srv/share" \
        "${WORK}/mounts-source/usr/lib/extra-fs"
    # shellcheck disable=SC2016 # expanded by the inner shell
    mounts_output="$(unshare --user --map-root-user --mount bash -euc '
        tree=$1 source=$2 helper=$3
        mount -t tmpfs -o mode=0755 tmpfs "${tree}"
        cp -a "${source}/." "${tree}/"
        mount --bind "${tree}/usr" "${tree}/usr"
        mount -o remount,bind,ro "${tree}/usr"
        mount --bind "${tree}/usr/share" "${tree}/srv/share"
        mount -t tmpfs tmpfs "${tree}/usr/lib/extra-fs"
        printf "other file system\n" > "${tree}/usr/lib/extra-fs/on-another-fs"
        "${helper}" --dry-run --root "${tree}"
    ' bash "${WORK}/mounts" "${WORK}/mounts-source" "${HELPER}")"
    grep -Fqx 'delete /usr/share/misc/magic' <<< "${mounts_output}" \
        || fail 'a file below the self-bound /usr was not released'
    grep -Fqx 'delete /usr/bin/bash' <<< "${mounts_output}" \
        || fail 'the self-bound /usr was treated as a mount boundary'
    if grep -Eq '^delete /srv/share(/|$)' <<< "${mounts_output}"; then
        fail 'the helper would delete through a bind mount'
    fi
    if grep -Eq '^delete /usr/lib/extra-fs(/|$)' <<< "${mounts_output}"; then
        fail 'the helper would delete on another file system'
    fi
else
    echo 'initramfs-release-contract-test: note: no unprivileged user namespace; skipping the real-mount check'
fi

# --- The boot step's delete actions report every unlink ----------------------
# A dry run cannot delete, so run the helper's own DELETE_ACTIONS through GNU
# find on a throwaway tree: one "D" line per entry, read before the unlink,
# no error, status 0 and nothing left. (Printing after -delete once made find
# report every entry as missing.)
actions_line="$(grep -E '^DELETE_ACTIONS=\(' "${HELPER}")" \
    || fail 'the helper has no DELETE_ACTIONS'
eval "${actions_line}"
make_debian_tree "${WORK}/delete" "${DEBIAN_SYSTEMCTL_LIBS}"
mkdir -p "${WORK}/delete/usr/share/twice"
mkfile "${WORK}/delete/usr/share/twice/one" 'shared content'
ln "${WORK}/delete/usr/share/twice/one" "${WORK}/delete/usr/share/twice/two"
entries="$(find "${WORK}/delete" -mindepth 1 \( -type f -o -type l \) | wc -l)"
status=0
delete_output="$(find "${WORK}/delete" -mindepth 1 \( -type f -o -type l \) \
    "${DELETE_ACTIONS[@]}" 2>&1)" || status=$?
[ "${status}" -eq 0 ] || fail "the delete actions exited ${status}: $(head -n 1 <<< "${delete_output}")"
if grep -v '^D [fl] [0-9]* [0-9]*$' <<< "${delete_output}" | grep -q .; then
    fail "the delete actions printed something else: $(grep -v '^D ' <<< "${delete_output}" | head -n 1)"
fi
[ "$(grep -c '^D ' <<< "${delete_output}")" -eq "${entries}" ] \
    || fail 'the delete actions did not report every entry'
[ -z "$(find "${WORK}/delete" \( -type f -o -type l \) -print -quit)" ] \
    || fail 'the delete actions left an entry behind'
# Only the last name of a hard-linked file frees it: exactly one of the two
# names is reported with a link count of 1.
[ "$(grep -c '^D f 15 1$' <<< "${delete_output}")" -eq 1 ] \
    && [ "$(grep -c '^D f 15 2$' <<< "${delete_output}")" -eq 1 ] \
    || fail 'the link counts do not show which name frees a hard-linked file'

# --- It cannot run outside the initrd ------------------------------------------
if [ -e /etc/initrd-release ]; then
    echo 'initramfs-release-contract-test: note: this host has /etc/initrd-release; skipping the outside-the-initrd check'
else
    check_output="$("${HELPER}" --check)"
    [ "${check_output}" = 'keeping the initramfs: not in the initrd: /etc/initrd-release does not exist' ] \
        || fail "--check outside the initrd did not refuse: ${check_output}"
fi
status=0
"${HELPER}" --root "${WORK}/debian" >/dev/null 2>&1 || status=$?
[ "${status}" -eq 2 ] || fail '--root without --dry-run was not rejected'
status=0
"${HELPER}" --dry-run --root relative/path >/dev/null 2>&1 || status=$?
[ "${status}" -eq 2 ] || fail 'a relative --root was not rejected'

echo 'PUNAR_INITRAMFS_RELEASE_CONTRACT_OK'
