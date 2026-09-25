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
#   - it waits for the TPM PCR barrier and the extension services to stop,
#     and for every other job of PID 1 to finish, before deleting;
#   - it acts only on Linux 7.0 to 7.2, and says "not needed" elsewhere;
#   - a failed switch-root still reboots unattended: the initrd drop-ins
#     (FailureAction=reboot-force, CrashAction=reboot) and systemd-shutdown in
#     the keep set;
#   - the keep set: the helper, run against fake initramfs trees with a fake
#     dynamic loader, keeps systemctl, systemd, systemd-executor,
#     systemd-shutdown, whatever initrd-switch-root.service runs, each one's
#     libraries and every symlink on those paths, deletes everything else,
#     never touches /sysroot, /run, /dev, /proc or /sys, and keeps everything
#     when anything is unresolved;
#   - --root never runs the tree's systemctl and is refused as real root;
#   - it refuses to remount in PID 1's mount namespace.
#
# Needs bash 4.4+, GNU find and cpio (the CI runners have them), and for the
# real-mount check an unprivileged user and mount namespace, which CI must
# provide (CI=true turns a missing one into a failure). Deletes nothing
# outside its own temporary directory: the helper runs only in its --dry-run
# and --check modes here, and single functions are sourced with fixtures.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGES="${REPO_ROOT}/os/images"
TREE="${IMAGES}/initrd-common"
HELPER="${TREE}/usr/lib/punar/release-initramfs"
UNIT="${TREE}/usr/lib/systemd/system/punar-release-initramfs.service"
WANTS="${TREE}/usr/lib/systemd/system/initrd-switch-root.target.d/50-punar-release-initramfs.conf"
REBOOT_DROPIN="${TREE}/usr/lib/systemd/system/initrd-switch-root.service.d/50-punar-reboot-on-failure.conf"
CRASH_CONF="${TREE}/usr/lib/systemd/system.conf.d/50-punar-initrd-crash-action.conf"
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
for file in "${HELPER}" "${UNIT}" "${WANTS}" "${REBOOT_DROPIN}" "${CRASH_CONF}" "${FINALIZER}" "${BUILDER}"; do
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
after_line="$(grep -E '^After=' "${UNIT}" | tr '\n' ' ')" || fail 'the unit has no After= line'
# The PCR barrier's ExecStop= extends leave-initrd with systemd-pcrextend,
# which the release deletes; the extension services unmerge with
# systemd-sysext. Their stops must be finished first.
for unit in initrd-cleanup.service initrd-switch-root.target initrd-udevadm-cleanup-db.service \
    systemd-pcrphase-initrd.service systemd-sysext-initrd.service systemd-confext-initrd.service; do
    case " ${after_line//After=/} " in
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
# Hardening that leaves the helper what it needs: CAP_SYS_PTRACE to read PID
# 1's mount namespace (with fewer capabilities than PID 1 it may not), and no
# ProtectKernelModules=, whose mount over /usr/lib/modules would keep the
# modules resident (the helper never deletes below a mount point).
assert_line "${UNIT}" 'NoNewPrivileges=yes'
assert_line "${UNIT}" 'CapabilityBoundingSet=CAP_SYS_ADMIN CAP_SYS_PTRACE CAP_DAC_OVERRIDE CAP_FOWNER'
assert_line "${UNIT}" 'RestrictAddressFamilies=AF_UNIX'
if grep -Eq '^(ProtectKernelModules|InaccessiblePaths|TemporaryFileSystem|BindPaths|BindReadOnlyPaths|ProtectSystem|ProtectHome)=' "${UNIT}"; then
    fail 'the unit mounts over part of the initramfs, which the helper then keeps'
fi

# A failed switch-root reboots rather than freezing, so boot counting can fall
# back with no one at the machine. Both files exist only in the initrd.
assert_line "${REBOOT_DROPIN}" '[Unit]'
assert_line "${REBOOT_DROPIN}" 'FailureAction=reboot-force'
assert_line "${CRASH_CONF}" '[Manager]'
assert_line "${CRASH_CONF}" 'CrashAction=reboot'
# shellcheck disable=SC2016 # the literal source line
grep -Fqx 'CRASH_ACTION_CONF=/usr/lib/systemd/system.conf.d/50-punar-initrd-crash-action.conf' "${HELPER}" \
    || fail 'the helper does not keep the initrd crash setting where it is shipped'

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
member_has -rw-r--r-- usr/lib/systemd/system/initrd-switch-root.service.d/50-punar-reboot-on-failure.conf
member_has -rw-r--r-- usr/lib/systemd/system.conf.d/50-punar-initrd-crash-action.conf
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

# What "systemctl show" prints for a tree's initrd-switch-root.service goes
# to the helper as --show FILE: a dry run of a --root tree executes nothing of
# that tree but its dynamic loader. show_file NAME TEXT -> path.
show_file() {
    printf '%s' "$2" > "${WORK}/$1.show"
    printf '%s' "${WORK}/$1.show"
}
SHOW_DEBIAN="$(show_file debian "${SHOW_SWITCH_ROOT}")"

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
    mkexe "${t}/usr/lib/systemd/systemd-shutdown" '#!/bin/sh'
    mkfile "${t}/usr/lib/systemd/system.conf.d/50-punar-initrd-crash-action.conf"
    mkfile "${t}/usr/lib/systemd/system.conf.d/40-other.conf"
    mkexe "${t}/usr/bin/bash" '#!/bin/sh'
    mkexe "${t}/usr/bin/find" '#!/bin/sh'
    mkexe "${t}/usr/sbin/sulogin" '#!/bin/sh'
    mkexe "${t}/usr/lib/systemd/systemd-sulogin-shell" '#!/bin/sh'
    mkexe "${t}/usr/lib/systemd/systemd-pcrextend" '#!/bin/sh'
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
    local shared=$'\tlibsystemd-shared-261.so => /usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-261.so (0x0000ffff97fb0000)\n\tlibc.so.6 => /usr/lib/aarch64-linux-gnu/libc.so.6 (0x0000ffff97df0000)\n\t/lib/ld-linux-aarch64.so.1 (0x0000ffff98930000)'
    local core=$'\tlibm.so.6 => /usr/lib/aarch64-linux-gnu/libm.so.6 (0x0000ffff98810000)\n\tlibsystemd-core-261.so => /usr/lib/aarch64-linux-gnu/systemd/libsystemd-core-261.so (0x0000ffff98550000)\n\tlibsystemd-shared-261.so => /usr/lib/aarch64-linux-gnu/systemd/libsystemd-shared-261.so (0x0000ffff97fb0000)\n\tlibc.so.6 => /usr/lib/aarch64-linux-gnu/libc.so.6 (0x0000ffff97df0000)\n\t/lib/ld-linux-aarch64.so.1 (0x0000ffff98930000)'
    mkexe "${t}/${gnu}/ld-linux-aarch64.so.1" "#!/bin/sh
[ \"\$1\" = --list ] || exit 1
case \$2 in
    */usr/lib/systemd/systemd|*/usr/lib/systemd/systemd-executor)
        printf '%s\n' '${vdso}' '${core}' ;;
    */usr/lib/systemd/systemd-shutdown)
        printf '%s\n' '${vdso}' '${shared}' ;;
    */usr/bin/systemctl)
        printf '%s\n' '${vdso}' '${systemctl_libs}' ;;
    *) echo \"\$2: not a dynamic executable\" >&2; exit 1 ;;
esac"
    # Never executed by a --root dry run: it would answer for this host's PID 1.
    mkexe "${t}/usr/bin/systemctl" '#!/bin/sh
echo "the helper ran the tree'"'"'s systemctl" >&2
exit 1'
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
    mkexe "${t}/usr/lib/systemd/systemd-shutdown" '#!/bin/sh'
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
    */usr/bin/systemctl|*/usr/lib/systemd/systemd-shutdown)
        printf '%s\n' '${vdso}' '${systemctl}' '${interp}' ;;
    */usr/bin/plymouth) printf '%s\n' '${vdso}' '${plymouth}' '${interp}' ;;
    *) echo \"\$2: not a dynamic executable\" >&2; exit 1 ;;
esac"
    mkexe "${t}/usr/bin/systemctl" '#!/bin/sh
exit 1'
}
SHOW_ARCH="$(show_file arch '
{ path=/usr/bin/plymouth ; argv[]=/usr/bin/plymouth update-root-fs --new-root-dir=/sysroot ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
{ path=systemctl ; argv[]=systemctl --no-block switch-root ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
')"

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
    # run_dry TREE [SHOW-FILE] -> helper output
    if [ -n "${2:-}" ]; then
        "${HELPER}" --dry-run --root "$1" --show "$2"
    else
        "${HELPER}" --dry-run --root "$1"
    fi
}

check_tree() {
    # check_tree NAME TREE SHOW-FILE EXPECTED_KEEP...
    local name=$1 tree=$2 show=$3 output before after
    shift 3
    before="$(snapshot "${tree}")"
    output="$(run_dry "${tree}" "${show}" 2>&1)"
    after="$(snapshot "${tree}")"
    [ "${before}" = "${after}" ] || fail "${name}: a dry run changed the tree"
    if grep -q '^keeping the initramfs' <<< "${output}"; then
        printf '%s\n' "${output}" >&2
        fail "${name}: the helper refused a well-formed tree"
    fi
    if grep -q "ran the tree's systemctl" <<< "${output}"; then
        fail "${name}: a --root dry run executed the tree's systemctl"
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
    # check_refusal NAME TREE SHOW-FILE REASON-FRAGMENT
    local name=$1 tree=$2 show=$3 reason=$4 output
    output="$(run_dry "${tree}" "${show}")"
    grep -Fq "keeping the initramfs: " <<< "${output}" \
        || fail "${name}: the helper did not refuse"
    grep -Fq -- "${reason}" <<< "${output}" \
        || { printf '%s\n' "${output}" >&2; fail "${name}: the refusal does not name: ${reason}"; }
    if grep -q '^delete ' <<< "${output}"; then
        fail "${name}: the helper listed deletions although it refused"
    fi
}

# PID 1's crash setting is kept by name; another system.conf.d file is not.
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
    /usr/lib/systemd/system.conf.d/50-punar-initrd-crash-action.conf
    /usr/lib/systemd/systemd
    /usr/lib/systemd/systemd-executor
    /usr/lib/systemd/systemd-shutdown
)
make_debian_tree "${WORK}/debian" "${DEBIAN_SYSTEMCTL_LIBS}"
check_tree 'Debian arm64' "${WORK}/debian" "${SHOW_DEBIAN}" "${DEBIAN_KEEP[@]}"
debian_output="$(run_dry "${WORK}/debian" "${SHOW_DEBIAN}")"
# A glob character in a kept name must not keep its look-alike.
grep -Fqx 'delete /usr/lib/aarch64-linux-gnu/libx.so' <<< "${debian_output}" \
    || fail 'a kept name with a glob character also kept its look-alike'
# The emergency shell goes: a failed switch-root reboots instead.
for path in /usr/sbin/sulogin /usr/lib/systemd/systemd-sulogin-shell /usr/bin/bash \
    /usr/lib/systemd/systemd-pcrextend /usr/lib/systemd/system.conf.d/40-other.conf; do
    grep -Fqx "delete ${path}" <<< "${debian_output}" || fail "the release keeps ${path}"
done

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
    /usr/lib/systemd/systemd-shutdown
    /usr/lib64
    /usr/sbin
)
make_arch_tree "${WORK}/arch"
check_tree 'Arch x86_64 with an ExecStartPre= drop-in' "${WORK}/arch" "${SHOW_ARCH}" "${ARCH_KEEP[@]}"

# --- Anything unresolved keeps everything ------------------------------------
make_debian_tree "${WORK}/missing-lib" \
    $'\tlibsystemd-shared-261.so => not found\n\tlibc.so.6 => /usr/lib/aarch64-linux-gnu/libc.so.6 (0x0000ffffb3eb0000)'
check_refusal 'a library the loader cannot find' "${WORK}/missing-lib" "${SHOW_DEBIAN}" \
    'needs libsystemd-shared-261.so, which the dynamic loader cannot find'

make_debian_tree "${WORK}/dangling-lib" \
    $'\tlibgone.so.1 => /usr/lib/aarch64-linux-gnu/libgone.so.1 (0x0000ffffb3eb0000)'
check_refusal 'a listed library that does not exist' "${WORK}/dangling-lib" "${SHOW_DEBIAN}" \
    'cannot resolve /usr/lib/aarch64-linux-gnu/libgone.so.1'

make_debian_tree "${WORK}/no-executor" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/no-executor/usr/lib/systemd/systemd-executor"
check_refusal 'no systemd-executor' "${WORK}/no-executor" "${SHOW_DEBIAN}" \
    'cannot resolve /usr/lib/systemd/systemd-executor'

make_debian_tree "${WORK}/no-shutdown" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/no-shutdown/usr/lib/systemd/systemd-shutdown"
check_refusal 'no systemd-shutdown' "${WORK}/no-shutdown" "${SHOW_DEBIAN}" \
    'cannot resolve /usr/lib/systemd/systemd-shutdown'

make_debian_tree "${WORK}/link-loop" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/link-loop/usr/bin/systemctl"
mklink systemctl.loop "${WORK}/link-loop/usr/bin/systemctl"
mklink systemctl "${WORK}/link-loop/usr/bin/systemctl.loop"
check_refusal 'a symlink loop' "${WORK}/link-loop" "${SHOW_DEBIAN}" 'cannot resolve /usr/bin/systemctl'

make_debian_tree "${WORK}/unknown-command" "${DEBIAN_SYSTEMCTL_LIBS}"
check_refusal 'a switch-root command on no search path directory' "${WORK}/unknown-command" \
    "$(show_file unknown '
{ path=frobnicate ; argv[]=frobnicate --now ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
')" \
    'cannot find frobnicate on the service search path'

make_debian_tree "${WORK}/no-loader" "${DEBIAN_SYSTEMCTL_LIBS}"
rm "${WORK}/no-loader/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1"
check_refusal 'no dynamic loader' "${WORK}/no-loader" "${SHOW_DEBIAN}" 'no dynamic loader'

# With nothing to report initrd-switch-root.service's commands (no --show, or
# an empty one, as a chroot's systemctl answers), only a dry run may fall back
# to the fixed set; the boot step refuses. The tree's systemctl is never run.
for variant in none blank; do
    case ${variant} in
        none) show= ;;
        blank) show="$(show_file blank $'\n\n\n')" ;;
    esac
    no_pid1_output="$(run_dry "${WORK}/debian" "${show}" 2>&1)"
    grep -Fq "dry run: nothing reported initrd-switch-root.service's commands; using the fixed set" \
        <<< "${no_pid1_output}" \
        || fail "a dry run with no switch-root commands (${variant}) did not say it used the fixed set"
    check_tree "the fixed set alone (${variant})" "${WORK}/debian" "${show}" "${DEBIAN_KEEP[@]}"
done
status=0
"${HELPER}" --dry-run --show "${SHOW_DEBIAN}" >/dev/null 2>&1 || status=$?
[ "${status}" -eq 2 ] || fail '--show without --root was not rejected'
grep -Fq '|| keep_nothing "PID 1 reported no command for initrd-switch-root.service' "${HELPER}" \
    || fail 'the boot step does not refuse when PID 1 reports no switch-root command'

# --- Never through a mount boundary -----------------------------------------
# The boot step reads the real mount table: another file system below / is
# skipped (-xdev) and excluded, and so is any bind that is not the initramfs
# bound onto its own path. PID 1's read-only /usr is such a self-bind and must
# still be released. Reproduced with real mounts in an unprivileged user and
# mount namespace. CI must provide one (the workflow lifts Ubuntu's AppArmor
# restriction first); only a local run may skip.
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
    # Root of a user namespace is not real root: --root is allowed there
    # (above), and refused for uid 0 of the initial namespace.
    # shellcheck disable=SC2016 # expanded by the inner shell
    real_root_output="$(unshare --user --map-root-user bash -euc '
        work=$1 helper=$2
        . "${helper}"
        if real_root; then echo "userns-root=real"; else echo "userns-root=not-real"; fi
        printf "0 0 4294967295\n" > "${work}/identity-uid-map"
        UID_MAP="${work}/identity-uid-map"
        if real_root; then echo "identity-map=real"; else echo "identity-map=not-real"; fi
        ( parse_args --dry-run --root "${work}/debian" ) 2>&1 || echo "status=$?"
    ' bash "${WORK}" "${HELPER}")"
    grep -Fqx 'userns-root=not-real' <<< "${real_root_output}" \
        || fail 'root of a user namespace was taken for real root'
    grep -Fqx 'identity-map=real' <<< "${real_root_output}" \
        || fail 'uid 0 with the identity map was not taken for real root'
    { grep -Fq 'refusing --root as root' <<< "${real_root_output}" \
        && grep -Fqx 'status=2' <<< "${real_root_output}"; } \
        || fail '--root as real root was not refused'
elif [ "${CI:-}" = true ]; then
    fail 'CI has no unprivileged user and mount namespace; the real-mount check cannot run'
else
    echo 'initramfs-release-contract-test: note: no unprivileged user namespace; skipping the real-mount check'
fi

# --- Single functions, sourced with fixtures ------------------------------------
# The helper only defines functions when sourced. Each case runs in a subshell
# so that keep_nothing's and not_needed's exit ends the case, not the test.
sourced() {
    # sourced SHELL-CODE -> its output; the helper is sourced first.
    bash -c '. "$1"; eval "$2"' bash "${HELPER}" "$1" 2>&1 || true
}

# Linux 7.0 to 7.2 only.
kernel_case() {
    # kernel_case RELEASE EXPECTED-PREFIX
    printf '%s\n' "$1" > "${WORK}/osrelease"
    local output
    output="$(sourced "KERNEL_RELEASE='${WORK}/osrelease'; check_kernel; echo needed")"
    case ${output} in
        "$2"*) ;;
        *) fail "kernel $1: expected '$2…', got: ${output}" ;;
    esac
}
kernel_case '7.1.12+deb14-arm64' 'needed'
kernel_case '7.2.2-arch1-1' 'needed'
kernel_case '7.0' 'needed'
kernel_case '7.3.0-arch1-1' 'initramfs release not needed: Linux 7.3.0-arch1-1 is 7.3 or later'
kernel_case '7.10.1' 'initramfs release not needed: Linux 7.10.1 is 7.3 or later'
kernel_case '8.0.0' 'initramfs release not needed: Linux 8.0.0 is 7.3 or later'
kernel_case '6.18.3-rpi' 'initramfs release not needed: Linux 6.18.3-rpi is older than 7.0'
kernel_case 'garbage' "keeping the initramfs: cannot read a kernel version from 'garbage'"
kernel_case '7' "keeping the initramfs: cannot read a kernel version from '7'"
grep -Eq '^    check_kernel$' "${HELPER}" || fail 'the safety checks do not check the kernel version'

# PID 1's read-only /usr is made writable only in a private mount namespace.
# The namespaces are fixture symlinks, as /proc/*/ns/mnt are; mount is a
# function that records its call.
ln -s 'mnt:[4026531841]' "${WORK}/ns-pid1"
ln -s 'mnt:[4026532999]' "${WORK}/ns-private"
remount_case() {
    # remount_case SELF-NS PID1-NS -> output
    sourced "
        mount() { echo \"mount \$*\"; }
        MOUNT_POINTS=(/ /usr) MOUNT_DEVS=(0:2 0:2) MOUNT_ROOTS=(/ /usr) MOUNT_OPTIONS=(rw,relatime ro,nosuid)
        ROOT_DEV=0:2 SELF_NS='$1' PID1_NS='$2'
        remount_writable; echo remounted"
}
remount_output="$(remount_case "${WORK}/ns-pid1" "${WORK}/ns-pid1")"
grep -Fq 'keeping the initramfs: /usr is read-only and this is not a private mount namespace' \
    <<< "${remount_output}" || fail "the helper did not refuse to remount in PID 1's namespace: ${remount_output}"
if grep -q '^mount ' <<< "${remount_output}"; then
    fail "the helper remounted in PID 1's namespace"
fi
remount_output="$(remount_case "${WORK}/ns-private" "${WORK}/no-such-ns")"
grep -Fq 'keeping the initramfs: /usr is read-only' <<< "${remount_output}" \
    || fail "the helper remounted without being able to read PID 1's namespace: ${remount_output}"
remount_output="$(remount_case "${WORK}/ns-private" "${WORK}/ns-pid1")"
{ grep -Fqx 'mount -o remount,bind,rw /usr' <<< "${remount_output}" \
    && grep -Fqx 'remounted' <<< "${remount_output}"; } \
    || fail "the helper did not remount /usr in its private namespace: ${remount_output}"
[ "$(grep -c '^mount ' <<< "${remount_output}")" -eq 1 ] \
    || fail 'the helper remounted more than the read-only self-bind'

# Nothing is deleted while PID 1 has a job other than this unit's and the
# switch-root's: a unit being stopped may still run a program of the
# initramfs. The fake systemctl prints $JOBS.
# shellcheck disable=SC2016 # the lines of the fake script, verbatim
printf '%s\n' '#!/bin/sh' '[ "$1" = list-jobs ] || exit 1' 'printf "%s" "$JOBS"' > "${WORK}/fake-systemctl"
chmod 0755 "${WORK}/fake-systemctl"
jobs_case() {
    # jobs_case JOBS -> output
    JOBS="$1" sourced "SYSTEMCTL='${WORK}/fake-systemctl' JOB_WAIT_POLLS=3; wait_for_other_jobs; echo proceed"
}
jobs_output="$(jobs_case '  96 initrd-switch-root.service start waiting
  97 punar-release-initramfs.service start running
')"
[ "${jobs_output}" = proceed ] || fail "the helper waited on its own and the switch-root's jobs: ${jobs_output}"
jobs_output="$(jobs_case '  96 initrd-switch-root.service start waiting
  97 punar-release-initramfs.service start running
  88 systemd-pcrphase-initrd.service stop running
')"
[ "${jobs_output}" = 'keeping the initramfs: PID 1 still has a job that may run a program of the initramfs: systemd-pcrphase-initrd.service stop' ] \
    || fail "the helper did not wait for the PCR barrier's stop: ${jobs_output}"
jobs_output="$(jobs_case '  96 initrd-switch-root.service stop waiting
')"
grep -Fq 'initrd-switch-root.service stop' <<< "${jobs_output}" \
    || fail "the helper took a stop of the switch-root for its start: ${jobs_output}"
grep -Eq '^    wait_for_other_jobs$' "${HELPER}" || fail 'the release does not wait for PID 1'"'"'s other jobs'


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
