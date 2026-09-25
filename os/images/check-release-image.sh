#!/bin/sh
# Reject development credentials, mocks and privileged test harnesses in an
# assembled Punar release tree. mkosi.finalize calls this before UKI creation;
# the standalone interface keeps every branch fixture-testable without an
# expensive image build.
set -eu

usage() {
    echo "usage: $0 ROOT PROFILES KERNEL_COMMAND_LINE EXPECTED_ENABLED_UNITS" >&2
    exit 2
}

[ "$#" -eq 4 ] || usage
ROOT=$1
PROFILES=$2
KERNEL_COMMAND_LINE=$3
EXPECTED_ENABLED_UNITS=$4

# mkosi 26 accepts comma-delimited --profile values but passes PROFILES to
# scripts as a space-delimited string. Normalize both spellings before
# deciding whether this intentionally is a development image.
NORMALIZED_PROFILES=$(printf '%s' "${PROFILES}" | tr ',' ' ')
case " ${NORMALIZED_PROFILES} " in
    *' dev '*)
        echo "PUNAR_RELEASE_IMAGE_POLICY_SKIPPED profiles=${PROFILES}"
        exit 0
        ;;
esac

[ -d "${ROOT}" ] || {
    echo "error: release-image root is not a directory: ${ROOT}" >&2
    exit 2
}

FAILURES=0
fail() {
    code=$1
    shift
    printf 'release-image violation %s: %s\n' "${code}" "$*" >&2
    FAILURES=$((FAILURES + 1))
}

# A0: update admission needs an immutable, canonical Punar identity before the
# first network request. Keep distro ID/VERSION_ID for substrate inventory;
# these image-specific fields identify the signed Punar release.
OS_RELEASE="${ROOT}/usr/lib/os-release"
if [ ! -f "${OS_RELEASE}" ]; then
    fail A0 '/usr/lib/os-release is missing'
else
    IMAGE_ID_VALUE=$(sed -n 's/^IMAGE_ID=//p' "${OS_RELEASE}")
    IMAGE_VERSION_VALUE=$(sed -n 's/^IMAGE_VERSION=//p' "${OS_RELEASE}")
    SNAPSHOT_VALUE=$(sed -n 's/^PUNAR_SNAPSHOT_PIN=//p' "${OS_RELEASE}")
    printf '%s\n' "${IMAGE_ID_VALUE}" \
        | grep -Eq '^punar-[a-z0-9]([a-z0-9-]*[a-z0-9])?$' \
        || fail A0 'IMAGE_ID is missing, duplicated or invalid'
    printf '%s\n' "${IMAGE_VERSION_VALUE}" \
        | grep -Eq '^[0-9]{4}\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\.[0-9]+$' \
        || fail A0 'IMAGE_VERSION is missing, duplicated or non-canonical'
    printf '%s\n' "${SNAPSHOT_VALUE}" \
        | grep -Eq '^[A-Za-z0-9][A-Za-z0-9._:+/-]{0,127}$' \
        || fail A0 'PUNAR_SNAPSHOT_PIN is missing, duplicated or invalid'
    ETC_OS_RELEASE="${ROOT}/etc/os-release"
    if [ ! -f "${ETC_OS_RELEASE}" ]; then
        fail A0 '/etc/os-release is missing'
    elif [ "$(sed -n 's/^IMAGE_ID=//p' "${ETC_OS_RELEASE}")" != "${IMAGE_ID_VALUE}" ] \
        || [ "$(sed -n 's/^IMAGE_VERSION=//p' "${ETC_OS_RELEASE}")" != "${IMAGE_VERSION_VALUE}" ] \
        || [ "$(sed -n 's/^PUNAR_SNAPSHOT_PIN=//p' "${ETC_OS_RELEASE}")" != "${SNAPSHOT_VALUE}" ]; then
        fail A0 '/etc/os-release and /usr/lib/os-release disagree on Punar identity'
    fi
fi

# A1: every shadow authenticator is locked. An empty field is login-capable
# with a null-password PAM policy, while any field beginning ! or * is locked.
if [ ! -f "${ROOT}/etc/shadow" ]; then
    fail A1 '/etc/shadow is missing; authenticator state cannot be proven'
elif awk -F: '
    $1 !~ /^#/ && $1 != "" && $2 !~ /^[!*]/ {
        print $1
        bad = 1
    }
    END { exit bad ? 0 : 1 }
' "${ROOT}/etc/shadow" > /dev/null; then
    fail A1 'at least one account has a usable authenticator'
fi

# A2: onboarding, not the image build, creates the first human account.
if [ -f "${ROOT}/etc/passwd" ] \
    && awk -F: '$1 == "punar" { found = 1 } END { exit found ? 0 : 1 }' \
        "${ROOT}/etc/passwd"; then
    fail A2 'the fixed development user punar exists'
fi

# A3: the fixed dev user's subordinate ID allocation must not survive.
for id_file in etc/subuid etc/subgid; do
    if [ -f "${ROOT}/${id_file}" ] \
        && grep -Eq '^punar:' "${ROOT}/${id_file}"; then
        fail A3 "${id_file} contains a punar allocation"
    fi
done

# A4: a release greeter must authenticate; it may never start a session by
# merely booting the device.
if [ -f "${ROOT}/etc/greetd/config.toml" ] \
    && grep -Eq '^[[:space:]]*\[initial_session\][[:space:]]*$' \
        "${ROOT}/etc/greetd/config.toml"; then
    fail A4 'greetd initial_session autologin is configured'
fi

# A5: exact repository-authored dev/test surface. Include the pre-M2 marker
# chain and the newer Wi-Fi/surface gates as well as M2..M10.
scan_dev_paths() {
    [ -d "${ROOT}/usr/lib/systemd/system" ] && find \
        "${ROOT}/usr/lib/systemd/system" -maxdepth 1 \
        \( -name 'punar-m*-check.service' \
        -o -name 'punar-surface-cost-check.service' \
        -o -name 'punar-surfaces-check.service' \
        -o -name 'punar-wifi-check.service' \
        -o -name 'punar-mock-smplify.service' \
        -o -name 'punar-boot-marker.service' \
        -o -name 'punar-desktop-marker.*' \
        -o -name 'punar-desktop-diag.*' \
        -o -name 'punar-idle-ram.service' \) -print

    [ -d "${ROOT}/usr/lib/punar" ] && find \
        "${ROOT}/usr/lib/punar" -maxdepth 1 \
        \( -name 'm*-check.sh' \
        -o -name 'surface-cost-check.sh' \
        -o -name 'surfaces-check.sh' \
        -o -name 'wifi-check.sh' \
        -o -name 'idle-ram.sh' \
        -o -name 'desktop-ready.sh' \
        -o -name 'foo-agent-fixture.sh' \
        -o -name 'punar-mock-agent' \
        -o -name '10-mock-control-plane.conf' \
        -o -name 'in-agent-scope.sh' \) -print

    [ -e "${ROOT}/usr/bin/punar-mock-smplify" ] \
        && printf '%s\n' "${ROOT}/usr/bin/punar-mock-smplify"
    [ -e "${ROOT}/usr/share/punar/fixtures" ] \
        && printf '%s\n' "${ROOT}/usr/share/punar/fixtures"
}

DEV_PATHS=$(scan_dev_paths || true)
if [ -n "${DEV_PATHS}" ]; then
    fail A5 "development/test paths exist: $(printf '%s' "${DEV_PATHS}" | sed "s#${ROOT}/##g" | tr '\n' ' ')"
fi

# A6: catch renamed or dangling enablement links which point at a forbidden
# unit even when the unit itself was accidentally removed.
if [ -d "${ROOT}/usr/lib/systemd/system" ]; then
    A6_LINKS_FILE=$(mktemp "${TMPDIR:-/tmp}/punar-release-a6.XXXXXX")
    cleanup_a6() {
        rm -f "${A6_LINKS_FILE}"
    }
    trap cleanup_a6 EXIT INT TERM
    find "${ROOT}/usr/lib/systemd/system" -type l \
        -path '*.wants/*' -print | while IFS= read -r link; do
        target=$(readlink "${link}")
        target=${target##*/}
        case "${target}" in
            punar-m*-check.service|punar-surface-cost-check.service|\
            punar-surfaces-check.service|punar-wifi-check.service|\
            punar-mock-smplify.service|punar-boot-marker.service|\
            punar-desktop-marker.*|punar-desktop-diag.*|\
            punar-idle-ram.service)
                printf '%s\n' "${link#"${ROOT}"/} -> ${target}"
                ;;
        esac
    done > "${A6_LINKS_FILE}"
    if [ -s "${A6_LINKS_FILE}" ]; then
        A6_LINKS=$(tr '\n' ' ' < "${A6_LINKS_FILE}")
        fail A6 "forbidden enabled-unit links exist: ${A6_LINKS}"
    fi
    cleanup_a6
    trap - EXIT INT TERM
fi

# A7: no passwordless administrative escape hatch.
if [ -d "${ROOT}/etc/sudoers.d" ] \
    && grep -Rqs -- 'NOPASSWD' "${ROOT}/etc/sudoers.d"; then
    fail A7 '/etc/sudoers.d contains NOPASSWD'
fi

# A8: serial consoles belong to dev/CI only. punar.live is valid only in the
# installer profile, and the exemption is keyed by profile rather than by a
# filename or image ID. Firmware can describe a serial console through ACPI
# SPCR even when no `console=` argument names it; disabling getty generation
# closes that real release login surface while preserving kernel diagnostics.
case " ${KERNEL_COMMAND_LINE} " in
    *' console=ttyS0 '*|*' console=ttyAMA0 '*)
        fail A8 'kernel command line enables a serial console'
        ;;
esac
case " ${KERNEL_COMMAND_LINE} " in
    *' systemd.getty_auto=no '*) ;;
    *) fail A8 'automatic serial/virtualizer getty generation is not disabled' ;;
esac
case " ${KERNEL_COMMAND_LINE} " in
    *' punar.live '*|*' punar.live='*)
        case " ${NORMALIZED_PROFILES} " in
            *' installer '*) ;;
            *) fail A8 'punar.live is set outside the installer profile' ;;
        esac
        ;;
esac

# A9: review the complete system and user unit enablement surface, including
# vendor links under /usr, preset/package-created links under /etc, target
# wants, and unit-specific wants. The expected file is intentionally
# architecture-specific; comments/blank lines are allowed and the normalized
# comparison is byte-exact.
if [ ! -f "${EXPECTED_ENABLED_UNITS}" ]; then
    fail A9 "expected enabled-unit manifest is missing: ${EXPECTED_ENABLED_UNITS}"
else
    ACTUAL_UNITS=$(mktemp "${TMPDIR:-/tmp}/punar-enabled-actual.XXXXXX")
    EXPECTED_UNITS=$(mktemp "${TMPDIR:-/tmp}/punar-enabled-expected.XXXXXX")
    cleanup_units() {
        rm -f "${ACTUAL_UNITS}" "${EXPECTED_UNITS}"
    }
    trap cleanup_units EXIT INT TERM

    for unit_root in \
        usr/lib/systemd/system etc/systemd/system \
        usr/lib/systemd/user etc/systemd/user; do
        [ -d "${ROOT}/${unit_root}" ] || continue
        find "${ROOT}/${unit_root}" -type l \
            -path '*.wants/*' -print
    done | LC_ALL=C sort | while IFS= read -r link; do
        printf '%s -> %s\n' "${link#"${ROOT}"/}" "$(readlink "${link}")"
    done > "${ACTUAL_UNITS}"
    awk 'NF && $1 !~ /^#/' "${EXPECTED_ENABLED_UNITS}" \
        | LC_ALL=C sort > "${EXPECTED_UNITS}"

    if ! diff -u "${EXPECTED_UNITS}" "${ACTUAL_UNITS}" > /dev/null; then
        fail A9 'enabled system units differ from the reviewed manifest'
        diff -u "${EXPECTED_UNITS}" "${ACTUAL_UNITS}" >&2 || true
    fi
    cleanup_units
    trap - EXIT INT TERM
fi

# A10: Hyprland 0.56 displays an unavoidable warning for the deprecated
# hyprlang provider and 0.57 removes it. Both product sessions must enter via
# the native Lua provider; keeping an unused legacy file is also rejected so a
# future launcher cannot silently select the wrong format.
for lua_config in hyprland.lua punar-greeter.lua; do
    if [ ! -f "${ROOT}/etc/xdg/hypr/${lua_config}" ]; then
        fail A10 "native Hyprland config is missing: etc/xdg/hypr/${lua_config}"
    fi
done
for legacy_config in hyprland.conf punar-greeter.conf; do
    if [ -e "${ROOT}/etc/xdg/hypr/${legacy_config}" ]; then
        fail A10 "legacy Hyprland config exists: etc/xdg/hypr/${legacy_config}"
    fi
done

# A11: a release may ship agent adapters and detection rules, but never the
# history those mechanisms produce. Build or test residue here would be shown
# as genuine activity on first boot, which is indistinguishable from lying to
# the user. Empty runtime-owned directories are fine; persisted records are
# not.
for state_file in \
    var/lib/punar/agents/registry.jsonl \
    var/lib/punar/agents/detections.jsonl \
    var/lib/punar/agents/detections-index.json \
    var/lib/punar/agents/ledger/index.json; do
    if [ -e "${ROOT}/${state_file}" ]; then
        fail A11 "seeded agent state exists: ${state_file}"
    fi
done
if [ -d "${ROOT}/var/lib/punar/agents/ledger" ] \
    && find "${ROOT}/var/lib/punar/agents/ledger" -mindepth 1 -print -quit \
        | grep -q .; then
    fail A11 'seeded agent ledger records exist'
fi

# A12: every release tree is also the live installer's userspace. Validate
# the exact fixed tools punard executes before an ISO can wrap a tree that
# boots correctly but cannot complete its mandatory encrypted install.
for installer_tool in \
    usr/bin/zstd \
    usr/bin/systemd-repart \
    usr/bin/systemd-cryptenroll \
    usr/bin/bootctl; do
    if [ ! -x "${ROOT}/${installer_tool}" ]; then
        fail A12 "required installer executable is missing: ${installer_tool}"
    fi
done
if [ ! -x "${ROOT}/usr/bin/cryptsetup" ] \
    && [ ! -x "${ROOT}/usr/sbin/cryptsetup" ]; then
    fail A12 'required installer executable is missing: usr/{bin,sbin}/cryptsetup'
fi

# A13: an unattended release session must lock itself. The lock surface and its
# PAM stack are useless if nothing invokes them, and the CI image deliberately
# overrides this policy with a day-long timeout so the desktop exercises are not
# locked out mid-run — which means the product's bound can only be asserted
# here, against a tree where nothing overrides it.
IDLE_POLICY="${ROOT}/etc/xdg/hypr/punar-hypridle.conf"
if [ ! -f "${IDLE_POLICY}" ]; then
    fail A13 'the idle-lock policy is missing: etc/xdg/hypr/punar-hypridle.conf'
else
    idle_timeout=$(awk '/^[[:space:]]*timeout[[:space:]]*=/ {print $3; exit}' \
        "${IDLE_POLICY}")
    case "${idle_timeout}" in
        ''|*[!0-9]*)
            fail A13 "the idle-lock policy states no numeric timeout (got '${idle_timeout}')"
            ;;
        *)
            if [ "${idle_timeout}" -lt 60 ] || [ "${idle_timeout}" -gt 1800 ]; then
                fail A13 "the idle-lock timeout is ${idle_timeout}s, outside 60..1800"
            fi
            ;;
    esac
    if ! grep -qE '^[[:space:]]*lock_cmd[[:space:]]*=.*ipc call lock lock' \
            "${IDLE_POLICY}"; then
        fail A13 'the idle-lock policy does not route locking to the Punar lock surface'
    fi
    # Owner is compared against the tree's own /etc rather than the literal
    # "root": a real image is assembled as root, but the policy test builds its
    # fixture as the unprivileged CI runner, where everything is owned by
    # `runner` and a literal check fails on a conforming tree. The property
    # that matters is that this file is owned by whoever owns the system
    # configuration and is writable by nobody else.
    idle_owner=$(stat -c '%U' "${IDLE_POLICY}")
    etc_owner=$(stat -c '%U' "${ROOT}/etc")
    idle_mode=$(stat -c '%a' "${IDLE_POLICY}")
    if [ "${idle_owner}" != "${etc_owner}" ]; then
        fail A13 "the idle-lock policy is owned by ${idle_owner}, not ${etc_owner} like /etc"
    fi
    if [ "${idle_mode}" != "644" ]; then
        fail A13 "the idle-lock policy is mode ${idle_mode}, not 644"
    fi
fi

# A14: the account-lockout policy must be STATED by the image, not inherited.
# etc/pam.d/punar-lock has always included pam_faillock, so after enough failed
# passphrases the account locks and the CORRECT passphrase is refused too. With
# no faillock.conf that threshold was whatever Arch's built-in defaults happened
# to be, written down nowhere — and a lockout that nobody declared is one the
# lock surface cannot describe, so it prints "Try again" and a locked-out owner
# concludes their passphrase is broken. On a LUKS machine that conclusion ends
# in a wipe. The bounds below are sanity, not taste: a deny of 1 is a machine
# that locks on one typo, and an unlock_time long enough to outlast a working
# day is indistinguishable from a brick.
LOCKOUT_POLICY="${ROOT}/etc/security/faillock.conf"
if [ ! -f "${LOCKOUT_POLICY}" ]; then
    fail A14 'the account-lockout policy is missing: etc/security/faillock.conf'
else
    lock_deny=$(awk -F= '/^[[:space:]]*deny[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' \
        "${LOCKOUT_POLICY}")
    lock_unlock=$(awk -F= '/^[[:space:]]*unlock_time[[:space:]]*=/ {gsub(/[[:space:]]/,"",$2); print $2; exit}' \
        "${LOCKOUT_POLICY}")
    case "${lock_deny}" in
        ''|*[!0-9]*) fail A14 "the lockout policy states no numeric deny (got '${lock_deny}')" ;;
        *) if [ "${lock_deny}" -lt 3 ] || [ "${lock_deny}" -gt 10 ]; then
               fail A14 "the lockout deny is ${lock_deny}, outside 3..10"
           fi ;;
    esac
    case "${lock_unlock}" in
        ''|*[!0-9]*) fail A14 "the lockout policy states no numeric unlock_time (got '${lock_unlock}')" ;;
        *) if [ "${lock_unlock}" -lt 60 ] || [ "${lock_unlock}" -gt 3600 ]; then
               fail A14 "the lockout unlock_time is ${lock_unlock}s, outside 60..3600"
           fi ;;
    esac
    # The lock surface READS this file to phrase what it tells the reader, so a
    # tree where it is unreadable would silently return the surface to the
    # unlabelled "Try again" this assertion exists to prevent.
    lock_mode=$(stat -c '%a' "${LOCKOUT_POLICY}")
    lock_owner=$(stat -c '%U' "${LOCKOUT_POLICY}")
    etc_owner_l=$(stat -c '%U' "${ROOT}/etc")
    if [ "${lock_owner}" != "${etc_owner_l}" ]; then
        fail A14 "the lockout policy is owned by ${lock_owner}, not ${etc_owner_l} like /etc"
    fi
    if [ "${lock_mode}" != "644" ]; then
        fail A14 "the lockout policy is mode ${lock_mode}, not 644 (the lock surface must read it)"
    fi
fi

# A15: the lock exercise seam must not exist in a release image. Its presence
# gates two IPC verbs. `qs ipc call lock submit <passphrase>` reaches the lock
# surface's PAM conversation, which is how the in-VM gate proves a correct
# passphrase actually unlocks a session; `lock field` reports what the frosted
# background resolved, which is how the gate tells a blank effect from an image
# that never loaded. Without the marker both answer "refused". That is not an unlock bypass — a wrong secret fails exactly
# as it does at the keyboard, and faillock counts it the same — but it does let
# anything that can reach the session's IPC socket guess at machine speed. A
# locked screen is a promise about someone at the keyboard, and this file is the
# mechanism that keeps the promise from being widened by a shipped convenience.
LOCK_EXERCISE="${ROOT}/usr/lib/punar/lock-exercise.allow"
if [ -e "${LOCK_EXERCISE}" ]; then
    fail A15 'the lock exercise seam is present: usr/lib/punar/lock-exercise.allow'
fi

# A16 (F0-S2): Yama lets a process ptrace-attach only to its own descendants.
# Without it every program a person runs can read the memory of every other —
# the shell while a password is typed, punarctl while it holds a ticket. Arch
# starts Yama at 1 and Debian patches it to 0, so the value must be STATED by
# this image, and nothing else in the tree may state a different one: exactly
# 1, because 3 would also forbid punard's by-pid descriptor fetch.
YAMA_CONF="${ROOT}/usr/lib/sysctl.d/50-punar-yama.conf"
if [ ! -f "${YAMA_CONF}" ]; then
    fail A16 'the Yama policy is missing: usr/lib/sysctl.d/50-punar-yama.conf'
else
    yama_value=$(sed -n \
        's/^[[:space:]]*kernel[./]yama[./]ptrace_scope[[:space:]]*=[[:space:]]*\([0-9][0-9]*\)[[:space:]]*$/\1/p' \
        "${YAMA_CONF}" | tail -n 1)
    if [ "${yama_value}" != 1 ]; then
        fail A16 "the Yama policy sets kernel.yama.ptrace_scope to '${yama_value}', not 1"
    fi
fi
for sysctl_dir in usr/lib/sysctl.d usr/local/lib/sysctl.d etc/sysctl.d run/sysctl.d; do
    [ -d "${ROOT}/${sysctl_dir}" ] || continue
    for sysctl_conf in "${ROOT}/${sysctl_dir}"/*.conf; do
        [ -f "${sysctl_conf}" ] && [ ! -L "${sysctl_conf}" ] || continue
        [ "${sysctl_conf}" = "${YAMA_CONF}" ] && continue
        if grep -Eq '^[[:space:]]*-?kernel[./]yama[./]ptrace_scope[[:space:]]*=' \
                "${sysctl_conf}"; then
            fail A16 "${sysctl_conf#"${ROOT}"/} also sets kernel.yama.ptrace_scope"
        fi
    done
done
if [ -f "${ROOT}/etc/sysctl.conf" ] \
    && grep -Eq '^[[:space:]]*-?kernel[./]yama[./]ptrace_scope[[:space:]]*=' \
        "${ROOT}/etc/sysctl.conf"; then
    fail A16 'etc/sysctl.conf also sets kernel.yama.ptrace_scope'
fi

# A17 (F0-S3): the audit trail belongs to root and group punar-audit, which no
# person is in. It used to be group punar — every account — so every person
# could read every person's events. A person reads their own through
# audit.tail. The directory, the live file, its rotation and its lock are all
# declared here, where an auditor reads them; no tmpfiles line anywhere may
# hand /var/log/punar to another group.
PUNARD_TMPFILES="${ROOT}/usr/lib/tmpfiles.d/punard.conf"
if [ ! -f "${PUNARD_TMPFILES}" ]; then
    fail A17 'the audit trail modes are undeclared: usr/lib/tmpfiles.d/punard.conf is missing'
else
    if ! grep -Eq '^d[[:space:]]+/var/log/punar[[:space:]]+0750[[:space:]]+root[[:space:]]+punar-audit([[:space:]]|$)' \
            "${PUNARD_TMPFILES}"; then
        fail A17 '/var/log/punar is not declared 0750 root:punar-audit'
    fi
    for audit_file in audit.jsonl audit.jsonl.1 audit.jsonl.lock; do
        if ! grep -Eq "^z[[:space:]]+/var/log/punar/${audit_file}[[:space:]]+0640[[:space:]]+root[[:space:]]+punar-audit([[:space:]]|\$)" \
                "${PUNARD_TMPFILES}"; then
            fail A17 "/var/log/punar/${audit_file} is not declared 0640 root:punar-audit"
        fi
    done
fi
for tmpfiles_dir in usr/lib/tmpfiles.d etc/tmpfiles.d; do
    [ -d "${ROOT}/${tmpfiles_dir}" ] || continue
    AUDIT_GRANTS=$(awk '
        $1 !~ /^#/ && $2 ~ /^\/var\/log\/punar(\/|$)/ \
            && $5 != "punar-audit" && $5 != "root" && $5 != "-" { print FILENAME ": " $0 }
    ' "${ROOT}/${tmpfiles_dir}"/*.conf 2>/dev/null || true)
    if [ -n "${AUDIT_GRANTS}" ]; then
        fail A17 "a tmpfiles line gives the audit trail to another group: $(printf '%s' "${AUDIT_GRANTS}" | sed "s#${ROOT}/##g" | tr '\n' ' ')"
    fi
done
group_members() {
    awk -F: -v name="$1" '$1 == name { found = 1; print "members=" $4 } END { if (!found) print "missing" }' \
        "${ROOT}/etc/group"
}
if [ ! -f "${ROOT}/etc/group" ]; then
    fail A17 '/etc/group is missing; the audit and administrator groups cannot be proven'
else
    case "$(group_members punar-audit)" in
        missing) fail A17 'the punar-audit group does not exist' ;;
        'members=') ;;
        *) fail A17 "the punar-audit group names members: $(group_members punar-audit)" ;;
    esac
fi

# A18 (F0-S1): the device-administrator group exists, so onboarding can put
# the first account in it, and it is EMPTY in the image: an administrator is a
# person on the device, never a property of the release. A member here would
# be an account every installed device trusts to act on everyone on it.
if [ -f "${ROOT}/etc/group" ]; then
    case "$(group_members punar-admin)" in
        missing) fail A18 'the punar-admin group does not exist; onboarding could not make the first account an administrator' ;;
        'members=') ;;
        *) fail A18 "the punar-admin group names members in the image: $(group_members punar-admin)" ;;
    esac
fi
if [ -f "${ROOT}/etc/gshadow" ] \
    && awk -F: '($1 == "punar-admin" || $1 == "punar-audit") && $4 != "" { bad = 1 } END { exit bad ? 0 : 1 }' \
        "${ROOT}/etc/gshadow"; then
    fail A18 '/etc/gshadow names members of punar-admin or punar-audit'
fi

if [ "${FAILURES}" -ne 0 ]; then
    printf 'PUNAR_RELEASE_IMAGE_POLICY_FAILED violations=%s\n' \
        "${FAILURES}" >&2
    exit 1
fi

echo PUNAR_RELEASE_IMAGE_POLICY_OK
