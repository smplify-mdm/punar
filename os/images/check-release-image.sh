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

    # The development image's unit drop-ins: one points punard at the mock
    # control plane, one lets its exercises stop the reconcile timer. Both
    # live in a unit's .d directory, which the maxdepth-1 scans above never
    # reach.
    [ -d "${ROOT}/usr/lib/systemd/system" ] && find \
        "${ROOT}/usr/lib/systemd/system" -mindepth 2 -maxdepth 2 -path '*.d/*' \
        \( -name '10-mock-control-plane.conf' \
        -o -name '10-dev-stoppable.conf' \) -print

    [ -e "${ROOT}/usr/bin/punar-mock-smplify" ] \
        && printf '%s\n' "${ROOT}/usr/bin/punar-mock-smplify"
    # The desktop gate's sign-in harness: a PAM driver for any service,
    # which has no place on a machine a person signs in to.
    [ -e "${ROOT}/usr/bin/punar-signin-probe" ] \
        && printf '%s\n' "${ROOT}/usr/bin/punar-signin-probe"
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

# A16: nobody who uses this machine is in `input` or `video`, the greeter
# included. `input` lets any process running as that account read every
# keystroke from /dev/input, the lock screen's passphrase included; `video` is
# raw DRM and framebuffer access, which reads the screen. Sessions take their
# devices from logind on the active seat (docs/design/onboarding.md 1.7).
# Checked everywhere membership can come from: /etc/group and /etc/gshadow,
# a sysusers.d `m` line that systemd-sysusers would replay on a later boot,
# and userdb records (membership drop-ins and a user record's memberOf).
greeter_user=$(sed -n 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' \
    "${ROOT}/etc/greetd/config.toml" 2>/dev/null | head -n 1)
is_protected_account() {
    case "$1" in
        greeter|_greetd) return 0 ;;
    esac
    [ -n "${greeter_user}" ] && [ "$1" = "${greeter_user}" ] && return 0
    [ -f "${ROOT}/etc/passwd" ] && awk -F: -v name="$1" '
        $1 == name && $3 >= 1000 && $3 < 60000 { found = 1 }
        END { exit found ? 0 : 1 }' "${ROOT}/etc/passwd"
}
# The loops read here-documents, not pipes, so fail() counts in this shell.
for retired_group in input video; do
    for group_file in etc/group etc/gshadow; do
        [ -f "${ROOT}/${group_file}" ] || continue
        members=$(awk -F: -v group="${retired_group}" -v file="${group_file}" '
            $1 == group {
                list = $4
                if (file == "etc/gshadow" && $3 != "") list = list "," $3
                n = split(list, names, ",")
                for (i = 1; i <= n; i++) if (names[i] != "") print names[i]
            }' "${ROOT}/${group_file}")
        while IFS= read -r member; do
            [ -n "${member}" ] || continue
            if is_protected_account "${member}"; then
                fail A16 "${member} is in the ${retired_group} group (${group_file})"
            fi
        done <<EOF
${members}
EOF
    done
    for sysusers_dir in usr/lib/sysusers.d etc/sysusers.d; do
        [ -d "${ROOT}/${sysusers_dir}" ] || continue
        for sysusers_conf in "${ROOT}/${sysusers_dir}"/*.conf; do
            [ -f "${sysusers_conf}" ] || continue
            members=$(awk -v group="${retired_group}" '
                $1 == "m" && $3 == group { print $2 }' "${sysusers_conf}")
            while IFS= read -r member; do
                [ -n "${member}" ] || continue
                if is_protected_account "${member}"; then
                    fail A16 "${sysusers_conf#"${ROOT}"/} would add ${member} to ${retired_group}"
                fi
            done <<EOF
${members}
EOF
        done
    done
    for userdb_dir in etc/userdb usr/lib/userdb usr/local/lib/userdb run/userdb; do
        [ -d "${ROOT}/${userdb_dir}" ] || continue
        for membership in "${ROOT}/${userdb_dir}"/*:"${retired_group}".membership; do
            [ -e "${membership}" ] || [ -L "${membership}" ] || continue
            fail A16 "a userdb record puts an account in ${retired_group}: ${membership#"${ROOT}"/}"
        done
        for record in "${ROOT}/${userdb_dir}"/*.user; do
            [ -f "${record}" ] || continue
            if tr -d '\n' < "${record}" \
                | grep -Eq "\"memberOf\"[[:space:]]*:[[:space:]]*\\[[^]]*\"${retired_group}\""; then
                fail A16 "a userdb user record is a member of ${retired_group}: ${record#"${ROOT}"/}"
            fi
        done
        # A group record can name its members itself.
        for record in "${ROOT}/${userdb_dir}"/*.group; do
            [ -f "${record}" ] || continue
            flat=$(tr -d '\n' < "${record}")
            if printf '%s' "${flat}" \
                    | grep -Eq "\"groupName\"[[:space:]]*:[[:space:]]*\"${retired_group}\"" \
                && printf '%s' "${flat}" \
                    | grep -Eq '"members"[[:space:]]*:[[:space:]]*\[[[:space:]]*"'; then
                fail A16 "a userdb group record gives ${retired_group} members: ${record#"${ROOT}"/}"
            fi
        done
    done
done
# Without `video` the greeter draws only because logind gives its session the
# seat, which happens only if the greeter's PAM session runs pam_systemd.
# greetd opens the greeter's session under the `greetd-greeter` service when
# that file exists (Debian ships one that includes `login`) and under
# `greetd` otherwise (Arch). Follow @include, include and substack from it.
greeter_service=greetd
for pam_dir in etc/pam.d usr/lib/pam.d; do
    if [ -f "${ROOT}/${pam_dir}/greetd-greeter" ]; then
        greeter_service=greetd-greeter
        break
    fi
done
pam_pending=${greeter_service}
pam_seen=' '
pam_systemd_found=no
pam_depth=0
while [ -n "${pam_pending}" ] && [ "${pam_depth}" -lt 16 ]; do
    pam_depth=$((pam_depth + 1))
    pam_next=''
    for pam_service in ${pam_pending}; do
        case "${pam_seen}" in *" ${pam_service} "*) continue ;; esac
        pam_seen="${pam_seen}${pam_service} "
        pam_file=''
        for pam_dir in etc/pam.d usr/lib/pam.d; do
            if [ -f "${ROOT}/${pam_dir}/${pam_service}" ]; then
                pam_file="${ROOT}/${pam_dir}/${pam_service}"
                break
            fi
        done
        [ -n "${pam_file}" ] || continue
        if grep -Eq '^[[:space:]]*-?session[[:space:]]+(\[[^]]*\]|[a-z]+)[[:space:]]+([^[:space:]]*/)?pam_systemd\.so' "${pam_file}"; then
            pam_systemd_found=yes
        fi
        pam_next="${pam_next} $(sed -n \
            -e 's/^[[:space:]]*@include[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\1/p' \
            -e 's/^[[:space:]]*-\{0,1\}session[[:space:]]\{1,\}\(include\|substack\)[[:space:]]\{1,\}\([^[:space:]]\{1,\}\).*/\2/p' \
            "${pam_file}" | tr '\n' ' ')"
    done
    pam_pending=${pam_next}
done
if [ "${pam_systemd_found}" != yes ]; then
    fail A16 "the greeter's PAM session (${greeter_service}) never runs pam_systemd, so without video it has no seat"
fi

# A17: names resolve over unicast DNS only. LLMNR and multicast DNS announce
# this machine's name to every neighbour on a shared network and let any of
# them answer a single-label lookup; systemd's default turns LLMNR on. The
# drop-in must state both off, and nothing that sorts after it or overrides it
# may state otherwise.
RESOLVED_DROPIN="${ROOT}/usr/lib/systemd/resolved.conf.d/50-punar.conf"
if [ ! -f "${RESOLVED_DROPIN}" ]; then
    fail A17 'the resolver drop-in is missing: usr/lib/systemd/resolved.conf.d/50-punar.conf'
else
    for protocol in LLMNR MulticastDNS; do
        grep -Eq "^[[:space:]]*${protocol}[[:space:]]*=[[:space:]]*no[[:space:]]*$" \
            "${RESOLVED_DROPIN}" \
            || fail A17 "50-punar.conf does not set ${protocol}=no"
    done
fi
# A file of the same name in a directory that outranks /usr/lib replaces the
# drop-in whole, even an empty file or a link to /dev/null, and systemd's
# default of LLMNR=yes comes back.
for resolved_dir in etc/systemd/resolved.conf.d run/systemd/resolved.conf.d \
    usr/local/lib/systemd/resolved.conf.d; do
    resolved_mask="${ROOT}/${resolved_dir}/50-punar.conf"
    if [ -e "${resolved_mask}" ] || [ -L "${resolved_mask}" ]; then
        fail A17 "${resolved_dir}/50-punar.conf replaces the shipped drop-in"
    fi
done
for resolved_conf in \
    "${ROOT}/etc/systemd/resolved.conf" \
    "${ROOT}/run/systemd/resolved.conf" \
    "${ROOT}/usr/local/lib/systemd/resolved.conf" \
    "${ROOT}/usr/lib/systemd/resolved.conf" \
    "${ROOT}"/etc/systemd/resolved.conf.d/*.conf \
    "${ROOT}"/run/systemd/resolved.conf.d/*.conf \
    "${ROOT}"/usr/local/lib/systemd/resolved.conf.d/*.conf \
    "${ROOT}"/usr/lib/systemd/resolved.conf.d/*.conf; do
    [ -f "${resolved_conf}" ] || continue
    awk '
        /^[[:space:]]*[#;]/ { next }
        /^[[:space:]]*(LLMNR|MulticastDNS)[[:space:]]*=/ {
            value = $0
            sub(/^[^=]*=[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            if (value != "no") { print; bad = 1 }
        }
        END { exit bad ? 0 : 1 }' "${resolved_conf}" > /dev/null \
        && fail A17 "${resolved_conf#"${ROOT}"/} turns LLMNR or multicast DNS on"
done

# A18: every package source verifies signatures. A source that installs
# unsigned packages is a path by which anyone on the network, or the mirror,
# runs code as root. pacman: no SigLevel or RemoteFileSigLevel (what
# `pacman -U https://...` uses) may allow an unsigned package, in pacman.conf,
# anything under pacman.d or any file it includes; Arch's own
# DatabaseOptional default concerns the database only, and LocalFileSigLevel
# governs a file root already holds, not a source. APT: no trusted=yes or
# insecure/weak allowance, in one-line or deb822 sources or in apt.conf.
# Flatpak: no remote with GPG verification off, and every catalog remote
# carries its key.
pacman_files="${ROOT}/etc/pacman.conf"
if [ -d "${ROOT}/etc/pacman.d" ]; then
    pacman_files="${pacman_files} $(find "${ROOT}/etc/pacman.d" -type f | tr '\n' ' ')"
fi
if [ -f "${ROOT}/etc/pacman.conf" ]; then
    pacman_includes=$(sed -n \
        's/^[[:space:]]*Include[[:space:]]*=[[:space:]]*\([^[:space:]]*\).*/\1/p' \
        "${ROOT}/etc/pacman.conf")
    while IFS= read -r pacman_include; do
        [ -n "${pacman_include}" ] || continue
        # An Include may be a glob; each match is read as pacman would.
        for pacman_included in "${ROOT}"${pacman_include}; do
            case " ${pacman_files} " in
                *" ${pacman_included} "*) ;;
                *) pacman_files="${pacman_files} ${pacman_included}" ;;
            esac
        done
    done <<EOF
${pacman_includes}
EOF
fi
for pacman_conf in ${pacman_files}; do
    [ -f "${pacman_conf}" ] || continue
    awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*(RemoteFile)?SigLevel[[:space:]]*=/ {
            value = $0
            sub(/^[^=]*=/, "", value)
            n = split(value, words, /[[:space:]]+/)
            for (i = 1; i <= n; i++) {
                if (words[i] ~ /^(Package)?(Never|Optional|TrustAll)$/) { bad = 1 }
            }
        }
        END { exit bad ? 0 : 1 }' "${pacman_conf}" \
        && fail A18 "${pacman_conf#"${ROOT}"/} lets pacman install an unsigned package"
done
for apt_source in "${ROOT}/etc/apt/sources.list" "${ROOT}"/etc/apt/sources.list.d/*.list; do
    [ -f "${apt_source}" ] || continue
    grep -v '^[[:space:]]*#' "${apt_source}" \
        | grep -Eiq '(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure)=yes' \
        && fail A18 "${apt_source#"${ROOT}"/} accepts an unauthenticated APT source"
done
for apt_source in "${ROOT}"/etc/apt/sources.list.d/*.sources; do
    [ -f "${apt_source}" ] || continue
    grep -v '^[[:space:]]*#' "${apt_source}" \
        | grep -Eiq '^[[:space:]]*(Trusted|Allow-Insecure|Allow-Weak|Allow-Downgrade-To-Insecure)[[:space:]]*:[[:space:]]*yes' \
        && fail A18 "${apt_source#"${ROOT}"/} accepts an unauthenticated APT source"
done
for apt_conf in "${ROOT}/etc/apt/apt.conf" "${ROOT}"/etc/apt/apt.conf.d/*; do
    [ -f "${apt_conf}" ] || continue
    grep -v '^[[:space:]]*//' "${apt_conf}" \
        | grep -Eiq '(AllowUnauthenticated|AllowInsecureRepositories|AllowWeakRepositories|AllowDowngradeToInsecureRepositories)[[:space:]"]+(true|yes|1)' \
        && fail A18 "${apt_conf#"${ROOT}"/} lets APT install without verified signatures"
done
for flatpak_conf in \
    "${ROOT}/var/lib/flatpak/repo/config" \
    "${ROOT}"/etc/flatpak/remotes.d/*.flatpakrepo \
    "${ROOT}"/usr/share/flatpak/remotes.d/*.flatpakrepo \
    "${ROOT}"/usr/share/punar/catalog/remotes/*.flatpakrepo; do
    [ -f "${flatpak_conf}" ] || continue
    grep -Eiq '^[[:space:]]*gpg-?verify(-summary)?[[:space:]]*=[[:space:]]*(false|0)' "${flatpak_conf}" \
        && fail A18 "${flatpak_conf#"${ROOT}"/} turns Flatpak signature verification off"
done
for catalog_remote in "${ROOT}"/usr/share/punar/catalog/remotes/*.flatpakrepo; do
    [ -f "${catalog_remote}" ] || continue
    grep -Eq '^GPGKey=.+' "${catalog_remote}" \
        || fail A18 "${catalog_remote#"${ROOT}"/} names no GPGKey, so its remote could not verify anything"
done

# A19: the downloader runs in exactly one place, the unprivileged fetch
# helper (crates/punard/src/fetch.rs). punard is root and used to run it for
# every update and vendor download; it must never again, and neither may any
# other unit or Punar program. punard.service makes the downloaders
# inaccessible to punard itself. The helper's unit must keep what makes it
# unprivileged and what confines its network to public addresses, nothing may
# change it from outside the file, and only root may reach its socket.
FETCH_HELPER=usr/lib/punar/punar-fetch
FETCH_UNIT="${ROOT}/usr/lib/systemd/system/punar-fetch@.service"
FETCH_SOCKET="${ROOT}/usr/lib/systemd/system/punar-fetch.socket"
PUNARD_UNIT="${ROOT}/usr/lib/systemd/system/punard.service"
PUNARD_NO_DOWNLOADER='InaccessiblePaths=-/usr/bin/curl -/usr/bin/wget'
UNIT_ROOTS='etc/systemd/system run/systemd/system usr/local/lib/systemd/system
usr/lib/systemd/system etc/systemd/system.control run/systemd/system.control
run/systemd/transient'
DOWNLOADER_UNITS=$(
    for unit_root in \
        usr/lib/systemd/system usr/lib/systemd/user \
        etc/systemd/system etc/systemd/user; do
        [ -d "${ROOT}/${unit_root}" ] || continue
        find "${ROOT}/${unit_root}" -type f | while IFS= read -r unit_file; do
            if grep -Eq '^[[:space:]]*Exec[A-Za-z]*=([-+!:@|]*|.*[^[:alnum:]_.-])(curl|wget)([[:space:]]|$)' "${unit_file}"; then
                printf '%s ' "${unit_file#"${ROOT}"/}"
            fi
        done
    done
)
if [ -n "${DOWNLOADER_UNITS}" ]; then
    fail A19 "units run a downloader directly: ${DOWNLOADER_UNITS}"
fi
for punar_program in "${ROOT}"/usr/bin/punar* "${ROOT}"/usr/lib/punar/*; do
    [ -f "${punar_program}" ] || continue
    [ "${punar_program}" = "${ROOT}/${FETCH_HELPER}" ] && continue
    if grep -a -q -e '/usr/bin/curl' -e '/usr/bin/wget' "${punar_program}"; then
        fail A19 "${punar_program#"${ROOT}"/} names a downloader; only ${FETCH_HELPER} may"
    elif [ "$(head -c 2 "${punar_program}")" = '#!' ] \
        && sed 's/#.*//' "${punar_program}" \
            | grep -Eq '(^|[;&|`([:space:]])(curl|wget)([[:space:]]|$)'; then
        fail A19 "${punar_program#"${ROOT}"/} runs a downloader; only ${FETCH_HELPER} may"
    fi
done
if [ ! -x "${ROOT}/${FETCH_HELPER}" ]; then
    fail A19 "the fetch helper is missing or not executable: ${FETCH_HELPER}"
fi
# punard: the downloaders stay out of its mount namespace, by path and through
# PATH alike, and nothing that loads after its unit file clears that.
if [ ! -f "${PUNARD_UNIT}" ] || ! grep -qxF -- "${PUNARD_NO_DOWNLOADER}" "${PUNARD_UNIT}"; then
    fail A19 "punard.service does not keep '${PUNARD_NO_DOWNLOADER}'"
fi
for unit_root in ${UNIT_ROOTS}; do
    for punard_file in "${ROOT}/${unit_root}/punard.service" \
        "${ROOT}/${unit_root}"/punard.service.d/*.conf; do
        [ -f "${punard_file}" ] || continue
        [ "${punard_file}" = "${PUNARD_UNIT}" ] && continue
        if grep -Eq '^[[:space:]]*InaccessiblePaths[[:space:]]*=[[:space:]]*$' "${punard_file}"; then
            fail A19 "${punard_file#"${ROOT}"/} clears the downloaders punard.service keeps out"
        fi
        case "${punard_file}" in
            */punard.service)
                grep -qxF -- "${PUNARD_NO_DOWNLOADER}" "${punard_file}" \
                    || fail A19 "${punard_file#"${ROOT}"/} replaces punard.service without '${PUNARD_NO_DOWNLOADER}'"
                ;;
        esac
    done
done
# Nothing but the shipped files may configure the helper: no drop-in for the
# template, an instance, the `punar-` prefix, or every service or socket
# (top-level service.d and socket.d, which no lane's systemd ships), and no
# unit of the same name, or of one instance, that outranks the shipped one.
# Any of these could undo the sandbox where this gate does not look.
for unit_root in ${UNIT_ROOTS}; do
    [ -d "${ROOT}/${unit_root}" ] || continue
    for fetch_override in \
        "${ROOT}/${unit_root}"/punar-fetch@*.service.d \
        "${ROOT}/${unit_root}"/punar-fetch.socket.d \
        "${ROOT}/${unit_root}"/punar-.service.d \
        "${ROOT}/${unit_root}"/punar-.socket.d \
        "${ROOT}/${unit_root}"/service.d \
        "${ROOT}/${unit_root}"/socket.d \
        "${ROOT}/${unit_root}"/punar-fetch@?*.service; do
        [ -e "${fetch_override}" ] || [ -L "${fetch_override}" ] || continue
        fail A19 "${fetch_override#"${ROOT}"/} would change the fetch helper's units"
    done
    [ "${unit_root}" = usr/lib/systemd/system ] && continue
    for fetch_override in "${ROOT}/${unit_root}/punar-fetch@.service" \
        "${ROOT}/${unit_root}/punar-fetch.socket"; do
        [ -e "${fetch_override}" ] || [ -L "${fetch_override}" ] || continue
        fail A19 "${fetch_override#"${ROOT}"/} replaces the shipped fetch helper unit"
    done
done
FETCH_DENY_LOCAL='IPAddressDeny=localhost link-local multicast'
FETCH_DENY_V4='IPAddressDeny=0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 240.0.0.0/4'
FETCH_DENY_V6='IPAddressDeny=::/128 ::ffff:0:0/96 100::/64 2001:db8::/32 fc00::/7 fec0::/10'
if [ ! -f "${FETCH_UNIT}" ]; then
    fail A19 'the fetch helper unit is missing: usr/lib/systemd/system/punar-fetch@.service'
else
    # Each of these is required exactly, and a second assignment of the same
    # setting anywhere in the file (which would win, or for a list, add) is
    # refused as well.
    for required in \
        "ExecStart=/${FETCH_HELPER}" \
        'DynamicUser=yes' \
        'CapabilityBoundingSet=' \
        'AmbientCapabilities=' \
        'NoNewPrivileges=yes' \
        'ProtectSystem=strict' \
        'ProtectHome=yes' \
        'PrivateDevices=yes' \
        'PrivateUsers=yes' \
        'RestrictAddressFamilies=AF_INET AF_INET6' \
        'IPAddressAllow=127.0.0.53'; do
        fetch_key=${required%%=*}
        grep -qxF -- "${required}" "${FETCH_UNIT}" \
            || fail A19 "punar-fetch@.service lost '${required}'"
        if grep -E "^[[:space:]]*${fetch_key}[[:space:]]*=" "${FETCH_UNIT}" \
            | grep -vqxF -- "${required}"; then
            fail A19 "punar-fetch@.service sets ${fetch_key} to something besides '${required#*=}'"
        fi
    done
    for required in "${FETCH_DENY_LOCAL}" "${FETCH_DENY_V4}" "${FETCH_DENY_V6}"; do
        grep -qxF -- "${required}" "${FETCH_UNIT}" \
            || fail A19 "punar-fetch@.service lost '${required}'"
    done
    if grep -E '^[[:space:]]*IPAddressDeny[[:space:]]*=' "${FETCH_UNIT}" \
        | grep -vqxF -e "${FETCH_DENY_LOCAL}" -e "${FETCH_DENY_V4}" -e "${FETCH_DENY_V6}"; then
        fail A19 'punar-fetch@.service changes or clears its address denials'
    fi
    for forbidden in '^User=' '^Group=' '^SupplementaryGroups=' '^ReadWritePaths=' \
        '^CapabilityBoundingSet=.+' '^AmbientCapabilities=.+' '^PrivateNetwork=no' \
        '^BindPaths=' '^\[Install\]'; do
        grep -Eq -- "${forbidden}" "${FETCH_UNIT}" \
            && fail A19 "punar-fetch@.service sets ${forbidden#^}"
    done
fi
if [ ! -f "${FETCH_SOCKET}" ]; then
    fail A19 'the fetch helper socket is missing: usr/lib/systemd/system/punar-fetch.socket'
else
    for required in 'SocketUser=root' 'SocketGroup=root' 'SocketMode=0600' \
        'DirectoryMode=0700' 'Accept=yes'; do
        fetch_key=${required%%=*}
        grep -qxF -- "${required}" "${FETCH_SOCKET}" \
            || fail A19 "punar-fetch.socket lost '${required}'"
        if grep -E "^[[:space:]]*${fetch_key}[[:space:]]*=" "${FETCH_SOCKET}" \
            | grep -vqxF -- "${required}"; then
            fail A19 "punar-fetch.socket sets ${fetch_key} to something besides '${required#*=}'"
        fi
    done
fi

# A20: a researcher can find where to report. security.txt (RFC 9116) names
# at least one contact and the policy, and has not expired: an expired file
# tells a reader the contacts may be stale, and RFC 9116 asks that it expire
# within a year. Evaluated against the time of this build.
SECURITY_TXT="${ROOT}/usr/share/punar/security.txt"
if [ ! -f "${SECURITY_TXT}" ]; then
    fail A20 'the security contact is missing: usr/share/punar/security.txt'
else
    grep -Eq '^Contact: (https://|mailto:).+' "${SECURITY_TXT}" \
        || fail A20 'security.txt names no https: or mailto: Contact'
    grep -Eq '^Policy: https://.+' "${SECURITY_TXT}" \
        || fail A20 'security.txt names no Policy'
    grep -Eq '^Preferred-Languages: .+' "${SECURITY_TXT}" \
        || fail A20 'security.txt states no Preferred-Languages'
    expires_count=$(grep -c '^Expires: ' "${SECURITY_TXT}" || true)
    expires_value=$(sed -n 's/^Expires: //p' "${SECURITY_TXT}" | head -n 1)
    if [ "${expires_count}" != 1 ]; then
        fail A20 "security.txt must carry exactly one Expires (found ${expires_count})"
    elif ! expires_epoch=$(date -u -d "${expires_value}" +%s 2>/dev/null); then
        fail A20 "security.txt Expires is not a time: ${expires_value}"
    else
        build_epoch=$(date -u +%s)
        if [ "${expires_epoch}" -le "${build_epoch}" ]; then
            fail A20 "security.txt expired at ${expires_value}; rotate it and SECURITY.md together"
        elif [ "${expires_epoch}" -gt $((build_epoch + 366 * 86400)) ]; then
            fail A20 "security.txt Expires is more than a year away (${expires_value})"
        fi
    fi
fi

# A21: a password sign-in unlocks the login keyring, so the keyring is
# created and kept encrypted under that password. Without the auth line,
# gnome-keyring never learns the password; without the session line, no
# daemon receives it. Either way the first application that stores a secret
# makes the person choose a keyring password, and an empty one writes every
# secret to disk in plaintext, which is where Omarchy's default keyring is.
# The auth line must follow pam_unix, which is what obtains the password, and
# pam_unix must be `requisite`: under `required` a WRONG password still reaches
# the keyring line, which, wherever it can reach the person's keyring daemon
# at auth time, creates a login keyring that does not exist yet under
# whatever was typed.
GREETD_PAM="${ROOT}/etc/pam.d/greetd"
if [ ! -f "${GREETD_PAM}" ]; then
    fail A21 'the sign-in PAM stack is missing: etc/pam.d/greetd'
else
    keyring_auth=$(awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*-?auth[[:space:]]/ && /pam_unix\.so/ { unix = NR }
        /^[[:space:]]*-?auth[[:space:]]+optional[[:space:]]+([^[:space:]]*\/)?pam_gnome_keyring\.so/ {
            if (unix && !found) { found = NR }
        }
        END { print found ? "ok" : "missing" }' "${GREETD_PAM}")
    [ "${keyring_auth}" = ok ] \
        || fail A21 'etc/pam.d/greetd has no optional pam_gnome_keyring auth line after pam_unix'
    unix_control=$(awk '
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*-?auth[[:space:]]/ && /pam_unix\.so/ { print $2; exit }' "${GREETD_PAM}")
    [ "${unix_control}" = requisite ] \
        || fail A21 "etc/pam.d/greetd runs pam_unix auth as '${unix_control:-absent}', not requisite, so a wrong password reaches pam_gnome_keyring"
    grep -Eq '^[[:space:]]*-?session[[:space:]]+optional[[:space:]]+([^[:space:]]*/)?pam_gnome_keyring\.so([[:space:]].*)?[[:space:]]auto_start([[:space:]]|$)' \
        "${GREETD_PAM}" \
        || fail A21 'etc/pam.d/greetd has no optional pam_gnome_keyring auto_start session line'
fi
keyring_module=no
for keyring_so in \
    "${ROOT}"/usr/lib/security/pam_gnome_keyring.so \
    "${ROOT}"/usr/lib/*/security/pam_gnome_keyring.so \
    "${ROOT}"/lib/security/pam_gnome_keyring.so \
    "${ROOT}"/lib/*/security/pam_gnome_keyring.so; do
    if [ -f "${keyring_so}" ]; then
        keyring_module=yes
        break
    fi
done
[ "${keyring_module}" = yes ] \
    || fail A21 'pam_gnome_keyring.so is not installed, so the sign-in stack cannot unlock the keyring'

if [ "${FAILURES}" -ne 0 ]; then
    printf 'PUNAR_RELEASE_IMAGE_POLICY_FAILED violations=%s\n' \
        "${FAILURES}" >&2
    exit 1
fi

echo PUNAR_RELEASE_IMAGE_POLICY_OK
