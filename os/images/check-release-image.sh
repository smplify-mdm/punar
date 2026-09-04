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
    usr/bin/cryptsetup \
    usr/bin/bootctl; do
    if [ ! -x "${ROOT}/${installer_tool}" ]; then
        fail A12 "required installer executable is missing: ${installer_tool}"
    fi
done

if [ "${FAILURES}" -ne 0 ]; then
    printf 'PUNAR_RELEASE_IMAGE_POLICY_FAILED violations=%s\n' \
        "${FAILURES}" >&2
    exit 1
fi

echo PUNAR_RELEASE_IMAGE_POLICY_OK
