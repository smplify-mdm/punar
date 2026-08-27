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
        -path '*.target.wants/*' -print | while IFS= read -r link; do
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
# filename or image ID.
case " ${KERNEL_COMMAND_LINE} " in
    *' console=ttyS0 '*|*' console=ttyAMA0 '*)
        fail A8 'kernel command line enables a serial console'
        ;;
esac
case " ${KERNEL_COMMAND_LINE} " in
    *' punar.live '*|*' punar.live='*)
        case " ${NORMALIZED_PROFILES} " in
            *' installer '*) ;;
            *) fail A8 'punar.live is set outside the installer profile' ;;
        esac
        ;;
esac

# A9: review the complete system-unit enablement surface, including vendor
# links under /usr and preset-created links under /etc. The expected file is
# intentionally architecture-specific at the caller; comments/blank lines
# are allowed there, the normalized comparison is byte-exact.
if [ ! -f "${EXPECTED_ENABLED_UNITS}" ]; then
    fail A9 "expected enabled-unit manifest is missing: ${EXPECTED_ENABLED_UNITS}"
else
    ACTUAL_UNITS=$(mktemp "${TMPDIR:-/tmp}/punar-enabled-actual.XXXXXX")
    EXPECTED_UNITS=$(mktemp "${TMPDIR:-/tmp}/punar-enabled-expected.XXXXXX")
    cleanup_units() {
        rm -f "${ACTUAL_UNITS}" "${EXPECTED_UNITS}"
    }
    trap cleanup_units EXIT INT TERM

    for unit_root in usr/lib/systemd/system etc/systemd/system; do
        [ -d "${ROOT}/${unit_root}" ] || continue
        find "${ROOT}/${unit_root}" -type l \
            -path '*.target.wants/*' -print
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

if [ "${FAILURES}" -ne 0 ]; then
    printf 'PUNAR_RELEASE_IMAGE_POLICY_FAILED violations=%s\n' \
        "${FAILURES}" >&2
    exit 1
fi

echo PUNAR_RELEASE_IMAGE_POLICY_OK
