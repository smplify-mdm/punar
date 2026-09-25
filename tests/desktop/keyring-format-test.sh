#!/usr/bin/env bash
# The desktop gate's keyring classifier (surfaces-check.sh group 8k), run as
# the gate runs it, against files gnome-keyring itself wrote: the encrypted
# binary format, the plaintext format an empty password produces, and the
# empty file the daemon reserves a new keyring's name with before writing it.
# That last one failed the Arch lane as 'unknown' while the login keyring was
# being written; the gate now waits for it to be written and names it 'empty'.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SURFACES="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh"
FIXTURES="${REPO_ROOT}/tests/desktop/fixtures/keyring"

work="$(mktemp -d)"
trap 'rm -rf "${work}"' EXIT

fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}

# The functions exactly as the gate runs them, each from its opening line to
# the first closing brace in column one.
for helper in keyring_format keyrings_written; do
    awk -v start="${helper}() {" '$0 == start { on = 1 } on { print } on && $0 == "}" { exit }' \
        "${SURFACES}" > "${work}/${helper}.sh"
    [ -s "${work}/${helper}.sh" ] \
        || fail "surfaces-check.sh no longer defines ${helper}() where this test reads it"
    # shellcheck source=/dev/null
    . "${work}/${helper}.sh"
done

expect_format() {
    local want="$1" file="$2" got
    got="$(keyring_format "${file}")"
    [ "${got}" = "${want}" ] || fail "keyring_format ${file#"${work}"/} is '${got}', expected '${want}'"
}

base64 -d < "${FIXTURES}/login.keyring.b64" > "${work}/login.keyring"
cp "${FIXTURES}/unprotected.keyring" "${work}/unprotected.keyring"

expect_format encrypted "${work}/login.keyring"
expect_format plaintext "${work}/unprotected.keyring"
expect_format absent "${work}/nothing.keyring"

# The reservation: created empty, mode 600, before the keyring is written.
: > "${work}/reserved.keyring"
chmod 600 "${work}/reserved.keyring"
expect_format empty "${work}/reserved.keyring"

# Anything else is 'unknown', and fails the gate like 'empty' does: the magic
# cut short, the magic with a version gnome-keyring never wrote, a directory,
# and text that is not the textual format's first group.
head -c 12 "${work}/login.keyring" > "${work}/truncated.keyring"
expect_format unknown "${work}/truncated.keyring"
{
    head -c 16 "${work}/login.keyring"
    printf '\001\000\000\000'
    tail -c +21 "${work}/login.keyring"
} > "${work}/other-version.keyring"
expect_format unknown "${work}/other-version.keyring"
mkdir "${work}/directory.keyring"
expect_format unknown "${work}/directory.keyring"
printf 'display-name=login\n[keyring]\n' > "${work}/misordered.keyring"
expect_format unknown "${work}/misordered.keyring"
if [ "$(id -u)" -ne 0 ]; then
    cp "${work}/login.keyring" "${work}/unreadable.keyring"
    chmod 000 "${work}/unreadable.keyring"
    expect_format unknown "${work}/unreadable.keyring"
    chmod 600 "${work}/unreadable.keyring"
fi

# The gate waits until no keyring in the directory is still a reservation.
written="${work}/written"
mkdir "${written}"
keyrings_written "${written}" || fail "an empty keyring directory counted as unwritten"
cp "${work}/login.keyring" "${written}/login.keyring"
keyrings_written "${written}" || fail "a written login keyring counted as unwritten"
: > "${written}/second.keyring"
if keyrings_written "${written}"; then
    fail "a reserved, unwritten keyring counted as written"
fi
cp "${work}/unprotected.keyring" "${written}/second.keyring"
keyrings_written "${written}" \
    || fail "a written plaintext keyring counted as unwritten (it must be classified, not waited on)"

# And that is what the gate waits on, rather than on the login keyring merely
# existing, which the reservation already satisfies; and a password sign-in
# through the real stack is the only way it creates one, on every lane.
# shellcheck disable=SC2016
grep -Fq '[ ! -s "${login_keyring}" ] || ! keyrings_written "${keyring_dir}"' "${SURFACES}" \
    || fail "group 8k no longer waits for every keyring to be written"
# shellcheck disable=SC2016
grep -Fq 'timeout 30 "${signin_probe}" greetd "$(id -un)"' "${SURFACES}" \
    || fail "group 8k no longer signs in through the greetd stack with punar-signin-probe"
if grep -Eq '^[^#]*gnome-keyring-daemon --unlock' "${SURFACES}"; then
    fail "group 8k stands in for the sign-in with the daemon's own --unlock again"
fi

echo "PUNAR_KEYRING_FORMAT_CONTRACT_OK"
