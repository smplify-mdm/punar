#!/usr/bin/env bash
# The sandbox package must be new enough to close GHSA-pxhw-h44j-8pfx on
# every substrate, and both construction and runtime must fail closed.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VERIFY="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/verify-bubblewrap"
M12_CHECK="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/m12-check.sh"
MOCK_AGENT="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/punar-mock-agent"

fail() { echo "bubblewrap-security-contract-test: FAIL: $*" >&2; exit 1; }

# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/snapshot.env"
[[ "${PUNAR_SNAPSHOT_PIN}" > 20260901T000000Z || "${PUNAR_SNAPSHOT_PIN}" == 20260901T000000Z ]] \
    || fail "Arch snapshot predates Bubblewrap 0.12.0"
# shellcheck source=/dev/null
. "${REPO_ROOT}/os/images/debian-snapshot.env"
[[ "${PUNAR_DEBIAN_SNAPSHOT}" > 20260901T000000Z || "${PUNAR_DEBIAN_SNAPSHOT}" == 20260901T000000Z ]] \
    || fail "Debian snapshot predates Bubblewrap 0.12.0"

[ -x "${VERIFY}" ] || fail "image Bubblewrap verifier is absent or not executable"
grep -q 'GHSA-pxhw-h44j-8pfx' "${VERIFY}" \
    || fail "image verifier does not cite the release-blocking advisory"
grep -q '0o6000' "${REPO_ROOT}/crates/punar-env/src/isolation.rs" \
    || fail "runtime does not reject a privileged Bubblewrap binary"
grep -q 'version < (0, 12, 0)' "${REPO_ROOT}/crates/punar-env/src/isolation.rs" \
    || fail "runtime does not enforce the 0.12.0 security floor"

# The M12 proof must obey the same closed project-file policy as a real
# managed launch. A coordination FIFO used to make the proof fail at the
# production validator before the adapter could start. Keep synchronization
# on a regular file and prove both sides use a blocking advisory lock.
grep -Fq "PROBE_GATE=\"\${ATLAS}/.punar-agent-net-gate\"" "${M12_CHECK}" \
    || fail "M12 does not declare its regular-file coordination gate"
grep -Fq "LEGACY_PROBE_FIFO=\"\${ATLAS}/.punar-agent-net-go\"" "${M12_CHECK}" \
    || fail "M12 does not remove the obsolete coordination FIFO"
grep -Fq 'flock -x 9' "${M12_CHECK}" \
    || fail "M12 does not hold the exclusive coordination lock"
grep -Fq 'exec 9>&-' "${M12_CHECK}" \
    || fail "M12 does not close the coordination descriptor at release and launch"
grep -Fq "flock -s \"./\$NET_GATE\" true" "${MOCK_AGENT}" \
    || fail "mock agent does not block on the regular-file coordination lock"
if grep -Eq 'mkfifo.*NET_|\[ ! -p .*NET_' "${M12_CHECK}" "${MOCK_AGENT}"; then
    fail "M12 still creates or requires a special-file coordination FIFO"
fi

for postinst in \
    "${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.postinst.chroot" \
    "${REPO_ROOT}/os/images/amd64-debian/mkosi.profiles/desktop/mkosi.postinst.chroot" \
    "${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.postinst.chroot"; do
    grep -qx '/usr/lib/punar/verify-bubblewrap' "${postinst}" \
        || fail "${postinst} does not run the image verifier"
done

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
fake="${tmp}/bwrap"
write_fake() {
    printf '#!/bin/sh\nprintf "bubblewrap %%s\\n" "%s"\n' "$1" > "${fake}"
    chmod 0755 "${fake}"
}

write_fake 0.11.2
if "${VERIFY}" "${fake}" >/dev/null 2>&1; then
    fail "image verifier accepted vulnerable Bubblewrap 0.11.2"
fi
write_fake 0.12.0
"${VERIFY}" "${fake}" >/dev/null \
    || fail "image verifier rejected fixed Bubblewrap 0.12.0"
chmod 4755 "${fake}"
if "${VERIFY}" "${fake}" >/dev/null 2>&1; then
    fail "image verifier accepted setuid Bubblewrap"
fi

echo "bubblewrap-security-contract-test: PASS"
