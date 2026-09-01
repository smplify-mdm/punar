#!/usr/bin/env bash
# Git is a product baseline on every desktop architecture and must remain
# visible inside the hardened native-app sandbox used by desktop AI tools.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
X86_PROFILE="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.conf"
ARM_PROFILE="${REPO_ROOT}/os/images/arm64/mkosi.profiles/desktop/mkosi.conf"
SURFACES="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh"
PUNARCTL="${REPO_ROOT}/crates/punarctl/src/main.rs"

fail() {
    echo "developer-baseline-contract-test: FAIL: $*" >&2
    exit 1
}

for profile in "${X86_PROFILE}" "${ARM_PROFILE}"; do
    grep -Eq '^[[:space:]]+git[[:space:]]*$' "${profile}" \
        || fail "${profile#"${REPO_ROOT}/"} does not install Git"
done

grep -Fq 'git --version' "${SURFACES}" \
    || fail "the in-guest desktop gate does not execute Git"
grep -Fq '"/usr/bin:/bin"' "${PUNARCTL}" \
    || fail "the native-app sandbox does not expose the system binary PATH"
grep -Fq '"/usr"' "${PUNARCTL}" \
    || fail "the native-app sandbox does not expose the system Git payload"

echo 'developer-baseline-contract-test: PASS'
