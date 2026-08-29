#!/bin/sh
# Fast contract proof for Terminal=true desktop entries. The launcher must
# preserve argv, honor the desktop-entry working directory, prefer the warm
# Foot server, and fall back to a standalone terminal when that server is not
# available.
set -eu

REPO_ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
HELPER="${REPO_ROOT}/os/modules/desktop/hypr/punar-terminal-app.sh"
TEST_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/punar-terminal-app-test.XXXXXX")
cleanup() {
    rm -rf -- "${TEST_ROOT}"
}
trap cleanup EXIT INT TERM

BIN="${TEST_ROOT}/bin"
LOG="${TEST_ROOT}/calls"
WORK="${TEST_ROOT}/working directory"
mkdir -p "${BIN}" "${WORK}"
WORK=$(CDPATH='' cd -- "${WORK}" && pwd)

cat > "${BIN}/footclient" <<'EOF'
#!/bin/sh
{
    printf 'client-pwd=%s\n' "$PWD"
    printf 'client-argc=%s\n' "$#"
    for arg in "$@"; do printf 'client-arg=<%s>\n' "$arg"; done
} >> "${PUNAR_TERMINAL_TEST_LOG}"
exit "${PUNAR_TERMINAL_CLIENT_STATUS:-0}"
EOF
cat > "${BIN}/foot" <<'EOF'
#!/bin/sh
{
    printf 'foot-pwd=%s\n' "$PWD"
    printf 'foot-argc=%s\n' "$#"
    for arg in "$@"; do printf 'foot-arg=<%s>\n' "$arg"; done
} >> "${PUNAR_TERMINAL_TEST_LOG}"
EOF
chmod 0755 "${BIN}/footclient" "${BIN}/foot"

export PATH="${BIN}:${PATH}"
export PUNAR_TERMINAL_TEST_LOG="${LOG}"

: > "${LOG}"
"${HELPER}" --working-directory "${WORK}" -- nvim "file with spaces.md"
grep -Fqx "client-pwd=${WORK}" "${LOG}"
grep -Fqx 'client-argc=4' "${LOG}"
grep -Fqx 'client-arg=<--no-wait>' "${LOG}"
grep -Fqx 'client-arg=<-->' "${LOG}"
grep -Fqx 'client-arg=<nvim>' "${LOG}"
grep -Fqx 'client-arg=<file with spaces.md>' "${LOG}"
if grep -q '^foot-' "${LOG}"; then
    echo 'error: standalone Foot ran even though footclient succeeded' >&2
    exit 1
fi

: > "${LOG}"
PUNAR_TERMINAL_CLIENT_STATUS=1 "${HELPER}" -- nvim README.md
grep -Fqx 'foot-argc=3' "${LOG}"
grep -Fqx 'foot-arg=<-->' "${LOG}"
grep -Fqx 'foot-arg=<nvim>' "${LOG}"
grep -Fqx 'foot-arg=<README.md>' "${LOG}"

: > "${LOG}"
if "${HELPER}" -- >/dev/null 2>&1; then
    echo 'error: launcher accepted a missing application command' >&2
    exit 1
fi
[ ! -s "${LOG}" ] || {
    echo 'error: malformed input reached a terminal process' >&2
    exit 1
}

echo PUNAR_TERMINAL_APP_OK
