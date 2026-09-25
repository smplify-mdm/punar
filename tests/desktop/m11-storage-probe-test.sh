#!/usr/bin/env bash
# The M11 context-separation step, run with the check's own helpers: a probe
# counts as persisted only in a profile's Local Storage, never because its
# value sits in the URL a session file recorded, and Chromium is closed
# through its browser process alone, so its storage service commits what it
# holds instead of being signalled straight out of existence. Keep failures
# here ahead of the ~50 minute VM exercise.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
M11_CHECK="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/m11-check.sh"

work="$(mktemp -d)"
stand_ins=""
cleanup() {
    # Intentional word splitting: a list of decimal process ids.
    # shellcheck disable=SC2086
    [ -z "${stand_ins}" ] || kill -9 ${stand_ins} >/dev/null 2>&1 || true
    rm -rf "${work}"
}
trap cleanup EXIT

fail() {
    printf 'FAIL %s\n' "$*" >&2
    exit 1
}

# The helpers exactly as the image runs them: every definition from
# chromium_pids to the EXIT handler, which has side effects and is left out.
awk '/^chromium_pids\(\) \{/ { on = 1 } /^# Invoked through EXIT\./ { on = 0 } on' \
    "${M11_CHECK}" > "${work}/helpers.sh"
for helper in chromium_pids chromium_browser_pids stop_browsers probe_stored probe_files \
        storage_compacted; do
    grep -q "^${helper}() {" "${work}/helpers.sh" \
        || fail "m11-check.sh no longer defines ${helper} where this test reads it"
done
# Read by the sourced chromium_pids, which keeps to this user's processes.
# shellcheck disable=SC2034
PUNAR_UID="$(id -u)"
# shellcheck source=/dev/null
. "${work}/helpers.sh"

# 1. Presence means Local Storage. The atlas page's probe value is its URL
# fragment, so a session file holds it within a second of the navigation,
# about five seconds before Chromium commits the page's own storage write.
atlas="${work}/atlas"
mkdir -p "${atlas}/Default/Sessions" "${atlas}/Default/Local Storage/leveldb"
printf 'file:///usr/share/punar/fixtures/webapps/notes/index.html#punar-ctx-probe-atlas' \
    > "${atlas}/Default/Sessions/Apps_13434819200062989"
if probe_stored "${atlas}" punar-ctx-probe-atlas; then
    fail "a probe value found only in a session file's URL counted as stored"
fi
case "$(probe_files "${atlas}" punar-ctx-probe-atlas)" in
    *Sessions/Apps_13434819200062989*) ;;
    *) fail "probe_files did not name the session file holding the value" ;;
esac
# LevelDB's log record: a Latin-1 marker byte, then the value.
printf 'punar-ctx-probe\001punar-ctx-probe-atlas' \
    > "${atlas}/Default/Local Storage/leveldb/000003.log"
probe_stored "${atlas}" punar-ctx-probe-atlas \
    || fail "a probe value in Local Storage was not found"
if probe_stored "${atlas}" punar-ctx-probe-personal; then
    fail "probe_stored found a value that is nowhere in the profile"
fi
[ -z "$(probe_files "${atlas}" punar-ctx-probe-personal)" ] \
    || fail "probe_files named files for a value that is nowhere in the profile"

# 2. A raw search cannot see inside a compacted table, where Snappy stores a
# probe value that repeats its key as a back-reference, so a table LevelDB
# wrote into Local Storage while the check ran is named, and fails the
# separation step; one written before the check began holds nothing it
# wrote and is not. Explicit times, so nothing here depends on the clock.
leveldb="${atlas}/Default/Local Storage/leveldb"
: > "${leveldb}/000002.ldb"
touch -d '2026-01-01 00:00:00' "${leveldb}/000002.ldb"
mark="${work}/storage-mark"
: > "${mark}"
touch -d '2026-01-02 00:00:00' "${mark}"
[ -z "$(storage_compacted "${atlas}" "${mark}")" ] \
    || fail "a table from before the check counted as compacted during it: $(storage_compacted "${atlas}" "${mark}")"
: > "${leveldb}/000005.ldb"
touch -d '2026-01-03 00:00:00' "${leveldb}/000005.ldb"
[ "$(storage_compacted "${atlas}" "${mark}")" = "Default/Local Storage/leveldb/000005.ldb;" ] \
    || fail "storage_compacted named '$(storage_compacted "${atlas}" "${mark}")', not the table written during the check"
rm -f "${leveldb}/000002.ldb" "${leveldb}/000005.ldb"
# And the separation step asks it of both profiles, against a mark made
# before either context's browser started.
for profile in PERSONAL_PROFILE ATLAS_PROFILE; do
    grep -Fq "compacted=\"\$(storage_compacted \"\${${profile}}\" \"\${STORAGE_MARK}\")\"" "${M11_CHECK}" \
        || fail "the separation step no longer looks for a table compacted in ${profile}"
done
# shellcheck disable=SC2016
mark_line="$(grep -nxF 'STORAGE_MARK="$(mktemp)"' "${M11_CHECK}" | cut -d: -f1)"
# shellcheck disable=SC2016
first_launch="$(grep -nE '^as_punar "\$\{CTL\}" web-apps (launch|browse) ' "${M11_CHECK}" | head -n 1 | cut -d: -f1)"
[ -n "${mark_line}" ] && [ -n "${first_launch}" ] && [ "${mark_line}" -lt "${first_launch}" ] \
    || fail "the storage mark is not made before the first context's browser starts (mark ${mark_line:-none}, launch ${first_launch:-none})"

# 3. stop_browsers signals the browser process only. Stand-ins carry the
# real binary's path in their command lines, as chromium_pids requires: a
# storage service that logs every way it is told to stop, and a browser that
# closes it half a second after being told to stop itself, so a SIGTERM sent
# to the service directly is logged first. The real service exits on that
# SIGTERM and loses what it had not committed; this one only records it.
marker="${work}/storage-service"
sh -c 'trap "echo signalled-directly >> \"\$0\"" TERM
       trap "echo closed-by-its-browser >> \"\$0\"; exit 0" USR1
       while :; do sleep 0.1; done' \
    "${marker}" /usr/lib/chromium/chromium --type=utility \
    --utility-sub-type=storage.mojom.StorageService &
service=$!
stand_ins="${service}"
STORAGE_SERVICE="${service}" sh -c 'trap "sleep 0.5; kill -USR1 \"\$STORAGE_SERVICE\"; exit 0" TERM
       while :; do sleep 0.1; done' \
    /usr/lib/chromium/chromium --user-data-dir="${work}/atlas" &
browser=$!
stand_ins="${stand_ins} ${browser}"
waited=0
while [ "$(chromium_pids | wc -l)" -lt 2 ] && [ "${waited}" -lt 50 ]; do
    sleep 0.1
    waited=$((waited + 1))
done
[ "$(chromium_browser_pids)" = "${browser}" ] \
    || fail "chromium_browser_pids named '$(chromium_browser_pids | tr '\n' ' ')', not the browser ${browser}"

stop_browsers
[ -z "$(chromium_pids)" ] || fail "stand-ins survived stop_browsers"
[ "${BROWSERS_KILLED}" -eq 0 ] \
    || fail "stop_browsers killed ${BROWSERS_KILLED} processes that should have closed"
[ "$(cat "${marker}" 2>/dev/null)" = closed-by-its-browser ] \
    || fail "the storage service was told to stop as: $(tr '\n' ' ' < "${marker}" 2>/dev/null || echo 'never'), not only closed by its browser"
stand_ins=""

echo "PUNAR_M11_STORAGE_PROBE_CONTRACT_OK"
