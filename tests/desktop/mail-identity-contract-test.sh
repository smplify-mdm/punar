#!/usr/bin/env bash
# Punar Mail's identity must agree in three places at once.
#
# WHY THIS IS A TEST AND NOT A CONVENTION. `//@ pragma AppId` becomes the
# xdg-toplevel app_id on Wayland. Apps.displayNameForAppId joins that runtime id
# to a desktop entry by the entry's FILE ID and nothing else — it never reads
# StartupWMClass. So the moment the pragma and the filename disagree, the join
# fails, displayNameForAppId falls through to its last resort, and the bar
# prints the raw reverse-DNS id.
#
# That is precisely the bug fixed earlier today for Evolution, and renaming this
# app from punar-mail to org.punar.Mail is exactly the edit that would
# reintroduce it — silently, because nothing errors: a window with an
# unresolvable id looks identical to a window whose entry has not been indexed
# yet. Three files, one identity, checked mechanically.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
QML="${REPO_ROOT}/shell/punar-shell/Mail/shell.qml"
APPS="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/local/share/applications"
GATE="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh"

fail() { echo "mail-identity-contract-test: FAIL: $*" >&2; exit 1; }

[ -f "${QML}" ] || fail "no Mail/shell.qml"

# 1 · the pragma, which is the source of truth
APP_ID=$(sed -n 's|^//@ pragma AppId  *\([^ ]*\) *$|\1|p' "${QML}" | head -1)
[ -n "${APP_ID}" ] || fail "Mail/shell.qml declares no '//@ pragma AppId'; the window would announce itself as org.quickshell"

# The pragma is parsed out of the file's leading lines before Qt starts, so it
# has to be at the top, not merely present.
head -5 "${QML}" | grep -q '^//@ pragma AppId ' \
    || fail "the AppId pragma is not in the first five lines"

# 2 · Theme resolves only with the import path, and the pragma must own it —
# a wrapper-only export dies on the bare `qs -p` path every m*-check.sh uses.
head -5 "${QML}" | grep -q '^//@ pragma Env QML_IMPORT_PATH = /usr/share/punar/shell$' \
    || fail "Mail/shell.qml does not set QML_IMPORT_PATH by pragma; Theme would not resolve on a bare qs -p launch"

# 3 · the desktop entry's FILE ID must equal the app id, because that is the
# only key the shell joins on.
DESKTOP="${APPS}/${APP_ID}.desktop"
[ -f "${DESKTOP}" ] \
    || fail "no ${APP_ID}.desktop — the app id and the desktop file id must match or the bar prints the raw id"

# 4 · StartupWMClass must match too, or startup notification never resolves.
WMCLASS=$(sed -n 's|^StartupWMClass=||p' "${DESKTOP}" | head -1)
[ "${WMCLASS}" = "${APP_ID}" ] \
    || fail "StartupWMClass is '${WMCLASS}', app id is '${APP_ID}'"

# 5 · and the in-VM gate must be looking for the same window, or it silently
# asserts nothing: `select(.class == "…")` matching no client makes every
# downstream check read a null it then compares against.
grep -q "select(.class == \"${APP_ID}\")" "${GATE}" \
    || fail "surfaces-check.sh does not look for class ${APP_ID}; the window gate would match nothing"

# 6 · the launcher must exist and be the Exec target.
EXEC=$(sed -n 's|^Exec=||p' "${DESKTOP}" | head -1)
case "${EXEC}" in
    /usr/lib/punar/punar-mail.sh*) ;;
    *) fail "Exec is '${EXEC}', expected the committed launcher under /usr/lib/punar" ;;
esac
[ -x "${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/lib/punar/punar-mail.sh" ] \
    || fail "the launcher is missing or not executable"

echo "mail-identity-contract-test: PASS (${APP_ID} agrees in shell.qml, ${APP_ID}.desktop and the gate)"
