#!/usr/bin/env bash
# Punar's non-shipping Mail window probe must have one stable runtime identity
# while remaining impossible to mistake for a working mail application.
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
PRODUCT_EXTRA="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra"
DEV_EXTRA="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra"
APPS="${DEV_EXTRA}/usr/local/share/applications"
GATE="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh"
STAGER="${REPO_ROOT}/os/images/scripts/container-build.sh"

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

# The surface is deliberately fixture-backed. It exists only in the dev/CI
# overlay for the graphical xdg-toplevel gate; the release image must contain
# neither its launcher nor its data.
grep -qx 'NoDisplay=true' "${DESKTOP}" \
    || fail "the fixture-backed Mail probe is visible in the application launcher"
grep -qx 'Name=Mail interface prototype' "${DESKTOP}" \
    || fail "the hidden probe does not name itself as a prototype"
! grep -q '^MimeType=' "${DESKTOP}" \
    || fail "the fixture-backed probe claims a real mail or calendar MIME handler"
grep -q 'FIXTURE DATA · NO ACCOUNT · NOTHING IS CONNECTED' "${QML}" \
    || fail "the prototype no longer discloses its fixture state on its own surface"
[ ! -e "${PRODUCT_EXTRA}/usr/local/share/applications/${APP_ID}.desktop" ] \
    || fail "the production image still ships the fixture-backed Mail desktop entry"
[ ! -e "${PRODUCT_EXTRA}/usr/lib/punar/punar-mail.sh" ] \
    || fail "the production image still ships the fixture-backed Mail launcher"
grep -Fq "rm -rf \"\${extra}/usr/share/punar/shell/Mail\"" "${STAGER}" \
    || fail "desktop staging does not remove Mail fixture QML from the production image"
grep -Fq "cp -R \"\${shell_src}/Mail\" \"\${dev_extra}/usr/share/punar/shell/Mail\"" "${STAGER}" \
    || fail "desktop staging does not restore the Mail probe in the dev/CI overlay"

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
LAUNCHER="${DEV_EXTRA}/usr/lib/punar/punar-mail.sh"
[ -x "${LAUNCHER}" ] || fail "the launcher is missing or not executable"

# 7 · THE LAUNCHER MUST ESTABLISH THE GRAPHICS ENVIRONMENT. A Punar application
# is started from a .desktop entry, a systemd unit, a terminal or a CI probe —
# none of which is a child of Hyprland, and none of which therefore inherits
# what session.sh configured. Without it, qs on a machine with no usable GPU
# dies with "libEGL warning: egl: failed to create dri2 screen" and the window
# never maps. Chromium never hit this only because the SHELL launches it.
grep -q 'punar_configure_graphics' "${LAUNCHER}" \
    || fail "the launcher does not configure graphics; the window will not map without a GPU"

# 8 · AND IT MUST NOT SET QML_IMPORT_PATH. That belongs to the pragma, so it
# survives the bare `qs -p` launches the m*-check scripts use. A wrapper that
# re-exports it invites the pragma being dropped as redundant.
! grep -q 'QML_IMPORT_PATH' "${LAUNCHER}" \
    || fail "the launcher exports QML_IMPORT_PATH; that belongs to the pragma, which covers every launch path"

echo "mail-identity-contract-test: PASS (${APP_ID} is stable, dev-only and absent from production staging)"
