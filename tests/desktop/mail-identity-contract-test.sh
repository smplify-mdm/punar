#!/usr/bin/env bash
# Punar Mail and its explicit developer fixture must share one stable runtime
# identity without allowing fixture data into a product image.
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
PRODUCT_DESKTOP_SOURCE="${REPO_ROOT}/os/modules/desktop/applications/org.punar.Mail.desktop"
DEV_APPS="${DEV_EXTRA}/usr/local/share/applications"
GATE="${REPO_ROOT}/os/images/mkosi.profiles/dev/mkosi.extra/usr/lib/punar/surfaces-check.sh"
STAGER="${REPO_ROOT}/os/images/scripts/container-build.sh"
ACCOUNT_QML="${REPO_ROOT}/shell/punar-shell/MailAccount/shell.qml"
ACCOUNT_DESKTOP="${REPO_ROOT}/os/modules/desktop/applications/org.punar.MailAccount.desktop"
ACCOUNTS_QML="${REPO_ROOT}/shell/punar-shell/MailAccounts/shell.qml"
ACCOUNTS_DESKTOP="${REPO_ROOT}/os/modules/desktop/applications/org.punar.MailAccounts.desktop"

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
DESKTOP="${PRODUCT_DESKTOP_SOURCE}"
[ -f "${DESKTOP}" ] \
    || fail "no ${APP_ID}.desktop — the app id and the desktop file id must match or the bar prints the raw id"

# 4 · StartupWMClass must match too, or startup notification never resolves.
WMCLASS=$(sed -n 's|^StartupWMClass=||p' "${DESKTOP}" | head -1)
[ "${WMCLASS}" = "${APP_ID}" ] \
    || fail "StartupWMClass is '${WMCLASS}', app id is '${APP_ID}'"

# The product entry is a visible generic Mail application and reaches only the
# closed punard launch method. It never starts QML directly.
grep -qx 'Name=Mail' "${DESKTOP}" || fail "the product entry is not generically named Mail"
! grep -q '^NoDisplay=true$' "${DESKTOP}" \
    || fail "the real Mail application is hidden from the launcher"
grep -qx 'Exec=punarctl mail open' "${DESKTOP}" \
    || fail "the product entry bypasses the protected Mail launch method"
! grep -q '^MimeType=' "${DESKTOP}" \
    || fail "Mail claims a message MIME handler before compose/import exists"

# The complete fixture surface remains a visibly labelled, hidden dev-only
# overlay. Production staging removes only Fixtures.qml, never the live model.
DEV_DESKTOP="${DEV_APPS}/${APP_ID}.desktop"
[ -f "${DEV_DESKTOP}" ] || fail "the developer Mail fixture entry is missing"
grep -qx 'NoDisplay=true' "${DEV_DESKTOP}" \
    || fail "the fixture-backed Mail probe is visible in the application launcher"
grep -qx 'Name=Mail interface prototype' "${DEV_DESKTOP}" \
    || fail "the hidden probe does not name itself as a prototype"
grep -q 'FIXTURE DATA · NO ACCOUNT · NOTHING IS CONNECTED' "${QML}" \
    || fail "the prototype no longer discloses its fixture state on its own surface"
[ ! -e "${PRODUCT_EXTRA}/usr/lib/punar/punar-mail.sh" ] \
    || fail "the production image still ships the fixture-backed Mail launcher"
# The expansion syntax is the literal staging contract we are searching for.
# shellcheck disable=SC2016
grep -Fq 'install -m 0644 "${mod}/applications/org.punar.Mail.desktop"' "${STAGER}" \
    || fail "desktop staging does not install the product Mail entry"
grep -Fq "rm -f \"\${extra}/usr/share/punar/shell/Mail/Fixtures.qml\"" "${STAGER}" \
    || fail "desktop staging does not remove Mail fixture data from the production image"
! grep -Fq "rm -rf \"\${extra}/usr/share/punar/shell/Mail\"" "${STAGER}" \
    || fail "desktop staging still removes the live Mail application"
grep -Fq "cp -R \"\${shell_src}/Mail\" \"\${dev_extra}/usr/share/punar/shell/Mail\"" "${STAGER}" \
    || fail "desktop staging does not restore the Mail probe in the dev/CI overlay"

# The account-entry surface is a separate identity and reaches only the
# no-parameter protected launch method. It must never be folded into Mail's
# read capability or launched as a normal same-uid QML process.
[ -f "${ACCOUNT_QML}" ] || fail "no MailAccount/shell.qml"
ACCOUNT_APP_ID=$(sed -n 's|^//@ pragma AppId  *\([^ ]*\) *$|\1|p' "${ACCOUNT_QML}" | head -1)
[ "${ACCOUNT_APP_ID}" = "org.punar.MailAccount" ] \
    || fail "Mail account surface has unstable app id '${ACCOUNT_APP_ID}'"
[ -f "${ACCOUNT_DESKTOP}" ] || fail "no ${ACCOUNT_APP_ID}.desktop"
grep -qx "StartupWMClass=${ACCOUNT_APP_ID}" "${ACCOUNT_DESKTOP}" \
    || fail "Mail account desktop identity does not match its Wayland app id"
grep -qx 'Exec=punarctl mail account-add' "${ACCOUNT_DESKTOP}" \
    || fail "Mail account entry bypasses the protected no-parameter launcher"
# shellcheck disable=SC2016
grep -Fq 'install -m 0644 "${mod}/applications/org.punar.MailAccount.desktop"' "${STAGER}" \
    || fail "desktop staging does not install the protected Mail account entry"
[ -f "${ACCOUNTS_QML}" ] || fail "no MailAccounts/shell.qml"
ACCOUNTS_APP_ID=$(sed -n 's|^//@ pragma AppId  *\([^ ]*\) *$|\1|p' "${ACCOUNTS_QML}" | head -1)
[ "${ACCOUNTS_APP_ID}" = "org.punar.MailAccounts" ] \
    || fail "Mail account manager has unstable app id '${ACCOUNTS_APP_ID}'"
[ -f "${ACCOUNTS_DESKTOP}" ] || fail "no ${ACCOUNTS_APP_ID}.desktop"
grep -qx "StartupWMClass=${ACCOUNTS_APP_ID}" "${ACCOUNTS_DESKTOP}" \
    || fail "Mail account manager desktop identity does not match its Wayland app id"
grep -qx 'Exec=punarctl mail account-manage' "${ACCOUNTS_DESKTOP}" \
    || fail "Mail account manager bypasses the protected no-parameter launcher"
# shellcheck disable=SC2016
grep -Fq 'install -m 0644 "${mod}/applications/org.punar.MailAccounts.desktop"' "${STAGER}" \
    || fail "desktop staging does not install the protected Mail account manager"

# 5 · and the in-VM gate must be looking for the same window, or it silently
# asserts nothing: `select(.class == "…")` matching no client makes every
# downstream check read a null it then compares against.
grep -q "select(.class == \"${APP_ID}\")" "${GATE}" \
    || fail "surfaces-check.sh does not look for class ${APP_ID}; the window gate would match nothing"

# 6 · the launcher must exist and be the Exec target.
EXEC=$(sed -n 's|^Exec=||p' "${DEV_DESKTOP}" | head -1)
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

echo "mail-identity-contract-test: PASS (${APP_ID} is stable; product is brokered and fixtures are dev-only)"
