#!/usr/bin/env bash
# The Evolution first-run defaults Punar seeds through /etc/skel.
#
# A person installed Evolution from the catalogue and its first run stacked a
# "make Evolution your default mail client?" modal on top of a seven-page
# account assistant, in Adwaita, on a desktop whose design language is the
# opposite of that. One configuration lever reaches a Flatpak's GSettings and
# this is it; docs/design/mail-calendar-contacts.md §6 records why the two
# obvious alternatives (a host dconf seed, and granting ca.desrt.dconf) are
# inert and actively harmful respectively.
#
# WHY A CONTRACT TEST AND NOT ONLY A RUNTIME CHECK. Every key here was verified
# byte-for-byte against Evolution's own gschema before it was written, because
# the failure this repository keeps meeting is a name that is CLOSE: GSettings
# silently ignores a key it does not know, so a typo ships, changes nothing,
# and reports success. A test that pins the exact spelling is the only thing
# standing between "we configured it" and "it is configured".
#
# The two DELIBERATE OMISSIONS are asserted as firmly as the inclusions. Both
# are things a well-meaning later edit would add, and both would be wrong.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SKEL="${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/etc/skel"
KEYFILE="${SKEL}/.var/app/org.gnome.Evolution/config/glib-2.0/settings/keyfile"

fail() {
    echo "evolution-defaults-contract-test: FAIL: $*" >&2
    exit 1
}

[ -f "${KEYFILE}" ] \
    || fail "no seeded keyfile at ${KEYFILE#"${REPO_ROOT}/"}"

# THE PATH IS THE MECHANISM. Flatpak's own settings migration writes this exact
# path only when it does not already exist, so seeding it through /etc/skel —
# which punar-onboardd copies with `cp -a` when it creates the home, before any
# application has run — is what makes Punar's values the ones that win. A file
# anywhere else is not a seed, it is a file.
case "${KEYFILE}" in
    *"/etc/skel/.var/app/org.gnome.Evolution/config/glib-2.0/settings/keyfile") ;;
    *) fail "the seed is not on the path flatpak reads" ;;
esac

# The group name is what GKeyfileSettingsBackend's convert_path() produces for
# the org.gnome.evolution.mail schema: the leading slash stripped, dots to
# slashes. A [org.gnome.evolution.mail] group would parse and do nothing.
grep -qx '\[org/gnome/evolution/mail\]' "${KEYFILE}" \
    || fail "the group must be [org/gnome/evolution/mail], slashes not dots"

require_key() {
    grep -qx "$1=$2" "${KEYFILE}" \
        || fail "missing or altered: $1=$2 ($3)"
}

# The stacked-modal fix, and the only key here that answers the original report.
require_key prompt-check-if-default-mailer false \
    "the modal that stacked on the account assistant"

# Read like the rest of the desktop. Values are g_variant_print output, so the
# strings carry single quotes; without them GSettings rejects the value and the
# default silently stands.
require_key use-custom-font true "fonts do not apply without this"
require_key variable-width-font "'Instrument Sans 11'" "the shipped sans family"
require_key monospace-font "'Geist Mono 10'" "the shipped mono family"

# One list, read top to bottom, header block out of the way.
require_key layout 1 "vertical view"
require_key thread-flat true "a flat list, not a thread tree"
require_key headers-collapsed true "the header block starts collapsed"

# BOTH FONT FAMILIES MUST ACTUALLY EXIST IN THE IMAGE. A Pango font description
# naming a family that is not installed does not fail — it silently falls back,
# which looks exactly like the bug being fixed here.
for family in instrument-sans geist-mono; do
    [ -d "${REPO_ROOT}/os/images/mkosi.profiles/desktop/mkosi.extra/usr/share/fonts/punar/${family}" ] \
        || fail "keyfile names a font family the image does not ship: ${family}"
done

# ---- the deliberate omissions ---------------------------------------------

# show-startup-wizard=false removes the account assistant, and with it the only
# path to adding an account: a mail client with no mail. The reported complaint
# was two modals, not the assistant, and prompt-check-if-default-mailer alone
# answers it.
! grep -q '^show-startup-wizard' "${KEYFILE}" \
    || fail "show-startup-wizard is set; it deletes the only way to add an account"

# buttons-hide=['calendar','tasks','memos'] turns Evolution into a focused mail
# reader by deleting the calendar and the reminders — the other two things this
# device is meant to do, and two thirds of what was actually asked for.
! grep -q '^buttons-hide' "${KEYFILE}" \
    || fail "buttons-hide is set; it removes the calendar and reminders"

# ---- the disclosures the catalogue owes -----------------------------------

# The Flathub build exports WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS=1 in its
# launch wrapper, so the inner sandbox is off for the process that renders
# untrusted remote HTML, and it is baked into the ref: no override, no
# GSettings key and no Punar policy can undo it. Configuration cannot fix that,
# so the card has to say it.
CATALOG="${REPO_ROOT}/catalog/catalog.json"
python3 - "${CATALOG}" <<'PY' || exit 1
import json, sys

catalog = json.load(open(sys.argv[1]))
app = next((a for a in catalog["apps"] if a["id"] == "evolution"), None)
if app is None:
    print("evolution-defaults-contract-test: FAIL: no evolution row in the catalogue",
          file=sys.stderr)
    sys.exit(1)

have = {d["id"] for d in app.get("disclosures", [])}
for needed, why in [
    ("access:renderer-sandbox-disabled",
     "the publisher's build disables the HTML renderer's own sandbox"),
    ("data:shared-keyring",
     "mail passwords land in the host keyring, which has no per-app separation"),
]:
    if needed not in have:
        print(f"evolution-defaults-contract-test: FAIL: the card does not disclose "
              f"{needed} — {why}", file=sys.stderr)
        sys.exit(1)
PY

echo "evolution-defaults-contract-test: PASS"
