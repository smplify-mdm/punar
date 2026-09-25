#!/usr/bin/env bash
# Build the CIDATA drive for an unattended Omarchy install (no root needed).
#
#   tools/bench/omarchy/make-cidata.sh OUT.img SECRET_FILE SSH_PUBKEY [DISK_GIB]
#
# SECRET_FILE holds the per-run throwaway passphrase (generated at job start,
# never stored): stock Omarchy's configurator uses one secret for the disk,
# the user and root, so this does too. It lands in plaintext on the drive,
# which only this disposable VM ever sees, and is typed at the disk prompt.
# SSH_PUBKEY enables sshd for the install phase only; restore-stock.sh
# removes it, the key and the firewall rule before anything is measured.
#
# The templates in cidata/ follow archinstall 3.0.9 as Omarchy 4.0.4 uses
# it. Before the first scheduled run the owner's checklist says to diff them
# against one interactive install's /root/user_*.json (the schema drifts).
# With OUT.img "-" the rendered files are written to stdout instead (tests).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${1:-}"
SECRET_FILE="${2:-}"
PUBKEY="${3:-}"
DISK_GIB="${4:-40}"

die() {
    echo "make-cidata: $*" >&2
    exit 1
}

[ -n "${OUT}" ] && [ -r "${SECRET_FILE}" ] && [ -r "${PUBKEY}" ] \
    || die "usage: make-cidata.sh OUT.img SECRET_FILE SSH_PUBKEY [DISK_GIB]"
case "${DISK_GIB}" in ''|*[!0-9]*) die "DISK_GIB must be a number" ;; esac
command -v openssl >/dev/null 2>&1 || die "openssl is required"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
chmod 0700 "${WORK}"
openssl passwd -6 -stdin < "${SECRET_FILE}" > "${WORK}/hash"

python3 - "${HERE}/cidata" "${WORK}" "${SECRET_FILE}" "${DISK_GIB}" <<'PY'
import json, sys
from pathlib import Path
templates, work, secret_file, disk_gib = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], int(sys.argv[4])
secret = Path(secret_file).read_text().strip("\r\n")
if not secret or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789" for c in secret):
    sys.exit("make-cidata: the throwaway secret must be lowercase letters and digits (typed over QMP)")
mib, gib = 1024 * 1024, 1024 * 1024 * 1024
disk = disk_gib * gib
boot_start, boot_size = mib, 2 * gib
main_start = boot_start + boot_size
main_size = disk - main_start - mib
values = {
    "@BOOT_START@": str(boot_start), "@BOOT_SIZE@": str(boot_size),
    "@MAIN_START@": str(main_start), "@MAIN_SIZE@": str(main_size),
    "@PASSPHRASE@": json.dumps(secret), "@HASH@": json.dumps((work / "hash").read_text().strip()),
    "@USER@": json.dumps("bench"), "@HOSTNAME@": json.dumps("omarchy-bench"),
}
for name in ("user_configuration.json", "user_credentials.json"):
    text = (templates / f"{name}.tmpl").read_text()
    for token, value in values.items():
        text = text.replace(token, value)
    json.loads(text)  # refuse to write a drive the installer cannot parse
    (work / name).write_text(text)
PY
cp "${HERE}/cidata/user_encrypt_installation.txt" "${WORK}/"
cp "${PUBKEY}" "${WORK}/authorized_keys"
rm -f "${WORK}/hash"

if [ "${OUT}" = - ]; then
    for f in user_configuration.json user_credentials.json user_encrypt_installation.txt; do
        echo "== ${f}"
        cat "${WORK}/${f}"
    done
    exit 0
fi
for tool in mkfs.vfat mcopy; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} is required (dosfstools, mtools)"
done
rm -f "${OUT}"
truncate -s 4M "${OUT}"
mkfs.vfat -n CIDATA "${OUT}" >/dev/null
mcopy -i "${OUT}" "${WORK}/user_configuration.json" "${WORK}/user_credentials.json" \
    "${WORK}/user_encrypt_installation.txt" "${WORK}/authorized_keys" ::/
chmod 0600 "${OUT}"
echo "make-cidata: ${OUT}"
